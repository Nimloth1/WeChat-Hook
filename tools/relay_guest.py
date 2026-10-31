"""一次性 VW12 原生发送执行器；仅由 SSH 调用，不驻留、不操作微信登录。"""
import argparse
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import secrets
import sys
import time

# 嵌入式 Python 的 ._pth 不包含脚本目录；只加入入口自身目录，不依赖 cwd/PYTHONPATH。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from relay_common import (HOOK_MODULE, MAX_WIRE, SOURCE_MODULE, Store, assets, asset_path, canonical,
                          digest, dispatch_diagnostics, file_hash, native_fingerprint, validate_job, validate_policy)
from relay_assets import receive


@contextmanager
def single_executor(root):
    # Windows 文件锁由内核在进程退出时释放；不留下无法自愈的 PID 锁。
    import msvcrt
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    with (root / "executor.lock").open("a+b") as f:
        if f.tell() == 0:
            f.write(b"\0")
            f.flush()
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            yield
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


def durable_new(path, value):
    with Path(path).open("x", encoding="utf-8") as f:
        f.write(canonical(value))
        f.flush()
        os.fsync(f.fileno())


class Hook:
    def request(self, method, path, body=None, token=None):
        c = http.client.HTTPConnection("127.0.0.1", 30001, timeout=20)
        headers = {"Connection": "close"}
        if body is not None:
            body = canonical(body).encode()
            if len(body) > MAX_WIRE:
                raise ValueError("hook_body_limit")
            headers["Content-Type"] = "application/json; charset=utf-8"
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            c.request(method, path, body=body, headers=headers)
            response = c.getresponse()
            raw = response.read(8193)
            if len(raw) > 8192:
                raise ValueError("hook_response_limit")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("hook_response_type")
            return response.status, result
        finally:
            c.close()

    def status(self):
        code, data = self.request("GET", "/QueryDB/status")
        if code != 200:
            raise ValueError("hook_status_unavailable")
        return data


def assert_idle(state, armed=False):
    expected = {"ApprovalReload": "per_request", "ApprovalVersion2GroupOnly": True,
                "NativeOwnershipMode": "native_reference_ownership", "NativeOwnershipFault": False,
                "SendApprovalConfigured": armed, "SendInProgress": False,
                "PendingMessageOwners": 0, "RetainedParameterBytes": 0, "RetainedPayloadHandles": 0,
                "FileSendSupported": True}
    if any(type(state.get(k)) is not type(v) or state[k] != v for k, v in expected.items()):
        raise ValueError("hook_not_idle_locked")


class Executor:
    def __init__(self, store, policy, permit, hook=None, reclaim_timeout=40):
        self.store = store
        self.policy = validate_policy(policy)
        self.permit = Path(permit)
        self.hook = hook or Hook()
        self.reclaim_timeout = reclaim_timeout

    def wait_reclaimed(self):
        deadline = time.monotonic() + self.reclaim_timeout
        while True:
            status = self.hook.status()
            if status.get("NativeOwnershipFault") is not False:
                raise ValueError("native_ownership_fault")
            if (status.get("PendingMessageOwners") == 0 and status.get("RetainedParameterBytes") == 0
                    and status.get("RetainedPayloadHandles") == 0 and status.get("SendInProgress") is False):
                assert_idle(status)
                return
            if time.monotonic() >= deadline:
                raise ValueError("resources_not_reclaimed")
            time.sleep(1)

    def health(self):
        return {"enabled": self.policy["enabled"], "recipient": self.policy["recipient"],
                "policy_sha256": digest(self.policy), "ledger": self.store.status(),
                "permit_present": self.permit.exists(), "hook": self.hook.status()}

    def upload(self, job, role, stream):
        validate_job(job, self.policy)
        if (not self.policy["enabled"] or self.store.get("paused") or self.permit.exists()
                or self.store.receipt(job["id"]) is not None or role not in assets(job)):
            raise ValueError("upload_not_allowed")
        if Path(str(self.permit) + ".client-attempt-" + job["id"]).exists() or Path(str(self.permit) + ".used-" + job["id"]).exists():
            raise ValueError("prior_attempt")
        descriptor = assets(job)[role]
        receive(stream, asset_path(self.store.root, job["id"], role), descriptor)
        return {"uploaded": descriptor["sha256"]}

    def dispatch(self, job):
        validate_job(job, self.policy)
        if not self.policy["enabled"]:
            raise ValueError("automatic_policy_disabled")
        old = self.store.receipt(job["id"])
        if old:
            if old["digest"] != digest(job):
                raise ValueError("job_conflict")
            # 不调用 POST，连旧的 ready 记录也不自动重新尝试。
            return {"receipt": old, "replayed": True, "post_attempts": 0}
        if self.store.get("paused"):
            raise ValueError("relay_paused")
        if not 0 <= time.time() - job["source_ts"] <= 86400:
            raise ValueError("source_too_old_or_future")
        client = Path(str(self.permit) + ".client-attempt-" + job["id"])
        used = Path(str(self.permit) + ".used-" + job["id"])
        if self.permit.exists() or client.exists() or used.exists():
            raise ValueError("existing_permit_or_attempt")
        assert_idle(self.hook.status())
        materialized = []
        request = {"request_id": job["id"], "wxidorgid": job["recipient"]}
        if job["kind"] == "text":
            request["msg"] = job["payload"]["text"]
            fingerprint = {"kind": "text", "recipient": job["recipient"], "value": request["msg"], "image_sha256": ""}
            endpoint = "/SendTextMsg"
        elif job["kind"] == "link":
            request.update(job["payload"])
            fingerprint = {"kind": "link", "recipient": job["recipient"], **job["payload"]}
            endpoint = "/send_link_msg"
        else:
            for role, descriptor in assets(job).items():
                incoming = asset_path(self.store.root, job["id"], role)
                if (not incoming.is_file() or incoming.stat().st_size != descriptor["size"]
                        or file_hash(incoming) != descriptor["sha256"]):
                    raise ValueError("staged_asset_mismatch")
                # 独立角色目录，缩略图与视频即使同名也不能互相覆盖。
                asset = self.store.root / "assets" / job["id"] / role / descriptor["filename"]
                asset.parent.mkdir(parents=True, exist_ok=True)
                if asset.exists():
                    raise ValueError("unresolved_asset")
                os.rename(incoming, asset)
                materialized.append(asset)
                if role == "media":
                    hash_field = "image_sha256" if job["kind"] == "image" else "file_sha256"
                    request.update(path=str(asset))
                    request[hash_field] = descriptor["sha256"]
                    fingerprint = {"kind": job["kind"], "recipient": job["recipient"],
                                   "value": str(asset), hash_field: descriptor["sha256"]}
                else:
                    request.update(thumbnail_path=str(asset), thumbnail_sha256=descriptor["sha256"],
                                   duration_seconds=job["payload"]["duration_seconds"])
                    fingerprint.update(thumbnail_path=str(asset), thumbnail_sha256=descriptor["sha256"],
                                       duration_seconds=job["payload"]["duration_seconds"])
            endpoint = {"image": "/SendImgMsg", "file": "/send_file_msg", "video": "/send_video_msg"}[job["kind"]]
        self.store.accept(job)
        if not self.store.claim(job, self.policy):
            raise ValueError("guest_paused_or_unresolved")
        approval = {"version": 2, "enabled": True, "token": secrets.token_hex(32),
                    "request_id": job["id"], "recipient": job["recipient"], "kind": job["kind"],
                    "payload_sha256": native_fingerprint(fingerprint), "module_sha256": SOURCE_MODULE,
                    # v2以逐条内容绑定和持久消耗限制一次调用；DLL契约要求无时间到期。
                    "expires_utc": 0}
        temp = Path(str(self.permit) + ".relay-tmp-" + job["id"])
        evidence = {"post_attempts": 0, "delivery_confirmed": False}
        state = "review_required"
        try:
            self.permit.parent.mkdir(parents=True, exist_ok=True)
            durable_new(temp, approval)
            # Windows rename 不覆盖现有许可；已有其他操作者时停止。
            os.rename(temp, self.permit)
            assert_idle(self.hook.status(), armed=True)
            durable_new(client, {"id": job["id"], "fingerprint": native_fingerprint(fingerprint), "attempt": time.time()})
            evidence["post_attempts"] = 1
            code, response = self.hook.request("POST", endpoint, request, approval["token"])
            evidence.update(dispatch_diagnostics({"http_status": code,
                "native_entered": response.get("NativeEntered"), "replayed": response.get("Replayed"),
                "response_state": response.get("state"), "hook_error": response.get("error")}))
            if (code == 202 and response.get("NativeEntered") is True
                    and response.get("Replayed") is False and response.get("DeliveryConfirmed") is False
                    and response.get("state") == "unconfirmed" and used.is_file()):
                state = "submitted_unconfirmed"
        except Exception as exc:
            # 不记录异常原文，避免 token/正文进入日志。任何异常都不重试。
            evidence["error_type"] = type(exc).__name__
        finally:
            try:
                if self.permit.exists():
                    current = json.loads(self.permit.read_text(encoding="utf-8"))
                    if current.get("token") != approval["token"]:
                        raise ValueError("permit_owner_changed")
                    self.permit.unlink()
                if temp.exists():
                    temp.unlink()
                # 只在引用/句柄均归零且无故障时删除本条临时资产。
                self.wait_reclaimed()
                for asset in materialized:
                    asset.unlink()
                    asset.parent.rmdir()
                if materialized:
                    materialized[0].parent.parent.rmdir()
                    asset_path(self.store.root, job["id"], "media").parent.rmdir()
            except Exception as exc:
                state = "review_required"
                evidence["cleanup_error_type"] = type(exc).__name__
            self.store.finish(job["id"], state, evidence)
            if state == "review_required":
                self.store.pause("guest_attempt_requires_review")
        return {"receipt": self.store.receipt(job["id"]), "replayed": False,
                "post_attempts": evidence["post_attempts"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True)
    args = p.parse_args()
    try:
        if os.name != "nt" or os.environ.get("COMPUTERNAME") != "VW12":
            raise ValueError("wrong_host")
        cfg = json.loads(args.config.read_text(encoding="utf-8"))
        validate_policy(cfg["policy"])
        raw = sys.stdin.buffer.readline(MAX_WIRE + 1)
        if len(raw) > MAX_WIRE or not raw.endswith(b"\n"):
            raise ValueError("control_frame_limit")
        request = json.loads(raw)
        if request.get("policy_sha256") != digest(cfg["policy"]):
            raise ValueError("policy_mismatch")
        if request.get("operation") != "upload" and sys.stdin.buffer.read(1):
            raise ValueError("unexpected_control_trailer")
        # 在实际调用前固定安装版本，不能仅相信状态的通用 Build 字段。
        native = Path(r"C:\Program Files\Tencent\Weixin\4.1.10.27\Weixin.dll")
        if (file_hash(native.parent.parent / "version.dll") != HOOK_MODULE
                or file_hash(native) != SOURCE_MODULE):
            raise ValueError("installed_module_changed")
        with single_executor(cfg["state_dir"]):
            executor = Executor(Store(cfg["state_dir"]), cfg["policy"],
                                Path(os.environ["LOCALAPPDATA"]) / "VW12-WeChatHook" / "send-approval.json")
            if request.get("operation") == "upload" and set(request) == {"operation", "policy_sha256", "job", "role"}:
                result = executor.upload(request["job"], request["role"], sys.stdin.buffer)
            elif request.get("operation") == "health" and set(request) == {"operation", "policy_sha256"}:
                result = executor.health()
            elif request.get("operation") == "dispatch" and set(request) == {"operation", "policy_sha256", "job"}:
                result = executor.dispatch(request["job"])
            else:
                raise ValueError("unknown_operation")
        print(canonical({"ok": True, **result}))
        return 0
    except Exception as exc:
        print(canonical({"ok": False, "error_type": type(exc).__name__, "no_retry": True}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
