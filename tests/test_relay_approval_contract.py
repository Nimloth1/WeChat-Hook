"""执行器真实生成的许可→生产C++加载/校验/消耗；仅合成数据和替身发送。"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pm_relay import (Executor, FakeHook, FIXTURES, event, media_job, policy, text_job)
from relay_common import Store, asset_path, assets, canonical, make_job
from relay_pm import dispatch_once
import relay_guest


class Probe:
    def __init__(self, executable):
        self.executable = executable

    def request(self, permit, request):
        result = subprocess.run([str(self.executable), str(permit)], input=canonical(request).encode(),
                                capture_output=True, timeout=10)
        if result.returncode or result.stderr:
            raise RuntimeError("actual_cpp_contract_probe_failed")
        return json.loads(result.stdout)


class ContractHook(FakeHook):
    def __init__(self, permit, probe):
        super().__init__(permit)
        self.probe = probe
        self.loaded = []

    def status(self):
        status = super().status()
        real = self.probe.request(self.permit, {"operation": "status"})
        status["SendApprovalConfigured"] = real["configured"]
        self.loaded.append(real)
        return status

    def request(self, method, endpoint, request, token):
        if method != "POST":
            raise ValueError("unexpected_fixture_method")
        kind = {"/SendTextMsg": "text", "/SendImgMsg": "image", "/send_file_msg": "file",
                "/send_video_msg": "video", "/send_link_msg": "link"}[endpoint]
        self.posts.append((endpoint, copy.deepcopy(request)))
        result = self.probe.request(self.permit, {"operation": "dispatch", "authorization": "Bearer " + token,
                                                "kind": kind, "body": request})
        if result["http"] == 202 and result["backend_calls"] != 1:
            raise AssertionError("fixture_backend_was_not_entered_once")
        return result["http"], result["response"]


class ApprovalContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        supplied = os.environ.get("RELAY_APPROVAL_PROBE")
        if supplied:
            executable = Path(supplied)
            if not executable.is_file():
                raise RuntimeError("supplied_contract_probe_missing")
        elif sys.platform == "darwin":
            compiler = shutil.which("clang++") or "/usr/bin/clang++"
            root = Path(__file__).resolve().parents[1]
            executable = Path(cls.temporary.name) / "approval-contract"
            command = [compiler, "-std=c++17", "-O1", "-g", "-fsanitize=address,undefined",
                       "-fno-omit-frame-pointer", "-fno-sanitize-recover=all", "-I" + str(root / "tests/approval_contract_stubs"),
                       "-I" + str(root / "include"), str(root / "tests/relay_approval_contract.cpp"),
                       str(root / "src/send_api.cpp"), str(root / "src/send_approval.cpp"),
                       "-o", str(executable)]
            result = subprocess.run(command, capture_output=True, timeout=120)
            if result.returncode:
                raise RuntimeError("contract_probe_build_failed: " + result.stderr.decode(errors="replace"))
        else:
            raise unittest.SkipTest("Windows请先构建夹具并设置RELAY_APPROVAL_PROBE；不使用纯Python替代校验")
        cls.probe = Probe(executable)

    def test_all_five_types_real_cpp_accepts_and_old_expiry_pauses(self):
        for kind in ("text", "image", "file", "video", "link"):
            for old_expiry in (False, True):
                with self.subTest(kind=kind, old_expiry=old_expiry), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    pm, guest = Store(root / "pm"), Store(root / "guest")
                    permit = root / "permit.json"
                    hook = ContractHook(permit, self.probe)
                    executor = Executor(guest, policy(), permit, hook, reclaim_timeout=0)
                    job = (text_job() if kind == "text" else make_job(event(), policy(), "link", {
                        "title": "合成链接", "description": "仅离线", "url": "https://example.com/energy"})
                        if kind == "link" else media_job(kind))
                    pm.accept(job)
                    for role, spec in assets(job).items():
                        path = asset_path(pm.root, job["id"], role)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(FIXTURES[spec["sha256"]])
                    class Transport:
                        def request(self, request):
                            return executor.dispatch(request["job"])
                    original = relay_guest.durable_new
                    generated = []
                    def capture(path, value):
                        if "expires_utc" in value:
                            generated.append(copy.deepcopy(value))
                            value = {**value, "expires_utc": int(time.time()) + 120} if old_expiry else value
                        return original(path, value)
                    with mock.patch("relay_guest.durable_new", side_effect=capture):
                        if old_expiry:
                            with self.assertRaisesRegex(ValueError, "remote_result_requires_review"):
                                dispatch_once(pm, policy(), Transport())
                        else:
                            self.assertTrue(dispatch_once(pm, policy(), Transport()))
                    self.assertEqual(len(generated), 1)
                    self.assertEqual(generated[0]["version"], 2)
                    self.assertEqual(generated[0]["expires_utc"], 0)
                    self.assertFalse(permit.exists())
                    if old_expiry:
                        self.assertEqual(hook.posts, [])
                        for store in (pm, guest):
                            self.assertEqual(store.receipt(job["id"])["state"], "review_required")
                            self.assertIsNotNone(store.get("paused"))
                    else:
                        self.assertEqual(len(hook.posts), 1)
                        self.assertTrue(any(x["configured"] and x["lifetime_valid"] and x["version"] == 2
                                            and x["expires_utc"] == 0 for x in hook.loaded))
                        for store in (pm, guest):
                            self.assertEqual(store.receipt(job["id"])["state"], "submitted_unconfirmed")
                            self.assertIsNone(store.get("paused"))
                        self.assertTrue(Path(str(permit) + ".used-" + job["id"]).is_file())
                        self.assertEqual(executor.dispatch(job)["post_attempts"], 0)
                        self.assertEqual(len(hook.posts), 1)
                        # 原许可恢复到同一路径也不能绕过真实LoadApproval的持久消耗标记。
                        permit.write_text(canonical(generated[0]))
                        self.assertFalse(self.probe.request(permit, {"operation": "status"})["configured"])

    def test_real_controller_rejects_changed_target_payload_and_token_before_consuming(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            permit = root / "permit.json"
            hook = ContractHook(permit, self.probe)
            executor = Executor(Store(root / "guest"), policy(), permit, hook, reclaim_timeout=0)
            original = relay_guest.durable_new
            generated = []
            def capture(path, value):
                if "expires_utc" in value:
                    generated.append(copy.deepcopy(value))
                return original(path, value)
            # 仅捕获真实执行器的许可和请求；隔离目录本条消费痕迹随后仍保留在原路径。
            with mock.patch("relay_guest.durable_new", side_effect=capture):
                executor.dispatch(text_job())
            approved = generated[0]
            fresh = root / "fresh-permit.json"
            fresh.write_text(canonical(approved))
            request = hook.posts[0][1]
            for field, changed in (("wxidorgid", "99999999999@chatroom"), ("msg", "另一段内容"),
                                   ("request_id", "different-request-0001")):
                result = self.probe.request(fresh, {"operation": "dispatch", "authorization": "Bearer " + approved["token"],
                    "kind": "text", "body": {**request, field: changed}})
                self.assertEqual(result["http"], 403)
                self.assertEqual(result["backend_calls"], 0)
                self.assertFalse(Path(str(fresh) + ".used-" + approved["request_id"]).exists())
            result = self.probe.request(fresh, {"operation": "dispatch", "authorization": "Bearer " + "x" * 64,
                                              "kind": "text", "body": request})
            self.assertEqual(result["http"], 403)
            self.assertEqual(result["backend_calls"], 0)
            self.assertTrue(self.probe.request(fresh, {"operation": "status"})["configured"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
