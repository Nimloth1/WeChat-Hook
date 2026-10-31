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
from test_pm_relay import (Executor, FakeHook, FIXTURES, descriptor, event, media_job, policy, text_job)
from relay_common import Store, asset_path, assets, canonical, make_job
from relay_pm import dispatch_once
import relay_guest
from relay_guest import single_executor


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
        self.prepare_error = ""

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
                                                "kind": kind, "body": request, "prepare_error": self.prepare_error})
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

    @unittest.skipUnless(os.name == "nt" and os.environ.get("RELAY_NATIVE_IMAGE_PROBE"),
                         "真实文件预检仅在PW使用WinAPI；不以替身冒充")
    def test_real_image_preflight_in_executor_appdata_layout(self):
        probe = Probe(Path(os.environ["RELAY_NATIVE_IMAGE_PROBE"]))
        for data, name in ((b"\x89PNG\r\n\x1a\nfixture", "中文.png"),
                           (b"\xff\xd8\xff" + b"\0" * (1024 * 1024 - 3), "a" * 32 + "_h.jpg")):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=os.environ["LOCALAPPDATA"]) as folder:
                root = Path(folder)
                guest = Store(root / "VW12-Relay" / "state")
                permit = root / "VW12-WeChatHook" / "send-approval.json"
                hook = ContractHook(permit, probe)
                executor = Executor(guest, policy(), permit, hook, reclaim_timeout=0)
                job = make_job(event(), policy(), "image", descriptor(data, name))
                with single_executor(guest.root):
                    result = executor.dispatch(job)
                self.assertEqual(result["receipt"]["state"], "submitted_unconfirmed", result)
                self.assertEqual(len(hook.posts), 1)
                self.assertFalse(permit.exists())

    def test_fixed_preflight_errors_reach_both_ledgers_without_retry(self):
        for kind in ("text", "image", "file", "video", "link"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                pm, guest = Store(root / "pm"), Store(root / "guest")
                permit = root / "permit.json"
                hook = ContractHook(permit, self.probe)
                hook.prepare_error = "image_path_not_stable"
                executor = Executor(guest, policy(), permit, hook, reclaim_timeout=0)
                job = (text_job() if kind == "text" else make_job(event(), policy(), "link", {
                    "title": "合成卡片", "description": "", "url": "https://example.com/a"})
                    if kind == "link" else media_job(kind))
                pm.accept(job)
                class Transport:
                    def request(self, request):
                        return executor.dispatch(request["job"])
                with self.assertRaisesRegex(ValueError, "remote_result_requires_review"):
                    with mock.patch("builtins.print") as output:
                        dispatch_once(pm, policy(), Transport())
                logged = json.loads(output.call_args.args[0])
                self.assertEqual(logged["event"], "dispatch_failed")
                self.assertEqual(logged["hook_error"], "image_path_not_stable")
                for store in (pm, guest):
                    evidence = store.receipt(job["id"])["evidence"]
                    self.assertEqual(evidence["hook_error"], "image_path_not_stable")
                    self.assertEqual(evidence["http_status"], 422)
                    self.assertIs(evidence["native_entered"], False)
                    self.assertEqual(evidence["post_attempts"], 1)
                    self.assertEqual(evidence["response_state"], "not_attempted")
                self.assertFalse(permit.exists())
                self.assertFalse(Path(str(permit) + ".used-" + job["id"]).exists())
                self.assertFalse(dispatch_once(pm, policy(), Transport()))
                executor.dispatch(job)
                self.assertEqual(len(hook.posts), 1)

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
