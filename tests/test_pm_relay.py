"""合成事件/伪 Hook/临时账本；绝不连接真实微信或发消息。"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import subprocess
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from relay_common import Store, canonical, digest, file_hash, make_job, validate_job, validate_policy
from relay_guest import Executor, assert_idle, single_executor
from relay_pm import Decoder, Tail, dispatch_once, resolve_media


def policy():
    return {"version": 1, "enabled": True, "recipient": "11111111111@chatroom",
            "source": "22222222222@chatroom", "corporations": ["国泰君安期货"],
            "interval_seconds": 180, "daily_messages": 120, "daily_media_bytes": 128 * 1024 * 1024}


def event(mid="1000", **kwargs):
    return {"server_id": mid, "local_id": 1, "conversation_id": policy()["source"],
            "sender_corp": "国泰君安期货", "is_self": False, "is_chatroom": True,
            "sender": "测试员", "ts": time.time(), "type": 1, "content": "真实内容仅为合成夹具", **kwargs}


def text_job(mid="1000"):
    return make_job(event(mid), policy(), "text", {"text": "hello 离线夹具"})


def media_job(kind="image", mid="2000"):
    data = b"\x89PNG\r\n\x1a\n" + b"test" * 100
    return make_job(event(mid), policy(), kind, {"filename": "离线夹具.png",
                    "sha256": hashlib.sha256(data).hexdigest(), "data_b64": base64.b64encode(data).decode()})


class FakeHook:
    def __init__(self, permit, mode="ok"):
        self.permit = permit
        self.mode = mode
        self.posts = []

    def status(self):
        after = bool(self.posts)
        return {"ApprovalReload": "per_request", "ApprovalVersion2GroupOnly": True,
                "NativeOwnershipMode": "native_reference_ownership", "NativeOwnershipFault": False,
                "SendApprovalConfigured": self.permit.exists(), "SendInProgress": False,
                "PendingMessageOwners": 1 if after and self.mode == "pending" else 0,
                "RetainedParameterBytes": 0, "RetainedPayloadHandles": 0, "FileSendSupported": True}

    def request(self, method, endpoint, request, token):
        assert method == "POST"
        approval = json.loads(self.permit.read_text())
        assert token == approval["token"]
        kind = {"/SendTextMsg": "text", "/SendImgMsg": "image", "/send_file_msg": "file"}[endpoint]
        # 独立复现 C++ Fingerprint 旧协议：文字也必须含空 image_sha256。
        fp = {"kind": kind, "recipient": request["wxidorgid"],
              "value": request.get("msg", request.get("path")), "image_sha256": ""}
        if kind != "text":
            field = "image_sha256" if kind == "image" else "file_sha256"
            if kind == "file":
                del fp["image_sha256"]
            fp[field] = file_hash(request["path"])
            assert request[field] == fp[field]
            assert len(request) == 4
        else:
            assert len(request) == 3
        assert hashlib.sha256(json.dumps(fp, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode()).hexdigest() == approval["payload_sha256"]
        self.posts.append((endpoint, copy.deepcopy(request)))
        if self.mode == "timeout":
            raise TimeoutError()
        if self.mode != "missing_marker":
            Path(str(self.permit) + ".used-" + request["request_id"]).write_text("consumed")
        return (422 if self.mode == "reject" else 202), {
            "NativeEntered": self.mode != "reject", "Replayed": self.mode == "replayed",
            "DeliveryConfirmed": False, "state": "unconfirmed"}


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.p = policy()

    def tearDown(self):
        self.tmp.cleanup()

    def make_executor(self, mode="ok", policy_value=None):
        store = Store(self.root / "guest")
        permit = self.root / "permit" / "send-approval.json"
        hook = FakeHook(permit, mode)
        return Executor(store, policy_value or self.p, permit, hook), hook

    def test_policy_validation(self):
        for key, bad in (("enabled", 1), ("interval_seconds", 0), ("interval_seconds", 179),
                         ("daily_messages", 0), ("daily_messages", 481),
                         ("daily_media_bytes", 128 * 1024 * 1024 + 1),
                         ("recipient", "filehelper"), ("source", self.p["recipient"]),
                         ("corporations", [])):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ValueError):
                    validate_policy({**self.p, key: bad})

    def test_job_validation(self):
        j = text_job()
        for key, bad in (("kind", "video"), ("kind", "link"), ("recipient", "3333@chatroom"),
                         ("source", "4444@chatroom"), ("id", "a" * 64),
                         ("corporation", "其他公司"), ("source_ts", float("nan")), ("source_ts", True)):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ValueError):
                    validate_job({**j, key: bad}, self.p)
        for bad in ["", "  ", "hello\x00", "😀" * 1001]:
            with self.subTest(text=repr(bad[:10])):
                with self.assertRaises(ValueError):
                    validate_job({**j, "payload": {"text": bad}}, self.p)

    def test_media_validation(self):
        j = media_job()
        for name in ["../x.png", "a\\b.png", "CON.txt", "NUL", "COM1.mp3", "a.", "a ", ""]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    validate_job({**j, "payload": {**j["payload"], "filename": name}}, self.p)
        for field, value in [("sha256", "0" * 64), ("data_b64", "!!!")]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    validate_job({**j, "payload": {**j["payload"], field: value}}, self.p)

    def test_duplicate_no_writes_and_conflict(self):
        store = Store(self.root / "store")
        j = text_job()
        self.assertTrue(store.accept(j))
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        for _ in range(100):
            self.assertFalse(store.accept(j))
            store.status()
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))
        with self.assertRaises(ValueError):
            store.accept({**j, "payload": {"text": "变更的内容"}})

    def baseline(self):
        source = self.root / "messages.jsonl"
        source.write_text(canonical(event("old")) + "\n")
        store = Store(self.root / "store")
        tail = Tail(source, store, self.p)
        tail.baseline()
        return source, store, tail

    def test_tail_history_partial_duplicate_and_noop(self):
        source, store, tail = self.baseline()
        self.assertEqual(tail.poll(), 0)
        self.assertIsNone(store.next_job())
        e = event("new")
        raw = (canonical(e) + "\n").encode()
        with source.open("ab") as f:
            f.write(raw[:10])
        self.assertEqual(tail.poll(), 0)
        with source.open("ab") as f:
            f.write(raw[10:] + raw)
        self.assertEqual(tail.poll(), 2)
        self.assertEqual(store.status()["counts"], {"ready": 1})
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        for _ in range(100):
            self.assertEqual(tail.poll(), 0)
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))
        with self.assertRaises(ValueError):
            tail.baseline()

    def test_tail_rotation_truncation_rewrite_and_bad_line(self):
        for mode in ["rotate", "truncate", "rewrite", "invalid", "oversize"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                source = Path(folder) / "source"
                source.write_text('{"old":1}\n')
                store = Store(Path(folder) / "state")
                tail = Tail(source, store, self.p)
                cursor = tail.baseline()
                if mode == "rotate":
                    source.rename(Path(folder) / "old")
                    source.write_text('{"new":1}\n')
                elif mode == "truncate":
                    source.write_text("")
                elif mode == "rewrite":
                    source.write_text('{"new":1}\n')
                else:
                    with source.open("a") as f:
                        f.write(("invalid" if mode == "invalid" else "x" * (1024 * 1024 + 1)) + "\n")
                with self.assertRaises(ValueError):
                    tail.poll()
                self.assertEqual(store.get("cursor"), cursor)

    def test_scope_and_unsupported_types_never_queued(self):
        _, store, tail = self.baseline()
        for changes in [{"is_self": True}, {"conversation_id": self.p["recipient"]},
                        {"sender_corp": ""}, {"is_chatroom": False}, {"type": 43, "video": {}},
                        {"type": 49}, {"ts": time.time() - 86401}]:
            with self.subTest(changes=changes):
                self.assertIsNone(tail.classify(event(**changes))[0])
        text, _ = tail.classify(event(content="😀" * 1200))
        self.assertEqual(text["kind"], "file")
        self.assertIn("😀" * 1200, base64.b64decode(text["payload"]["data_b64"]).decode())

    def test_cursor_and_queue_atomic_on_failure(self):
        source, store, tail = self.baseline()
        cursor = store.get("cursor")
        with source.open("a") as f:
            f.write(canonical(event()) + "\n")
        with mock.patch.object(store, "add", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                tail.poll()
        self.assertEqual(store.get("cursor"), cursor)
        self.assertEqual(tail.poll(), 1)
        self.assertEqual(store.status()["counts"], {"ready": 1})

    def test_waiting_media_does_not_block_new_text(self):
        source, store, tail = self.baseline()
        e = event("image", type=3, image_md5="a" * 32)
        with source.open("a") as f:
            f.write(canonical(e) + "\n" + canonical(event("text")) + "\n")
        tail.poll()
        decoder = mock.Mock()
        decoder.image.return_value = None
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        resolve_media(store, self.p, decoder)
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))
        self.assertEqual(store.next_job()["kind"], "text")
        decoder.image.return_value = b"fake png bytes", "image.png"
        resolve_media(store, self.p, decoder)
        self.assertEqual(store.status()["counts"], {"ready": 2})
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        resolve_media(store, self.p, decoder)
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))

    def test_rate_limits_persist_across_restart(self):
        store = Store(self.root / "store")
        j1, j2 = text_job("one"), text_job("two")
        store.accept(j1)
        store.accept(j2)
        self.assertTrue(store.claim(j1, self.p, now=100000))
        with mock.patch("time.time", return_value=100010):
            store.finish(j1["id"], "submitted_unconfirmed", {"delivery_confirmed": False})
        store = Store(store.root)
        self.assertFalse(store.claim(j2, self.p, now=100179))
        self.assertFalse(store.claim(j2, {**self.p, "daily_messages": 1}, now=100200))
        self.assertFalse(store.claim(j2, self.p, now=100180))
        self.assertTrue(store.claim(j2, self.p, now=100190))
        with self.assertRaises(ValueError):
            store.claim(j2, self.p, now=100400)

    def test_two_end_rate_jitter_waits_without_claim_or_retry(self):
        for first_delay, second_delay, reply_delay in [(10, 1, 0), (1, 30, 4), (30, 0, 8)]:
            with self.subTest(delays=(first_delay, second_delay, reply_delay)), tempfile.TemporaryDirectory() as folder:
                clock = [100000.0]
                with mock.patch("time.time", side_effect=lambda: clock[0]):
                    pm, guest = Store(Path(folder) / "pm"), Store(Path(folder) / "guest")
                    permit = Path(folder) / "permit.json"
                    hook = FakeHook(permit)
                    executor = Executor(guest, self.p, permit, hook, reclaim_timeout=0)
                    first, second = text_job("first"), text_job("second")
                    pm.accept(first)
                    pm.accept(second)
                    class Transport:
                        delay = first_delay
                        calls = 0
                        def request(self, request):
                            self.calls += 1
                            clock[0] += self.delay
                            result = executor.dispatch(request["job"])
                            clock[0] += reply_delay
                            return result
                    transport = Transport()
                    self.assertTrue(dispatch_once(pm, self.p, transport))
                    completed = clock[0]
                    pm = Store(pm.root)  # 间隔跨 PM 进程重启仍有效。
                    before = pm.path.read_bytes(), pm.path.stat().st_mtime_ns
                    for when in [100180.0, completed + 179.999]:
                        clock[0] = when
                        self.assertFalse(dispatch_once(pm, self.p, transport))
                        self.assertEqual(pm.receipt(second["id"])["state"], "ready")
                        self.assertIsNone(guest.receipt(second["id"]))
                    self.assertEqual(before, (pm.path.read_bytes(), pm.path.stat().st_mtime_ns))
                    self.assertEqual(transport.calls, 1)
                    clock[0] = completed + 180
                    transport.delay = second_delay
                    self.assertTrue(dispatch_once(pm, self.p, transport))
                    self.assertEqual(transport.calls, 2)
                    self.assertEqual(len(hook.posts), 2)
                    self.assertIsNone(pm.get("paused"))
                    self.assertIsNone(guest.get("paused"))
                    self.assertEqual(executor.dispatch(second)["post_attempts"], 0)

    def test_two_end_daily_quotas_wait_from_completion(self):
        for quota in ["daily_messages", "daily_media_bytes"]:
            with self.subTest(quota=quota), tempfile.TemporaryDirectory() as folder:
                clock = [100000.0]
                with mock.patch("time.time", side_effect=lambda: clock[0]):
                    first = media_job("file", "first")
                    p = {**self.p, quota: 1 if quota == "daily_messages" else
                         len(base64.b64decode(first["payload"]["data_b64"]))}
                    pm, guest = Store(Path(folder) / "pm"), Store(Path(folder) / "guest")
                    permit = Path(folder) / "permit.json"
                    hook = FakeHook(permit)
                    executor = Executor(guest, p, permit, hook, reclaim_timeout=0)
                    class Transport:
                        calls = 0
                        def request(self, request):
                            self.calls += 1
                            clock[0] += 10 if self.calls == 1 else 1
                            result = executor.dispatch(request["job"])
                            clock[0] += 10
                            return result
                    transport = Transport()
                    pm.accept(first)
                    self.assertTrue(dispatch_once(pm, p, transport))
                    completed = clock[0]
                    clock[0] = completed + 86400 - 1
                    second = media_job("file", "second")
                    pm.accept(second)
                    self.assertFalse(dispatch_once(pm, p, transport))
                    self.assertEqual(transport.calls, 1)
                    self.assertIsNone(guest.receipt(second["id"]))
                    clock[0] = completed + 86400
                    self.assertTrue(dispatch_once(pm, p, transport))
                    self.assertEqual(len(hook.posts), 2)
                    self.assertIsNone(pm.get("paused"))
                    self.assertIsNone(guest.get("paused"))

    def test_waiting_media_round_robin_is_bounded_and_noop_does_not_write(self):
        source, store, tail = self.baseline()
        md5s = [f"{i:032x}" for i in range(25)]
        with source.open("a") as f:
            for i, md5 in enumerate(md5s):
                f.write(canonical(event(str(i), type=3, image_md5=md5)) + "\n")
        self.assertEqual(tail.poll(), 25)
        decoder = mock.Mock()
        decoder.image.side_effect = lambda _, md5: (b"image", "image.png") if md5 in {md5s[10], md5s[24]} else None
        for _ in range(3):
            before = decoder.image.call_count
            resolve_media(store, self.p, decoder)
            self.assertLessEqual(decoder.image.call_count - before, 10)
        requested = {call.args[1] for call in decoder.image.call_args_list}
        self.assertEqual(requested, set(md5s))
        self.assertEqual(store.status()["counts"], {"ready": 2})
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        for _ in range(50):
            resolve_media(store, self.p, decoder)
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))

    def test_waiting_media_rotation_covers_new_file_and_restart(self):
        source, store, tail = self.baseline()
        with source.open("a") as f:
            for i in range(10):
                f.write(canonical(event(str(i), type=3, image_md5=f"{i:032x}")) + "\n")
        tail.poll()
        decoder = mock.Mock()
        decoder.image.return_value = None
        decoder.file.return_value = b"pdf", "new.pdf"
        resolve_media(store, self.p, decoder)
        with source.open("a") as f:
            f.write(canonical(event("new-file", type=49, file={"name": "new.pdf", "size": 3})) + "\n")
        tail.poll()
        store = Store(store.root)  # 游标可重置，但不能每轮从头开始。
        resolve_media(store, self.p, decoder)
        self.assertIsNone(store.next_job())
        resolve_media(store, self.p, decoder)
        self.assertEqual(store.next_job()["kind"], "file")
        decoder.file.assert_called_once_with("new.pdf", 3)

    def test_daily_byte_limit_and_pause(self):
        store = Store(self.root / "store")
        j = media_job()
        store.accept(j)
        self.assertFalse(store.claim(j, {**self.p, "daily_media_bytes": 1}))
        self.assertEqual(store.receipt(j["id"])["state"], "ready")
        store.pause("test")
        self.assertFalse(store.claim(j, self.p))

    def test_guest_exact_text_image_file_and_persistent_replay(self):
        for kind in ["text", "image", "file"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                store = Store(Path(folder) / "guest")
                permit = Path(folder) / "permit.json"
                hook = FakeHook(permit)
                executor = Executor(store, self.p, permit, hook, reclaim_timeout=0)
                j = text_job() if kind == "text" else media_job(kind)
                result = executor.dispatch(j)
                self.assertEqual(result["receipt"]["state"], "submitted_unconfirmed")
                self.assertFalse(result["receipt"]["delivery_confirmed"])
                self.assertFalse(permit.exists())
                self.assertEqual(list((store.root / "assets").glob("*/*")) if (store.root / "assets").exists() else [], [])
                before = store.path.read_bytes(), store.path.stat().st_mtime_ns
                executor = Executor(Store(store.root), self.p, permit, hook)
                replay = executor.dispatch(j)
                self.assertTrue(replay["replayed"])
                self.assertEqual(len(hook.posts), 1)
                self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))
                self.assertEqual(store.receipt(j["id"])["state"], "submitted_unconfirmed")

    def test_guest_timeout_reject_missing_marker_or_busy_stops(self):
        for mode in ["timeout", "reject", "missing_marker", "pending", "replayed"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                store = Store(Path(folder) / "guest")
                permit = Path(folder) / "permit.json"
                hook = FakeHook(permit, mode)
                executor = Executor(store, self.p, permit, hook, reclaim_timeout=0)
                j = media_job()
                result = executor.dispatch(j)
                self.assertEqual(result["receipt"]["state"], "review_required")
                self.assertIsNotNone(store.get("paused"))
                self.assertFalse(permit.exists())
                self.assertEqual(len(hook.posts), 1)
                assets = list((store.root / "assets").glob("*/*"))
                self.assertEqual(len(assets), 1 if mode == "pending" else 0)
                executor.dispatch(j)  # 只查旧回执，不重复发送。
                with self.assertRaises(ValueError):
                    executor.dispatch(text_job("next"))
                self.assertEqual(len(hook.posts), 1)

    def test_disabled_or_foreign_permit_never_posts(self):
        executor, hook = self.make_executor(policy_value={**self.p, "enabled": False})
        with self.assertRaises(ValueError):
            executor.dispatch(text_job())
        self.assertEqual(hook.posts, [])
        executor.policy = self.p
        executor.permit.parent.mkdir()
        executor.permit.write_text("other operator")
        with self.assertRaises(ValueError):
            executor.dispatch(text_job())
        self.assertEqual(hook.posts, [])
        self.assertEqual(executor.permit.read_text(), "other operator")

    def test_waits_for_actual_reclamation_not_a_fixed_release_timer(self):
        executor, hook = self.make_executor()
        original = hook.status
        observed_pending = []
        def status():
            state = original()
            if hook.posts and not observed_pending:
                observed_pending.append(True)
                self.assertTrue(list((executor.store.root / "assets").glob("*/*")))
                state["PendingMessageOwners"] = 1
            return state
        hook.status = status
        with mock.patch("relay_guest.time.sleep") as sleep:
            result = executor.dispatch(media_job())
        self.assertEqual(result["receipt"]["state"], "submitted_unconfirmed")
        self.assertTrue(observed_pending)
        self.assertEqual(sleep.call_count, 1)

    def test_bounded_media_reader_and_duplicate_file_names(self):
        decoder = Decoder.__new__(Decoder)
        decoder.decoder = mock.Mock(account_dir=str(self.root))
        base = self.root / "msg/file/2026-10"
        base.mkdir(parents=True)
        (base / "test(1).pdf").write_bytes(b"pdf-data")
        self.assertEqual(decoder.file("test.pdf", 8), (b"pdf-data", "test.pdf"))
        self.assertIsNone(decoder.file("test.pdf", 9))
        with (self.root / "oversize").open("wb") as f:
            f.truncate(20 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            decoder.read_bounded(self.root / "oversize")

    def test_bounded_v2_decode_uses_existing_key_contract(self):
        try:
            from Crypto.Cipher import AES
        except ImportError:
            self.skipTest("仅 PM 媒体环境需要现有 pycryptodome；执行器不依赖它")
        decoder = Decoder.__new__(Decoder)
        key = b"0123456789abcdef"
        decoder.decoder = mock.Mock(_key=(key, 90))
        decoder.aes = AES
        original = b"\x89PNG\r\n\x1a\n" + b"x" * 100
        plain = original[:32] + b"\x10" * 16
        body = AES.new(key, AES.MODE_ECB).encrypt(plain) + original[32:-10] + bytes(x ^ 90 for x in original[-10:])
        path = self.root / "fixture.dat"
        path.write_bytes(b"\x07\x08V2\x08\x07" + struct.pack("<II", 32, 10) + b"\0" + body)
        self.assertEqual(decoder.decode(path), original)
        path.write_bytes(b"short")
        self.assertIsNone(decoder.decode(path))

    def test_pm_success_and_timeout_no_retry(self):
        for fail in [False, True]:
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as folder:
                store = Store(folder)
                j = text_job()
                store.accept(j)
                transport = mock.Mock()
                if fail:
                    transport.request.side_effect = TimeoutError()
                    with self.assertRaises(TimeoutError):
                        dispatch_once(store, self.p, transport)
                    self.assertFalse(dispatch_once(store, self.p, transport))
                    self.assertEqual(store.receipt(j["id"])["state"], "review_required")
                else:
                    transport.request.return_value = {"receipt": {"id": j["id"], "digest": digest(j),
                        "state": "submitted_unconfirmed", "delivery_confirmed": False,
                        "evidence": {"http_status": 202}}, "replayed": False, "post_attempts": 1}
                    self.assertTrue(dispatch_once(store, self.p, transport))
                    self.assertFalse(dispatch_once(store, self.p, transport))
                self.assertEqual(transport.request.call_count, 1)

    def test_unresolved_dispatch_blocks_after_restart(self):
        store = Store(self.root / "store")
        j, following = text_job(), text_job("following")
        store.accept(j)
        store.accept(following)
        store.claim(j, self.p)
        store = Store(store.root)
        with self.assertRaises(ValueError):
            store.claim(following, self.p, now=time.time() + 200)

    @unittest.skipUnless(os.name == "nt", "Windows 内核文件锁，仅在隔离 PW 上运行")
    def test_windows_executor_lock_and_crash_release(self):
        tools = str(Path(__file__).resolve().parents[1] / "tools")
        code = "import sys;sys.path.insert(0,sys.argv[1]);from relay_guest import single_executor\nwith single_executor(sys.argv[2]): print('locked')"
        with single_executor(self.root):
            result = subprocess.run([sys.executable, "-B", "-c", code, tools, str(self.root)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        result = subprocess.run([sys.executable, "-B", "-c", code, tools, str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        code = "import sys,os;sys.path.insert(0,sys.argv[1]);from relay_guest import single_executor\nwith single_executor(sys.argv[2]): os._exit(99)"
        result = subprocess.run([sys.executable, "-B", "-c", code, tools, str(self.root)])
        self.assertEqual(result.returncode, 99)
        with single_executor(self.root):
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
