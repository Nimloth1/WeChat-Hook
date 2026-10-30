"""合成事件/伪 Hook/临时账本；绝不连接真实微信或发消息。"""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import subprocess
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from relay_common import assets, asset_path, Store, canonical, digest, file_hash, make_job, validate_job, validate_policy
from relay_guest import Executor as RealExecutor, assert_idle, single_executor
from relay_pm import Decoder, Tail, dispatch_once, resolve_media


def policy():
    return {"version": 2, "enabled": True, "recipient": "11111111111@chatroom",
            "source": "22222222222@chatroom", "corporations": ["国泰君安期货"]}


def event(mid="1000", **kwargs):
    return {"server_id": mid, "local_id": 1, "conversation_id": policy()["source"],
            "sender_corp": "国泰君安期货", "is_self": False, "is_chatroom": True,
            "sender": "测试员", "ts": time.time(), "type": 1, "content": "真实内容仅为合成夹具", **kwargs}


def text_job(mid="1000"):
    return make_job(event(mid), policy(), "text", {"text": "hello 离线夹具"})


FIXTURES = {}


def descriptor(data, name="离线夹具.png"):
    sha = hashlib.sha256(data).hexdigest()
    FIXTURES[sha] = data
    return {"filename": name, "sha256": sha, "size": len(data)}


def media_job(kind="image", mid="2000"):
    payload = descriptor(b"\x89PNG\r\n\x1a\n" + b"test" * 100)
    if kind == "video":
        payload = {"media": descriptor(b"\x00\x00\x00\x18ftypmp42test", "clip.mp4"),
                   "thumbnail": descriptor(b"\xff\xd8\xfftest", "cover.jpg"), "duration_seconds": 2}
    return make_job(event(mid), policy(), kind, payload)


class Executor(RealExecutor):
    """合成传输入口：确实通过生产 upload 代码写入附件，而非跳过校验。"""
    def dispatch(self, job):
        if self.store.receipt(job["id"]) is None and self.policy["enabled"] and not self.permit.exists() and not self.store.get("paused"):
            for role, spec in assets(job).items():
                self.upload(job, role, io.BytesIO(FIXTURES[spec["sha256"]]))
        return super().dispatch(job)


class FakeHook:
    def __init__(self, permit, mode="ok"):
        self.permit = permit
        self.mode = mode
        self.posts = []

    def status(self):
        after = bool(self.posts)
        try:
            approval = json.loads(self.permit.read_text())
            configured = (approval.get("version") == 2 and approval.get("enabled") is True
                          and type(approval.get("expires_utc")) is int and approval["expires_utc"] == 0)
        except (OSError, ValueError, AttributeError):
            configured = False
        return {"ApprovalReload": "per_request", "ApprovalVersion2GroupOnly": True,
                "NativeOwnershipMode": "native_reference_ownership", "NativeOwnershipFault": False,
                "SendApprovalConfigured": configured, "SendInProgress": False,
                "PendingMessageOwners": 1 if after and self.mode == "pending" else 0,
                "RetainedParameterBytes": 0, "RetainedPayloadHandles": 0, "FileSendSupported": True}

    def request(self, method, endpoint, request, token):
        assert method == "POST"
        approval = json.loads(self.permit.read_text())
        assert token == approval["token"]
        kind = {"/SendTextMsg": "text", "/SendImgMsg": "image", "/send_file_msg": "file", "/send_video_msg": "video", "/send_link_msg": "link"}[endpoint]
        # 独立复现 C++ Fingerprint 旧协议：文字也必须含空 image_sha256。
        fp = {"kind": kind, "recipient": request["wxidorgid"],
              "value": request.get("msg", request.get("path")), "image_sha256": ""}
        if kind == "link":
            fp = {"kind": "link", "recipient": request["wxidorgid"],
                  **{k: request[k] for k in ("title", "description", "url")}}
            assert len(request) == 5
        elif kind != "text":
            field = "image_sha256" if kind == "image" else "file_sha256"
            if kind in {"file", "video"}:
                del fp["image_sha256"]
            fp[field] = file_hash(request["path"])
            assert request[field] == fp[field]
            if kind == "video":
                fp.update(thumbnail_path=request["thumbnail_path"], thumbnail_sha256=file_hash(request["thumbnail_path"]),
                          duration_seconds=request["duration_seconds"])
                assert request["thumbnail_sha256"] == fp["thumbnail_sha256"]
                assert len(request) == 7
            else:
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
        for key, bad in (("enabled", 1), ("version", 1), ("interval_seconds", 180),
                         ("daily_messages", 120), ("daily_media_bytes", 67108864),
                         ("recipient", "filehelper"), ("source", self.p["recipient"]),
                         ("corporations", [])):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ValueError):
                    validate_policy({**self.p, key: bad})

    def test_job_validation(self):
        j = text_job()
        for key, bad in (("kind", "unknown"), ("recipient", "3333@chatroom"),
                         ("source", "4444@chatroom"), ("id", "a" * 64),
                         ("corporation", "其他公司"), ("source_ts", float("nan")), ("source_ts", True)):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ValueError):
                    validate_job({**j, key: bad}, self.p)
        for bad in ["", "  ", "hello\x00"]:
            with self.subTest(text=repr(bad[:10])):
                with self.assertRaises(ValueError):
                    validate_job({**j, "payload": {"text": bad}}, self.p)

    def test_media_validation(self):
        j = media_job()
        for name in ["../x.png", "a\\b.png", "CON.txt", "NUL", "COM1.mp3", "a.", "a ", ""]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    validate_job({**j, "payload": {**j["payload"], "filename": name}}, self.p)
        for field, value in [("sha256", "bad"), ("size", 0), ("size", True)]:
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
        self.assertEqual(text["kind"], "text")
        self.assertIn("😀" * 1200, text["payload"]["text"])

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
        decoder.image.return_value = descriptor(b"fake png bytes", "image.png")
        resolve_media(store, self.p, decoder)
        self.assertEqual(store.status()["counts"], {"ready": 2})
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        resolve_media(store, self.p, decoder)
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))

    def test_no_interval_or_daily_quota_across_restart(self):
        clock = [time.time()]
        with mock.patch("time.time", side_effect=lambda: clock[0]):
            pm, guest = Store(self.root / "pm"), Store(self.root / "guest")
            permit = self.root / "permit.json"
            hook = FakeHook(permit)
            executor = Executor(guest, self.p, permit, hook, reclaim_timeout=0)
            class Transport:
                def request(self, request):
                    return executor.dispatch(request["job"])
            # 同一秒内连续130条，跨账本重开超过旧120条配额，仍逐条只发一次。
            for i in range(130):
                pm = Store(pm.root)
                pm.accept(text_job(str(i)))
                self.assertTrue(dispatch_once(pm, self.p, Transport()))
            self.assertEqual(len(hook.posts), 130)
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
        decoder.image.side_effect = lambda _, md5, path: descriptor(b"image", "image.png") if md5 in {md5s[10], md5s[24]} else None
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
        decoder.file.return_value = descriptor(b"pdf", "new.pdf")
        resolve_media(store, self.p, decoder)
        with source.open("a") as f:
            f.write(canonical(event("new-file", type=49, file={"name": "new.pdf", "size": 3})) + "\n")
        tail.poll()
        store = Store(store.root)  # 游标可重置，但不能每轮从头开始。
        resolve_media(store, self.p, decoder)
        self.assertIsNone(store.next_job())
        resolve_media(store, self.p, decoder)
        self.assertEqual(store.next_job()["kind"], "file")
        self.assertEqual(decoder.file.call_count, 1)
        self.assertEqual(decoder.file.call_args.args[:2], ("new.pdf", 3))

    def test_pause_still_blocks_dispatch(self):
        store = Store(self.root / "store")
        j = media_job()
        store.accept(j)
        store.pause("test")
        self.assertFalse(store.claim(j, self.p))

    def test_guest_exact_text_image_file_and_persistent_replay(self):
        for kind in ["text", "image", "file", "video", "link"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                store = Store(Path(folder) / "guest")
                permit = Path(folder) / "permit.json"
                hook = FakeHook(permit)
                executor = Executor(store, self.p, permit, hook, reclaim_timeout=0)
                j = (text_job() if kind == "text" else make_job(event(), self.p, "link", {
                    "title": "离线卡片", "description": "说明", "url": "https://example.com/a?a=1&b=2"})
                     if kind == "link" else media_job(kind))
                result = executor.dispatch(j)
                self.assertEqual(result["receipt"]["state"], "submitted_unconfirmed")
                self.assertFalse(result["receipt"]["delivery_confirmed"])
                self.assertFalse(permit.exists())
                self.assertEqual(list((store.root / "assets").glob("*/*/*")) if (store.root / "assets").exists() else [], [])
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
                assets = list((store.root / "assets").glob("*/*/*"))
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
                self.assertTrue(list((executor.store.root / "assets").glob("*/*/*")))
                state["PendingMessageOwners"] = 1
            return state
        hook.status = status
        with mock.patch("relay_guest.time.sleep") as sleep:
            result = executor.dispatch(media_job())
        self.assertEqual(result["receipt"]["state"], "submitted_unconfirmed")
        self.assertTrue(observed_pending)
        self.assertEqual(sleep.call_count, 1)

    def test_streaming_file_over_old_limit_and_duplicate_names(self):
        decoder = Decoder.__new__(Decoder)
        decoder.decoder = mock.Mock(account_dir=str(self.root))
        base = self.root / "msg/file/2026-10"
        base.mkdir(parents=True)
        source = base / "test(1).pdf"
        with source.open("wb") as f:
            f.truncate(21 * 1024 * 1024)
        destination = self.root / "stage.bin"
        result = decoder.file("test.pdf", source.stat().st_size, destination)
        self.assertEqual(result["size"], 21 * 1024 * 1024)
        self.assertEqual(result["sha256"], file_hash(source))
        self.assertLess(len(canonical(result)), 512)
        self.assertIsNone(decoder.file("test.pdf", 9, self.root / "missing.bin"))

    def test_streaming_v2_decode(self):
        try:
            from Crypto.Cipher import AES
            from PIL import Image
        except ImportError:
            self.skipTest("使用现有PM媒体环境执行")
        decoder = Decoder.__new__(Decoder)
        key = b"0123456789abcdef"
        decoder.decoder = mock.Mock(_key=(key, 90))
        decoder.aes = AES
        image = io.BytesIO()
        Image.new("RGB", (16, 16), "blue").save(image, format="PNG")
        original = image.getvalue()
        plain = original[:32] + b"\x10" * 16
        body = AES.new(key, AES.MODE_ECB).encrypt(plain) + original[32:-10] + bytes(x ^ 90 for x in original[-10:])
        path = self.root / "fixture.dat"
        path.write_bytes(b"\x07\x08V2\x08\x07" + struct.pack("<II", 32, 10) + b"\0" + body)
        out = self.root / "decoded"
        self.assertIsNotNone(decoder.decode(path, out))
        self.assertEqual(out.read_bytes(), original)

    def test_upload_stream_hash_length_and_exclusive_creation(self):
        from relay_assets import receive, snapshot
        spec = descriptor(b"approved bytes", "sample.pdf")
        path = self.root / "incoming"
        for data in [b"short", b"approved bytes extra", b"tampered bytes"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                receive(io.BytesIO(data), path, spec)
            self.assertFalse(path.exists())
        receive(io.BytesIO(b"approved bytes"), path, spec)
        with self.assertRaises(FileExistsError):
            receive(io.BytesIO(b"approved bytes"), path, spec)
        with self.assertRaises(FileExistsError):
            snapshot(path, path, "sample.pdf")
        self.assertEqual(path.read_bytes(), b"approved bytes")

    def test_video_and_link_classification_uses_existing_jsonl(self):
        _, store, tail = self.baseline()
        card, kind = tail.classify(event(type=(5 << 32) | 49,
            content="[文章] 能化周报\nhttps://example.com/report?a=1&b=2"))
        self.assertEqual(kind, "job")
        self.assertEqual(card["kind"], "link")
        self.assertEqual(card["payload"], {"title": "能化周报", "description": "",
                                         "url": "https://example.com/report?a=1&b=2"})
        video, kind = tail.classify(event(type=43, video={"md5": "a" * 32, "size": 123}))
        self.assertEqual(kind, "media")
        self.assertEqual(video["kind"], "video")
        for url in ["file:///private/data", "https://user@host/a", "https://host:0/", "https://host/a b"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                tail.classify(event(type=(5 << 32) | 49, content="[文章] 周报\n" + url))

    def test_real_offline_mp4_probe_and_jpeg_thumbnail(self):
        ffmpeg, ffprobe = "/opt/homebrew/bin/ffmpeg", "/opt/homebrew/bin/ffprobe"
        if not Path(ffmpeg).is_file() or not Path(ffprobe).is_file():
            self.skipTest("此环境没有已有的FFmpeg；不下载依赖")
        source = self.root / "msg/video/2026-10" / ("a" * 32 + ".mp4")
        source.parent.mkdir(parents=True)
        subprocess.run([ffmpeg, "-v", "error", "-nostdin", "-f", "lavfi", "-i",
            "color=c=blue:s=64x64:r=2:d=1", "-threads", "1", "-c:v", "mpeg4", str(source)],
            check=True, capture_output=True, timeout=20)
        decoder = Decoder.__new__(Decoder)
        decoder.decoder = mock.Mock(account_dir=str(self.root))
        decoder.ffmpeg, decoder.ffprobe = ffmpeg, ffprobe
        media, thumbnail = self.root / "stage/media.bin", self.root / "stage/thumbnail.bin"
        result = decoder.video({"md5": "a" * 32, "size": source.stat().st_size}, media, thumbnail)
        self.assertEqual(result["duration_seconds"], 1)
        self.assertEqual(result["media"]["sha256"], file_hash(source))
        self.assertTrue(thumbnail.read_bytes().startswith(b"\xff\xd8\xff"))
        job = make_job(event(), self.p, "video", result)
        self.assertEqual(set(assets(job)), {"media", "thumbnail"})

    def test_attachment_larger_than_old_daily_quota_has_small_ledger(self):
        # 描述符可表示任意文件长度；不分配几GiB数据来模拟。
        store = Store(self.root / "store")
        j = make_job(event(), self.p, "file", {"filename": "large.bin", "sha256": "a" * 64,
                                               "size": 3 * 1024**3})
        store.accept(j)
        self.assertTrue(store.claim(j, self.p))
        self.assertLess(store.path.stat().st_size, 128 * 1024)

    @unittest.skipUnless(sys.platform == "darwin", "仅PM启动离线媒体工具")
    def test_media_tool_timeout_and_output_budget_stop_own_child(self):
        from relay_pm import media_tool
        self.assertEqual(media_tool([sys.executable, "-c", "print('ok')"], 3, self.root), b"ok\n")
        for code, timeout in [("import time;time.sleep(5)", 0.1), ("print('x'*5000)", 3)]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                media_tool([sys.executable, "-c", code], timeout, self.root)

    def test_age_gate_is_explicit_and_does_not_make_unknown_attempt(self):
        store = Store(self.root / "store")
        old = make_job(event(ts=time.time() - 86401), self.p, "text", {"text": "合成旧任务"})
        store.accept(old)
        transport = mock.Mock()
        with self.assertRaisesRegex(ValueError, "pending_job_expired"):
            dispatch_once(store, self.p, transport)
        self.assertEqual(store.receipt(old["id"])["state"], "ready")
        transport.request.assert_not_called()

    def test_upgrade_preserves_cursor_and_attempts_and_rejects_pending(self):
        from relay_upgrade import upgrade
        _, store, tail = self.baseline()
        previous = {**self.p, "version": 1, "interval_seconds": 180,
                    "daily_messages": 120, "daily_media_bytes": 67108864}
        with store.connect() as db:
            store.put(db, "policy_scope", digest(previous))
        cursor, activated = store.get("cursor"), store.get("activated_at")
        j = text_job()
        store.accept(j)
        with self.assertRaisesRegex(ValueError, "pending_jobs"):
            upgrade(store, previous, self.p)
        store.claim(j, self.p)
        store.finish(j["id"], "submitted_unconfirmed", {"test": True})
        self.assertEqual(upgrade(store, previous, self.p)["sends"], 0)
        self.assertEqual(store.get("cursor"), cursor)
        self.assertEqual(store.get("activated_at"), activated)
        self.assertEqual(store.receipt(j["id"])["state"], "submitted_unconfirmed")
        before = store.path.read_bytes(), store.path.stat().st_mtime_ns
        upgrade(store, previous, self.p)
        self.assertEqual(before, (store.path.read_bytes(), store.path.stat().st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "scope_changed"):
            upgrade(store, previous, {**self.p, "recipient": "99999@chatroom"})

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

    def test_guest_entry_starts_with_isolated_import_path(self):
        tools = Path(__file__).resolve().parents[1] / "tools"
        entry = self.root / "执行器 code"
        entry.mkdir()
        for name in ["relay_guest.py", "relay_common.py", "relay_assets.py"]:
            shutil.copyfile(tools / name, entry / name)
        foreign = self.root / "unrelated cwd"
        foreign.mkdir()
        (foreign / "relay_common.py").write_text("raise RuntimeError('untrusted cwd module')\n")
        env = {**os.environ, "PYTHONPATH": str(foreign)}
        executables = [sys.executable]
        if os.environ.get("RELAY_EMBEDDED_PYTHON"):
            executables.append(os.environ["RELAY_EMBEDDED_PYTHON"])
        for executable in executables:
            with self.subTest(executable=executable):
                result = subprocess.run([executable, "-I", "-B", str(entry / "relay_guest.py"), "--help"],
                                        cwd=foreign, env=env, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertIn(b"--config", result.stdout)
        self.assertEqual({p.name for p in entry.iterdir()}, {"relay_guest.py", "relay_common.py", "relay_assets.py"})
        self.assertEqual({p.name for p in foreign.iterdir()}, {"relay_common.py"})

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

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell二进制stdin，仅隔离PW运行")
    def test_windows_powershell_binary_upload_then_fake_dispatch(self):
        tools = Path(__file__).resolve().parents[1] / "tools"
        driver = self.root / "offline-rpc.py"
        cfg = self.root / "config.json"
        cfg.write_text(canonical({"policy": self.p, "state_dir": str(self.root / "state")}))
        # 只在本测试子进程中替换主机身份/模块检查/Hook；不接触真实安装或端口。
        driver.write_text("\n".join([
            "import os,sys;from pathlib import Path",
            "sys.path.insert(0," + repr(str(tools)) + ")",
            "sys.path.insert(0," + repr(str(Path(__file__).parent)) + ")",
            "import relay_guest as g;from test_pm_relay import FakeHook",
            "os.environ['COMPUTERNAME']='VW12'",
            "os.environ['LOCALAPPDATA']=" + repr(str(self.root / "local")),
            "original=g.file_hash",
            "g.file_hash=lambda p: g.HOOK_MODULE if Path(p).name=='version.dll' else g.SOURCE_MODULE if Path(p).name=='Weixin.dll' else original(p)",
            "g.Hook=lambda:FakeHook(Path(os.environ['LOCALAPPDATA'])/'VW12-WeChatHook'/'send-approval.json')",
            "sys.argv=[sys.argv[0],'--config'," + repr(str(cfg)) + "]",
            "raise SystemExit(g.main())",
        ]), encoding="utf-8")
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        script = ("$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();& "
                  + quote(sys.executable) + " -B " + quote(driver) + ";exit $LASTEXITCODE")
        command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                   base64.b64encode(script.encode("utf-16le")).decode()]
        data = bytes(range(256)) * 1000
        job = make_job(event(), self.p, "file", descriptor(data, "binary.dat"))
        header = {"operation": "upload", "policy_sha256": digest(self.p), "job": job, "role": "media"}
        upload = subprocess.run(command, input=(canonical(header) + "\n").encode() + data,
                                capture_output=True, timeout=30)
        self.assertEqual(upload.returncode, 0, upload.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(upload.stdout.decode("utf-8-sig"))["uploaded"], job["payload"]["sha256"])
        dispatch = subprocess.run(command, input=(canonical({"operation": "dispatch",
            "policy_sha256": digest(self.p), "job": job}) + "\n").encode(), capture_output=True, timeout=30)
        self.assertEqual(dispatch.returncode, 0, dispatch.stderr.decode(errors="replace"))
        result = json.loads(dispatch.stdout.decode("utf-8-sig"))
        self.assertEqual(result["receipt"]["state"], "submitted_unconfirmed")
        self.assertEqual(result["post_attempts"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
