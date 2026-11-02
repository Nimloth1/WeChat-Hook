"""真实 V2 编解码 + 临时账本；不连接微信、不发送。"""
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from test_pm_relay import event, policy
from relay_common import Store, canonical, asset_path
from relay_pm import Decoder, Tail, resolve_media


class OriginalImageTest(unittest.TestCase):
    def setUp(self):
        try:
            from Crypto.Cipher import AES
            from PIL import Image
        except ImportError:
            self.skipTest("使用现有PM媒体环境执行")
        self.aes, self.image = AES, Image
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = b"0123456789abcdef"
        self.paths = []
        self.decoder = Decoder.__new__(Decoder)
        self.decoder.decoder = mock.Mock(_key=(self.key, 90))
        self.decoder.decoder.find.side_effect = lambda *_: list(self.paths)
        self.decoder.aes = AES
        self.decoder.image_rejections = {}
        self.store = Store(self.root / "store")
        self.source = self.root / "messages.jsonl"
        self.source.write_text("")
        self.tail = Tail(self.source, self.store, policy())
        self.tail.baseline()

    def png(self, size, pad=0):
        out = io.BytesIO()
        self.image.new("RGB", size, "blue").save(out, format="PNG")
        data = out.getvalue()
        return data + b"\0" * max(0, pad - len(data))

    def encrypted(self, name, data):
        plain = data[:32] + b"\x10" * 16
        body = (self.aes.new(self.key, self.aes.MODE_ECB).encrypt(plain)
                + data[32:-10] + bytes(x ^ 90 for x in data[-10:]))
        path = self.root / name
        path.write_bytes(b"\x07\x08V2\x08\x07" + struct.pack("<II", 32, 10) + b"\0" + body)
        if str(path) not in self.paths:
            self.paths.append(str(path))
        return path

    def queue(self, info):
        e = event("original-image", type=3, image_md5="a" * 32, image_info=info)
        self.source.write_text(canonical(e) + "\n")
        self.assertEqual(self.tail.poll(), 1)
        with self.store.connect() as db:
            import json
            item = json.loads(db.execute("SELECT payload FROM media").fetchone()[0])
        self.assertEqual(item["event"]["image_info"], info)
        return item["id"]

    def test_preview_first_original_later_enters_queue_only_once(self):
        full = self.png((2159, 12000))
        info = {"original_bytes": len(full), "width": 2159, "height": 12000}
        key = self.queue(info)
        self.encrypted("image.dat", self.png((143, 800)))
        dest = asset_path(self.store.root, key, "media")
        before = self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns
        for _ in range(20):
            resolve_media(self.store, policy(), self.decoder)
        self.assertIsNone(self.store.next_job())
        self.assertFalse(dest.exists())
        self.assertFalse(dest.with_suffix(".candidate").exists())
        self.assertEqual(before, (self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns))
        self.encrypted("image_h.dat", full)
        resolve_media(self.store, policy(), self.decoder)
        job = self.store.next_job()
        self.assertEqual(job["payload"]["size"], len(full))
        self.assertEqual(job["payload"]["sha256"], hashlib.sha256(full).hexdigest())
        self.assertEqual(dest.read_bytes(), full)
        self.assertEqual(self.store.status()["counts"], {"ready": 1})
        before = self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns, dest.stat().st_mtime_ns
        resolve_media(self.store, policy(), self.decoder)
        self.assertEqual(before, (self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns,
                                  dest.stat().st_mtime_ns))

    def test_full_and_preview_available_order_does_not_matter(self):
        full = self.png((280, 1043))
        info = {"original_bytes": len(full), "width": 280, "height": 1043}
        self.encrypted("preview.dat", self.png((21, 80)))
        self.encrypted("full_h.dat", full)
        for reverse in (False, True):
            if reverse:
                self.paths.reverse()
            dest = self.root / ("reverse.bin" if reverse else "forward.bin")
            result = self.decoder.image("group", "md5", dest, info)
            self.assertEqual(result["sha256"], hashlib.sha256(full).hexdigest())
            self.assertEqual(dest.read_bytes(), full)

    def test_wrong_size_never_creates_candidate(self):
        data = self.png((16, 16))
        self.encrypted("preview.dat", data)
        dest = self.root / "missing.bin"
        for _ in range(3):
            self.assertIsNone(self.decoder.image("group", "md5", dest,
                              {"original_bytes": len(data) + 1, "width": 16, "height": 16}))
        self.assertFalse(dest.exists())
        self.assertFalse(dest.with_suffix(".candidate").exists())

    def test_matching_size_wrong_dimensions_waits_without_repeated_writes(self):
        wrong, full = self.png((32, 48), 400), self.png((64, 24), 400)
        self.assertEqual(len(wrong), len(full))
        info = {"original_bytes": len(full), "width": 64, "height": 24}
        path = self.encrypted("same-size.dat", wrong)
        dest = self.root / "checked.bin"
        with mock.patch.object(self.decoder, "decode", wraps=self.decoder.decode) as decode:
            for _ in range(20):
                self.assertIsNone(self.decoder.image("group", "md5", dest, info))
            self.assertEqual(decode.call_count, 1)
            self.assertFalse(dest.exists())
            self.assertFalse(dest.with_suffix(".candidate").exists())
            self.encrypted(path.name, full)
            self.assertEqual(self.decoder.image("group", "md5", dest, info)["size"], len(full))
            self.assertEqual(decode.call_count, 2)
        self.assertEqual(dest.read_bytes(), full)

    def test_missing_or_invalid_metadata_never_falls_back(self):
        data = self.png((16, 16))
        self.encrypted("preview.dat", data)
        good = {"original_bytes": len(data), "width": 16, "height": 16}
        for info in (None, {}, {"width": 16}, {**good, "original_bytes": True},
                     {**good, "original_bytes": 0}, {**good, "original_bytes": "100"},
                     {**good, "width": 0}, {**good, "height": False}):
            with self.subTest(info=info):
                dest = self.root / "no-metadata" / "output.bin"
                self.assertIsNone(self.decoder.image("group", "md5", dest, info))
                self.assertFalse(dest.parent.exists())

    def test_size_is_required_known_dimensions_are_optional(self):
        data = self.png((16, 16))
        self.encrypted("full.dat", data)
        result = self.decoder.image("group", "md5", self.root / "full.bin",
                                    {"original_bytes": len(data)})
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()
