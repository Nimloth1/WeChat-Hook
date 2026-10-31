"""合成附件权限回归；只读取指定桌面进程令牌，不读内存、不注入、不发送。"""
import ctypes
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from relay_assets import receive
from relay_common import Store


class DirectoryPermissionsTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX mode check")
    def test_posix_receive_remains_private(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state")
            path = store.root / "spool" / "task" / "media.bin"
            data = b"offline fixture"
            receive(io.BytesIO(data), path, {"filename": "a.pdf", "size": len(data),
                                           "sha256": hashlib.sha256(data).hexdigest()})
            self.assertEqual(stat.S_IMODE(store.root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == "nt" and os.environ.get("RELAY_DESKTOP_TOKEN_PID"),
                         "Windows regression requires an explicit same-user desktop token PID")
    def test_receive_rename_readable_with_desktop_token(self):
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        def api(lib, name, result, args):
            f = getattr(lib, name)
            f.restype, f.argtypes = result, args
            return f
        close = api(kernel, "CloseHandle", w.BOOL, [w.HANDLE])
        open_process = api(kernel, "OpenProcess", w.HANDLE, [w.DWORD, w.BOOL, w.DWORD])
        open_token = api(advapi, "OpenProcessToken", w.BOOL, [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)])
        duplicate = api(advapi, "DuplicateToken", w.BOOL, [w.HANDLE, ctypes.c_int, ctypes.POINTER(w.HANDLE)])
        impersonate = api(advapi, "ImpersonateLoggedOnUser", w.BOOL, [w.HANDLE])
        revert = api(advapi, "RevertToSelf", w.BOOL, [])
        create = api(kernel, "CreateFileW", w.HANDLE,
                     [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE])
        process = open_process(0x1000, False, int(os.environ["RELAY_DESKTOP_TOKEN_PID"]))
        self.assertTrue(process, "desktop process query failed")
        token, copy = w.HANDLE(), w.HANDLE()
        try:
            self.assertTrue(open_token(process, 0xA, ctypes.byref(token)))
            self.assertTrue(duplicate(token, 2, ctypes.byref(copy)))
            system = Path(os.environ["SystemRoot"]) / "System32"
            identity = subprocess.run([str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                                      capture_output=True, check=True, timeout=10).stdout
            sid = re.search(rb'S-1-5-[0-9-]+', identity)
            self.assertIsNotNone(sid)
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                # Model the provisioned private root: SYSTEM/admin plus the actual user SID.
                # A 3.13 elevated tempfile initially grants only its default owner (admin).
                subprocess.run([str(system / "icacls.exe"), str(root), "/grant",
                                "*" + sid[0].decode("ascii") + ":(OI)(CI)F", "/q"],
                               capture_output=True, check=True, timeout=10)
                store = Store(root / "state")
                for name, data in (("Dubai Price Complex.pdf", b"%PDF-1.4\noffline\n"),
                                   ("image.jpg", b"\xff\xd8\xffoffline"),
                                   ("clip.mp4", b"\0\0\0\x18ftypmp42offline")):
                    with self.subTest(name=name):
                        incoming = store.root / "spool" / name / "media.bin"
                        receive(io.BytesIO(data), incoming, {"filename": name, "size": len(data),
                                "sha256": hashlib.sha256(data).hexdigest()})
                        asset = store.root / "assets" / name / "media" / name
                        asset.parent.mkdir(parents=True)
                        os.rename(incoming, asset)
                        self.assertTrue(impersonate(copy))
                        try:
                            handle = create(str(asset), 0x80000000, 1, None, 3, 0x00200080, None)
                            error = ctypes.get_last_error()
                            if handle != ctypes.c_void_p(-1).value:
                                close(handle)
                            self.assertNotEqual(handle, ctypes.c_void_p(-1).value,
                                                "desktop read failed: WinError " + str(error))
                        finally:
                            self.assertTrue(revert())
                        self.assertEqual(hashlib.sha256(asset.read_bytes()).hexdigest(),
                                         hashlib.sha256(data).hexdigest())
        finally:
            if copy:
                close(copy)
            if token:
                close(token)
            close(process)


if __name__ == "__main__":
    unittest.main()
