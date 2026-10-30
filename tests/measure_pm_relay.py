"""128MiB 合成附件完整周期的内存/磁盘写入测量，不连接微信或网络。"""
import base64
import gc
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pm_relay import FakeHook, event, policy
from relay_assets import snapshot
from relay_common import asset_path
from relay_common import Store, make_job
from relay_guest import Executor
from relay_pm import dispatch_once


def counters():
    if sys.platform == "darwin":
        import ctypes
        import os
        import resource
        class RUsageV2(ctypes.Structure):
            _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in (
                "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups", "pageins",
                "wired_size", "resident_size", "phys_footprint", "proc_start_abstime",
                "proc_exit_abstime", "child_user_time", "child_system_time", "child_pkg_idle_wkups",
                "child_interrupt_wkups", "child_pageins", "child_elapsed_abstime", "diskio_bytesread", "diskio_byteswritten")]
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        info = RUsageV2()
        if lib.proc_pid_rusage(os.getpid(), 2, ctypes.byref(info)) != 0:
            raise RuntimeError("proc_pid_rusage_failed")
        r = resource.getrusage(resource.RUSAGE_SELF)
        return {"peak_rss_bytes": r.ru_maxrss, "write_bytes": info.diskio_byteswritten}
    import ctypes
    from ctypes import wintypes
    class Memory(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (x, ctypes.c_size_t) for x in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                "PagefileUsage", "PeakPagefileUsage")]
    class IO(ctypes.Structure):
        _fields_ = [(x, ctypes.c_ulonglong) for x in ("read_ops", "write_ops", "other_ops",
                                                        "read_bytes", "write_bytes", "other_bytes")]
    kernel = ctypes.windll.kernel32
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    proc = kernel.GetCurrentProcess()
    m, io = Memory(), IO()
    m.cb = ctypes.sizeof(m)
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
    kernel.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IO)]
    if not ctypes.windll.psapi.GetProcessMemoryInfo(proc, ctypes.byref(m), m.cb):
        raise ctypes.WinError()
    if not kernel.GetProcessIoCounters(proc, ctypes.byref(io)):
        raise ctypes.WinError()
    return {"peak_rss_bytes": m.PeakWorkingSetSize, "write_bytes": io.write_bytes}


def main():
    with tempfile.TemporaryDirectory(dir=os.environ.get("RELAY_TEST_TMP")) as folder:
        root = Path(folder)
        before = counters()
        started = time.monotonic()
        pm, guest = Store(root / "pm"), Store(root / "guest")
        permit = root / "permit.json"
        hook = FakeHook(permit)
        executor = Executor(guest, policy(), permit, hook)
        size = 128 * 1024 * 1024
        source = root / "synthetic.bin"
        with source.open("wb") as f:
            f.truncate(size)
        job = make_job(event(), policy(), "file", {
            "filename": "synthetic.bin", "size": size, "sha256": "a" * 64})
        meta = snapshot(source, asset_path(pm.root, job["id"], "media"), "synthetic.bin", size)
        job = make_job(event(), policy(), "file", meta)
        pm.accept(job)
        class LocalTransport:
            def request(self, request):
                # 真正走流式上传实现；文件不进入 JSON。替身只替换网络和微信。
                with asset_path(pm.root, job["id"], "media").open("rb") as f:
                    executor.upload(job, "media", f)
                return json.loads(json.dumps(executor.dispatch(json.loads(json.dumps(request))["job"])))
        assert dispatch_once(pm, policy(), LocalTransport())
        assert len(hook.posts) == 1
        assert not permit.exists()
        assert not list((guest.root / "assets").glob("*/*"))
        after_cycle = counters()
        gc.collect()
        # 无变化的完整空转路径应不写账本。
        for _ in range(100):
            assert not dispatch_once(pm, policy(), LocalTransport())
            pm.status()
            guest.status()
        after_idle = counters()
        result = {"synthetic_media_bytes": size,
                  "seconds": round(time.monotonic() - started, 3),
                  "peak_rss_bytes": after_idle["peak_rss_bytes"],
                  "cycle_process_write_bytes": after_cycle["write_bytes"] - before["write_bytes"],
                  "idle_100_process_write_bytes": after_idle["write_bytes"] - after_cycle["write_bytes"],
                  "post_attempts_fake_only": len(hook.posts), "actual_wechat_calls": 0,
                  "temporary_test_data_cleaned_on_exit": True}
        print(json.dumps(result))
        assert result["peak_rss_bytes"] < 512 * 1024 * 1024
        assert result["idle_100_process_write_bytes"] == 0


if __name__ == "__main__":
    main()
