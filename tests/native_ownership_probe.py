# encoding: UTF-8
"""只在 CPU 模拟器中验证 4.1.10.27 的参数所有权，不加载或连接微信。

依赖 unicorn==2.1.4。输入必须是指定摘要的本地 Weixin.dll；不自动下载。
分配器、UUID 生成和最外层调度队列是替身，其余使用原文件指令。
这不是生产回收实现，也不证明文件读取完成、真实发送或账号安全。
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import time

from unicorn import (
    Uc,
    UC_ARCH_X86,
    UC_MODE_64,
    UC_HOOK_CODE,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
)

EXPECTED_SHA256 = "f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36"


class PE:
    def __init__(self, path):
        if path.stat().st_size != 183094832:
            raise ValueError("native_size_mismatch")
        with path.open("rb") as f:
            digest = hashlib.sha256()
            for block in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != EXPECTED_SHA256:
            raise ValueError("native_hash_mismatch")
        self.file = path.open("rb")
        self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        u16 = lambda p: struct.unpack_from("<H", self.data, p)[0]
        u32 = lambda p: struct.unpack_from("<I", self.data, p)[0]
        pe = u32(60)
        if (
            self.data[:2] != b"MZ"
            or self.data[pe : pe + 4] != b"PE\0\0"
            or u16(pe + 4) != 0x8664
        ):
            raise ValueError("native_arch_mismatch")
        self.image_size = u32(pe + 24 + 56)
        self.sections = []
        for i in range(u16(pe + 6)):
            p = pe + 24 + u16(pe + 20) + 40 * i
            self.sections.append((u32(p + 12), u32(p + 16), u32(p + 20)))

    def read(self, r, n):
        for v, size, raw in self.sections:
            if v <= r < v + size:
                return self.data[
                    raw + r - v : raw + r - v + min(n, v + size - r)
                ] + bytes(max(0, n - (v + size - r)))
        raise ValueError("unmapped_image_rva")

    def close(self):
        self.data.close()
        self.file.close()


pe = None
B = 0x180000000
H = 0x300000000
S = 0x400000000
END = 0x500000000


class VM:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.allocs = {}
        self.freed = set()
        self.next = H
        self.pages = set()
        self.steps = 0
        self.calls = []
        self.queue = []
        self.peak = 0
        self.total = 0
        self.run_limit = 0
        self.uc.mem_map(H, 16 * 1024 * 1024)
        self.uc.mem_map(S, 1024 * 1024)
        self.uc.mem_map(END, 4096)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self.unmapped)
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.access,
            begin=H,
            end=H + 16 * 1024 * 1024 - 1,
        )

    def access(self, u, access, a, n, value, data):
        if not any(p <= a and a + n <= p + size for p, size in self.allocs.items()):
            raise RuntimeError("invalid_heap_access:" + hex(a))

    def unmapped(self, u, access, a, n, value, data):
        p = a & ~4095
        r = p - B
        if not 0 <= r < pe.image_size:
            raise RuntimeError("outside image " + hex(a))
        try:
            raw = pe.read(r, 4096)
        except ValueError:
            raw = bytes(4096)
        if len(self.pages) >= 8192:
            raise RuntimeError("image_page_budget")
        u.mem_map(p, 4096)
        u.mem_write(p, raw)
        self.pages.add(p)
        return True

    def q(self, p):
        if B <= p < B + pe.image_size:
            for a in {p & ~4095, (p + 7) & ~4095}:
                if a not in self.pages:
                    self.unmapped(self.uc, 0, a, 8, 0, None)
        if H <= p < H + 16 * 1024 * 1024:
            self.access(self.uc, 0, p, 8, 0, None)
        return struct.unpack("<Q", self.uc.mem_read(p, 8))[0]

    def put(self, p, x):
        self.uc.mem_write(p, struct.pack("<Q", x))

    def alloc(self, n):
        if n <= 0 or n > 1024 * 1024 or self.next + n + 32 > H + 16 * 1024 * 1024:
            raise RuntimeError("alloc budget " + str(n))
        p = self.next
        self.next += (n + 31) & ~15
        self.allocs[p] = n
        self.total += 1
        self.peak = max(self.peak, sum(self.allocs.values()))
        self.uc.mem_write(p, bytes(n))
        return p

    def free(self, p):
        if not p:
            return
        if p not in self.allocs:
            raise RuntimeError("invalid/double free " + hex(p))
        n = self.allocs.pop(p)
        self.freed.add(p)
        self.uc.mem_write(p, b"\xdd" * n)

    def ret(self, value=0):
        u = self.uc
        sp = u.reg_read(UC_X86_REG_RSP)
        u.reg_write(UC_X86_REG_RAX, value)
        u.reg_write(UC_X86_REG_RIP, self.q(sp))
        u.reg_write(UC_X86_REG_RSP, sp + 8)

    def code(self, u, a, n, data):
        self.steps += 1
        if self.steps > self.run_limit:
            raise RuntimeError("instruction budget")
        if a == END:
            u.emu_stop()
            return
        r = a - B
        c = u.reg_read(UC_X86_REG_RCX)
        d = u.reg_read(UC_X86_REG_RDX)
        e = u.reg_read(UC_X86_REG_R8)
        if r in [
            0x680D0FC,
            0x680D138,
            0x680D140,
            0x68960D0,
            0x4DF240,
            0x410C0,
            0x426B0,
            0x2BBCB0,
        ]:
            self.calls.append(hex(r))
            self.calls = self.calls[-32:]
            if r == 0x680D0FC:
                self.ret(self.alloc(c))
            elif r in [0x680D138, 0x680D140]:
                self.free(c)
                self.ret()
            elif r == 0x68960D0:
                for pointer in (c, d):
                    if H <= pointer < H + 16 * 1024 * 1024:
                        self.access(u, 0, pointer, e, 0, None)
                u.mem_write(c, bytes(u.mem_read(d, e)))
                self.ret(c)
            elif r == 0x4DF240:
                self.str(c, "00000000-0000-0000-0000-000000000002")
                self.ret(c)
            elif r == 0x410C0:
                self.ret(S + 0x1000)
            elif r == 0x426B0:
                self.put(d, S + 0x1100)
                self.put(d + 8, 0)
                self.ret(d)
            elif r == 0x2BBCB0:
                closure = u.reg_read(UC_X86_REG_R9)
                task = self.q(closure + 0x38)
                assert task in self.allocs and self.q(task) == B + 0x84ECAA8
                self.queue.append(task)
                self.put(closure + 0x38, 0)
                self.put(d, 0)
                self.put(d + 8, 0)
                self.ret(d)

    def run(self, r, *args):
        u = self.uc
        self.run_limit = self.steps + 100000
        sp = S + 1024 * 1024 - 0x108
        self.put(sp, END)
        for reg, value in zip(
            [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9], args
        ):
            u.reg_write(reg, value)
        for i, v in enumerate(args[4:]):
            self.put(sp + 40 + i * 8, v)
        u.reg_write(UC_X86_REG_RSP, sp)
        try:
            u.emu_start(B + r, END + 1, timeout=2000000, count=100000)
        except Exception:
            print("at", hex(u.reg_read(UC_X86_REG_RIP) - B), "calls", self.calls[-15:])
            raise
        if u.reg_read(UC_X86_REG_RIP) != END:
            raise RuntimeError("execution incomplete")
        return u.reg_read(UC_X86_REG_RAX)

    def str(self, p, txt, wide=False):
        raw = txt.encode("utf-16le" if wide else "utf8")
        n = len(raw) // (2 if wide else 1)
        cap = 7 if wide else 15
        if n <= cap:
            self.uc.mem_write(
                p, raw + bytes(16 - len(raw)) + struct.pack("<QQ", n, cap)
            )
        else:
            cap = n | (7 if wide else 15)
            size = (cap + 1) * (2 if wide else 1)
            if size >= 4096:
                b = self.alloc(size + 39)
                buf = (b + 39) & ~31
                self.put(buf - 8, b)
            else:
                buf = self.alloc(size)
            self.uc.mem_write(buf, raw)
            self.uc.mem_write(p, struct.pack("<QQQQ", buf, 0, n, cap))

    def release(self, control):
        count = struct.unpack("<I", self.uc.mem_read(control + 8, 4))[0]
        assert count > 0
        self.uc.mem_write(control + 8, struct.pack("<I", count - 1))
        if count == 1:
            vtable = self.q(control)
            self.run(self.q(vtable) - B, control)
            weak = struct.unpack("<I", self.uc.mem_read(control + 12, 4))[0]
            assert weak > 0
            self.uc.mem_write(control + 12, struct.pack("<I", weak - 1))
            if weak == 1:
                self.run(self.q(vtable + 8) - B, control)

    def message(
        self,
        image=False,
        counts=0x100000001,
        text="hello",
        path=r"C:\synthetic\image.png",
    ):
        p = self.alloc(0x7C0 if image else 0x758)
        self.put(p, B + (0x84F96B8 if image else 0x8279358))
        self.put(p + 8, counts)
        if not image:
            self.run(0x6B2C30, p + 16)
            self.str(p + 16 + 0xB0, "12345678901@chatroom")
            self.str(p + 16 + 0x708, text)
        else:
            self.put(p + 16, B + 0x84F9748)
            for o in [
                0x40,
                0x60,
                0x80,
                0xA0,
                0x130,
                0x170,
                0x1B8,
                0x668,
                0x688,
                0x6B0,
                0x6F0,
                0x710,
                0x738,
                0x760,
                0x780,
                0x7A0,
            ]:
                self.put(p + o, 15)
            self.put(p + 0x150, 7)
            self.str(p + 0xC0, "12345678901@chatroom")
            self.str(p + 0xF0, path, True)
            self.str(p + 0x6B8, "00000000-0000-0000-0000-000000000001")
        return p

    def submit(self, p):
        env = self.alloc(0x100)
        vec = self.alloc(16)
        self.put(vec, p + 16)
        self.put(vec + 8, p)
        self.put(env, vec)
        self.put(env + 8, vec + 16)
        self.put(env + 16, vec + 16)
        arg1 = self.alloc(320)
        self.put(arg1, B + 0x84EC9C8)
        self.put(arg1 + 8, vec)
        self.put(arg1 + 16, vec + 16)
        self.put(arg1 + 24, vec + 16)
        self.put(arg1 + 32, 1)
        nodes = [self.alloc(512) for _ in range(3)]
        scratch = self.alloc(128)
        for n, vt in zip(nodes, [0x8595F58, 0x8595E98, 0x8595DD8]):
            self.put(n, B + vt)
            self.put(n + 56, n)
        self.run(0xDF40, env + 24, *nodes, scratch, 1)
        self.run(0x1677A30, arg1, env + 24)
        self.run(0x1678000, env)
        for x in nodes + [scratch, arg1, env]:
            self.free(x)
        return self.queue.pop()

    def delete_task(self, task):
        self.run(0x1678660, task, 1)


def main():
    global pe
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--cycles", type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.cycles <= 10000:
        parser.error("cycles must be 1..10000")
    started = time.monotonic()
    pe = PE(args.native)
    checks = 0
    results = []

    def check(ok):
        nonlocal checks
        if not ok:
            raise AssertionError("check_" + str(checks + 1))
        checks += 1

    try:
        # 真实析构、复制和引用计数；最外层队列暂不消费，所有地址均为合成。
        for image in [False, True]:
            for count in [0x100000001, 0x200000006 if image else 0x200000005]:
                v = VM()
                p = v.message(image, count, "z" * 5000)
                task = v.submit(p)
                check(p in v.allocs)
                copy = v.run(0x1678180, task)
                v.delete_task(task)
                check(p in v.allocs)
                v.delete_task(copy)
                remaining = sum(v.allocs.values())
                check(bool(remaining) == (count != 0x100000001))
                results.append(
                    dict(
                        kind="image" if image else "text",
                        initial_count=hex(count),
                        remaining_allocations=len(v.allocs),
                        remaining_bytes=remaining,
                        peak_bytes=v.peak,
                    )
                )
        # 长短字符串与 MSVC 大块字符串的 4096 字节分界。
        for size in [1, 15, 16, 4094, 4095, 4096, 5000, 32768]:
            v = VM()
            p = v.message(text="x" * size)
            t = v.submit(p)
            v.delete_task(t)
            check(not v.allocs)
        v = VM()
        p = v.message(True, path="C:\\synthetic\\" + "\u56fe" * 2100 + ".png")
        t = v.submit(p)
        v.delete_task(t)
        check(not v.allocs)
        # 原生图片深复制可拥有独立路径。原消息析构不能被当成读图完成事件。
        v = VM()
        p = v.message(True)
        pair = v.alloc(16)
        v.run(0x1778170, p + 16, pair)
        cloned = v.q(pair)
        control = v.q(pair + 8)
        original_path = v.q(p + 0xF0)
        copy_path = v.q(cloned + 0xE0)
        check(
            original_path != copy_path and bytes(v.uc.mem_read(copy_path, 2)) == b"C\0"
        )
        v.release(p)
        check(p not in v.allocs and control in v.allocs and copy_path in v.allocs)
        v.release(control)
        v.free(pair)
        check(not v.allocs)
        # 在同一模拟器反复运行，回到空堆后复用地址。超过旧累计保留量，不改上限。
        v = VM()
        for i in range(args.cycles):
            if time.monotonic() - started > 150:
                raise RuntimeError("whole_probe_time_budget")
            p = v.message(bool(i % 2), text="z" * (5000 if i % 3 == 0 else 17))
            t = v.submit(p)
            clone = v.run(0x1678180, t)
            v.delete_task(t)
            check(p in v.allocs)
            v.delete_task(clone)
            check(not v.allocs)
            v.next = H
            v.freed.clear()
        report = dict(
            checks=checks,
            cycles=args.cycles,
            cycle_remaining_allocations=len(v.allocs),
            cycle_peak_parameter_bytes=v.peak,
            cycle_total_allocations=v.total,
            cases=results,
            image_original_can_die_before_clone=True,
            image_path_copy_is_independent=True,
            stubbed_functions=[
                "native_allocator",
                "native_free",
                "memcpy",
                "uuid_generator",
                "session_provider",
                "outer_queue",
            ],
            executes_actual_native_instruction_bytes=True,
            queued_task_body_executed=False,
            queue_disposal_only=True,
            private_function_exceptions_verified=False,
            callback_captures_are_empty=True,
            loads_native_module=False,
            real_image_io=False,
            production_reclamation_changed=False,
            handle_reclamation_verified=False,
            real_wechat_access=False,
            native_sha256=EXPECTED_SHA256,
            elapsed_seconds=round(time.monotonic() - started, 3),
        )
        print(json.dumps(report, indent=2))
    finally:
        pe.close()


if __name__ == "__main__":
    main()
