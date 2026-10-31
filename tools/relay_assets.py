"""附件以固定块暂存/传输；账本只保存摘要、长度和名称。"""
import hashlib
import os
from pathlib import Path
import shutil

from relay_common import DIRECTORY_MODE, MIN_FREE, validate_asset

BLOCK = 64 * 1024


def reserve(path, size):
    if shutil.disk_usage(path).free < MIN_FREE + size:
        raise ValueError("disk_reserve")


def signature(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


def snapshot(source, destination, name, expected_size=None):
    """下载中的文件等待下轮；已读对象在读取期间变化则丢弃副本。"""
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    with source.open("rb") as f:
        before = os.fstat(f.fileno())
        if expected_size is not None and before.st_size != expected_size:
            return None
        reserve(destination.parent, before.st_size)
        h, size = hashlib.sha256(), 0
        out = destination.open("xb")
        try:
            with out:
                remaining = before.st_size
                while remaining:
                    block = f.read(min(BLOCK, remaining))
                    if not block:
                        raise ValueError("source_changed")
                    reserve(destination.parent, len(block))
                    out.write(block)
                    h.update(block)
                    size += len(block)
                    remaining -= len(block)
                if f.read(1) or signature(os.fstat(f.fileno())) != signature(before) or signature(source.stat()) != signature(before):
                    raise ValueError("source_changed")
                out.flush()
                os.fsync(out.fileno())
        except Exception:
            destination.unlink(missing_ok=True)
            raise
    return validate_asset({"filename": name, "sha256": h.hexdigest(), "size": size})


def receive(stream, destination, descriptor):
    """只消费声明长度；多一个字节也拒绝，失败删除本次新建的临时文件。"""
    validate_asset(descriptor)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    reserve(destination.parent, descriptor["size"])
    h, remaining = hashlib.sha256(), descriptor["size"]
    # 已存在文件不能被失败处理误删。
    with destination.open("xb") as f:
        try:
            while remaining:
                block = stream.read(min(BLOCK, remaining))
                if not block:
                    raise ValueError("upload_truncated")
                reserve(destination.parent, len(block))
                f.write(block)
                h.update(block)
                remaining -= len(block)
            if stream.read(1) or h.hexdigest() != descriptor["sha256"]:
                raise ValueError("upload_hash_or_length_mismatch")
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            f.close()
            destination.unlink(missing_ok=True)
            raise
    return descriptor
