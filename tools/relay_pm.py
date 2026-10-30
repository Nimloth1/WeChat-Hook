"""只读跟随小麦 JSONL 的独立 PM 转发器；不改变采集水位或其他渠道。"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import time
import tempfile
import ctypes

from relay_common import (MAX_WIRE, Store, assets, asset_path, canonical, digest, file_hash,
                          make_job, validate_job, validate_policy)
from relay_assets import BLOCK, reserve, signature, snapshot

MAX_LINE = 1024 * 1024
STOP = False


def policy_scope(policy):
    return digest({**policy, "enabled": True})


def anchor(f, offset):
    f.seek(max(0, offset - 256))
    return hashlib.sha256(f.read(min(offset, 256))).hexdigest()


class Tail:
    def __init__(self, path, store, policy):
        self.path, self.store = Path(path), store
        self.policy = validate_policy(policy)

    def baseline(self):
        """只允许首次在当前完整行末建立基线；不能用它清除旧记录。"""
        if self.store.get("cursor") is not None:
            raise ValueError("baseline_already_exists")
        with self.path.open("rb") as f:
            st = os.fstat(f.fileno())
            if st.st_size:
                f.seek(-1, 2)
                if f.read(1) != b"\n":
                    raise ValueError("source_partial_line_at_baseline")
            cursor = {"dev": st.st_dev, "ino": st.st_ino, "offset": st.st_size,
                      "anchor": anchor(f, st.st_size)}
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM meta WHERE key='cursor'").fetchone():
                raise ValueError("baseline_already_exists")
            self.store.put(db, "cursor", cursor)
            self.store.put(db, "policy_scope", policy_scope(self.policy))
            self.store.put(db, "activated_at", time.time())
        return cursor

    def classify(self, event):
        if not isinstance(event, dict):
            raise ValueError("source_event_not_object")
        if (event.get("conversation_id") != self.policy["source"] or event.get("is_self")
                or not event.get("is_chatroom")
                or event.get("sender_corp") not in self.policy["corporations"]):
            return None, "scope"
        ts = event.get("ts")
        if type(ts) not in (float, int) or not math.isfinite(ts):
            raise ValueError("invalid_source_time")
        # JSONL 发生采集补录时，也不能把基线前的旧消息当新消息发出去。
        if ts < self.store.get("activated_at") or not 0 <= time.time() - ts <= 86400:
            return None, "old_or_future"
        if type(event.get("type")) is not int:
            raise ValueError("invalid_source_type")
        base = event["type"] & 0xFFFFFFFF
        if base == 1:
            text = str(event.get("content") or "")
            sender = str(event.get("sender") or "")
            corp = "gtja sg" if event["sender_corp"].startswith("GUOTAI ") else "gtja"
            text = f"{sender}@{corp}：{text}"
            return make_job(event, self.policy, "text", {"text": text}), "job"
        sub = event["type"] >> 32
        if base == 49 and sub in {1, 4, 5, 68}:
            # 小麦现有 JSONL 仅保留渲染标题和最后一行 URL；不反查聊天库。
            content = str(event.get("content") or "")
            title, separator, url = content.rpartition("\n")
            title = re.sub(r"^\[(链接|文章|应用消息)\]\s*", "", title)
            if not separator:
                raise ValueError("source_link_missing_url")
            return make_job(event, self.policy, "link", {
                "title": title, "description": "", "url": url}), "job"
        if base == 3 and re.fullmatch(r"[0-9a-f]{32}", str(event.get("image_md5") or "")):
            kind = "image"
        elif base == 49 and event.get("file") and not event.get("video"):
            spec = event["file"]
            if (not isinstance(spec, dict) or type(spec.get("size")) is not int
                    or spec["size"] <= 0 or not isinstance(spec.get("name"), str)):
                raise ValueError("invalid_file_spec")
            kind = "file"
        elif base == 43 and event.get("video"):
            spec = event["video"]
            if (not isinstance(spec, dict) or not re.fullmatch(r"[0-9a-f]{32}", str(spec.get("md5", "")))
                    or type(spec.get("size")) is not int or spec["size"] <= 0):
                raise ValueError("invalid_video_spec")
            kind = "video"
        else:
            return None, "unsupported_type"
        # 仅存附件定位所需元数据，不复制完整聊天正文。
        small = {k: event.get(k) for k in ("conversation_id", "sender_corp", "server_id",
                                          "local_id", "ts", "image_md5", "file", "video")}
        message_id = str(event.get("server_id") or event.get("local_id") or "")
        if not message_id:
            raise ValueError("source_missing_id")
        return {"id": digest(["pm-vw12-relay-v1", self.policy["recipient"], self.policy["source"],
                              message_id, kind]), "kind": kind, "event": small}, "media"

    def poll(self, limit=50):
        cursor = self.store.get("cursor")
        if not cursor or self.store.get("policy_scope") != policy_scope(self.policy):
            raise ValueError("baseline_or_policy_mismatch")
        processed = 0
        with self.path.open("rb") as f:
            st = os.fstat(f.fileno())
            if ((st.st_dev, st.st_ino) != (cursor["dev"], cursor["ino"])
                    or st.st_size < cursor["offset"] or anchor(f, cursor["offset"]) != cursor["anchor"]):
                raise ValueError("source_rotated_or_rewritten")
            f.seek(cursor["offset"])
            for _ in range(limit):
                raw = f.readline(MAX_LINE + 1)
                if len(raw) > MAX_LINE:
                    raise ValueError("source_line_limit")
                if not raw.endswith(b"\n"):
                    break  # 未写完的一行不消耗偏移。
                end = f.tell()
                item, kind = self.classify(json.loads(raw))
                updated = {**cursor, "offset": end, "anchor": anchor(f, end)}
                f.seek(end)
                with self.store.connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    if kind == "job":
                        self.store.add(db, item)
                    elif kind == "media":
                        payload = canonical(item)
                        old = db.execute("SELECT payload FROM media WHERE id=?", (item["id"],)).fetchone()
                        if old and old[0] != payload:
                            raise ValueError("media_event_conflict")
                        if not old:
                            count = db.execute("SELECT count(*) FROM media").fetchone()[0]
                            if count >= 50000:
                                raise ValueError("media_index_capacity")
                            db.execute("INSERT INTO media VALUES(?,?,'waiting',?)",
                                       (item["id"], payload, time.time()))
                    self.store.put(db, "cursor", updated)
                cursor = updated
                processed += 1
        return processed


def resolve_media(store, policy, decoder):
    with store.connect() as db:
        after = store.media_scan_after
        rows = db.execute("SELECT rowid,id,payload FROM media WHERE state='waiting' AND rowid>? "
                          "ORDER BY rowid LIMIT 10", (after,)).fetchall()
        if len(rows) < 10:
            rows += db.execute("SELECT rowid,id,payload FROM media WHERE state='waiting' AND rowid<=? "
                               "ORDER BY rowid LIMIT ?", (after, 10 - len(rows))).fetchall()
    for rowid, key, payload in rows:
        store.media_scan_after = rowid
        item = json.loads(payload)
        event = item["event"]
        if time.time() - event["ts"] > 86400:
            raise ValueError("attachment_expired_requires_review")
        path = asset_path(store.root, key, "media")
        if item["kind"] == "image":
            loaded = decoder.image(event["conversation_id"], event["image_md5"], path)
        elif item["kind"] == "video":
            loaded = decoder.video(event["video"], path, asset_path(store.root, key, "thumbnail"))
        else:
            spec = event["file"]
            loaded = decoder.file(spec["name"], spec["size"], path)
        if loaded is None:
            continue
        job = make_job(event, policy, item["kind"], loaded)
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            store.add(db, job)
            db.execute("UPDATE media SET state='ready' WHERE id=? AND state='waiting'", (key,))

def media_tool(command, timeout, root):
    """只监控自建的媒体子进程；不观察或结束微信进程。"""
    if sys.platform != "darwin":
        raise ValueError("media_tools_require_PM")
    from ctypes import c_uint8, c_uint64, Structure
    class Usage(Structure):
        _fields_ = [("uuid", c_uint8 * 16)] + [(k, c_uint64) for k in (
            "utime", "stime", "wakeups", "interrupts", "pageins", "wired", "resident", "footprint",
            "start", "exit", "child_utime", "child_stime", "child_wakeups", "child_interrupts",
            "child_pageins", "child_elapsed", "reads", "writes")]
    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    with tempfile.TemporaryFile(dir=root) as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                usage = Usage()
                measured = lib.proc_pid_rusage(process.pid, 2, ctypes.byref(usage)) == 0
                if ((measured and usage.resident > 512 * 1024 * 1024)
                        or output.tell() > 4096 or time.monotonic() >= deadline):
                    raise ValueError("media_tool_resource_budget")
                time.sleep(0.05)
            output.seek(0)
            raw = output.read(4097)
            if process.returncode or len(raw) > 4096:
                raise ValueError("media_tool_failed")
            return raw
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()


class Decoder:
    def __init__(self, cfg):
        sys.path.insert(0, cfg["xiaomai_root"])
        from app.ingest.image import ImageDecoder
        from Crypto.Cipher import AES
        self.decoder = ImageDecoder(cfg["account_dir"])
        self.aes = AES
        self.ffmpeg = cfg.get("ffmpeg", "/opt/homebrew/bin/ffmpeg")
        self.ffprobe = cfg.get("ffprobe", "/opt/homebrew/bin/ffprobe")

    def decode(self, path, destination):
        from PIL import Image
        with Path(path).open("rb") as f:
            before = os.fstat(f.fileno())
            header = f.read(31)
            if len(header) < 31 or not header.startswith(b"\x07\x08V2\x08\x07"):
                return None
            aes_size, xor_size = struct.unpack("<II", header[6:14])
            padded = aes_size + 16 - aes_size % 16
            if 15 + padded + xor_size > before.st_size:
                return None
            for _ in range(2):
                if self.decoder._key is None:
                    self.decoder._key = self.decoder._derive(header)
                    if self.decoder._key is None:
                        return None
                key, xor = self.decoder._key
                cipher = self.aes.new(key, self.aes.MODE_ECB)
                head = cipher.decrypt(header[15:31])
                if head.startswith((b"\xff\xd8\xff", b"\x89PNG")):
                    break
                self.decoder._key = None
            else:
                return None
            reserve(destination.parent, before.st_size)
            with destination.open("xb") as out:
                f.seek(15)
                remaining = padded
                while remaining:
                    block = f.read(min(BLOCK, remaining))
                    if not block or len(block) % 16:
                        raise ValueError("image_source_changed")
                    plain = cipher.decrypt(block)
                    remaining -= len(block)
                    if not remaining:
                        pad = plain[-1]
                        if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                            raise ValueError("image_padding_invalid")
                        plain = plain[:-pad]
                    reserve(destination.parent, len(plain))
                    out.write(plain)
                middle = before.st_size - 15 - padded - xor_size
                for size, encrypted in ((middle, False), (xor_size, True)):
                    while size:
                        block = f.read(min(BLOCK, size))
                        if not block:
                            raise ValueError("image_source_changed")
                        reserve(destination.parent, len(block))
                        out.write(bytes(x ^ xor for x in block) if encrypted else block)
                        size -= len(block)
                if f.read(1) or signature(os.fstat(f.fileno())) != signature(before) or signature(Path(path).stat()) != signature(before):
                    raise ValueError("image_source_changed")
                out.flush()
                os.fsync(out.fileno())
        with Image.open(destination) as image:
            width, height = image.size
            extension = ".png" if image.format == "PNG" else ".jpg"
        return {"filename": Path(path).stem + extension, "size": destination.stat().st_size,
                "sha256": file_hash(destination)}, (width * height, destination.stat().st_size)

    def image(self, conversation, md5, destination):
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists():
            raise ValueError("unresolved_spool")
        best, score = None, (0, 0)
        for path in self.decoder.find(conversation, md5):
            candidate = destination.with_suffix(".candidate")
            try:
                result = self.decode(path, candidate)
                if result and result[1] > score:
                    best, score = result
                    os.replace(candidate, destination)
            finally:
                candidate.unlink(missing_ok=True)
        return best

    def file(self, name, size, destination):
        base = Path(self.decoder.account_dir) / "msg" / "file"
        stem, dot, ext = name.rpartition(".")
        if not dot:
            stem, ext = name, ""
        if not base.exists():
            return None
        for month in sorted(base.iterdir(), reverse=True):
            if not month.is_dir():
                continue
            for path in month.iterdir():
                if path.name != name and not re.fullmatch(
                        re.escape(stem) + r"\(\d+\)" + re.escape(dot + ext), path.name):
                    continue
                if path.is_file() and path.stat().st_size == size:
                    result = snapshot(path, destination, name, size)
                    if result:
                        return result
        return None

    def video(self, spec, destination, thumbnail):
        base = Path(self.decoder.account_dir) / "msg" / "video"
        for path in sorted(base.glob("*/" + spec["md5"] + ".mp4"), reverse=True):
            if path.stat().st_size != spec["size"]:
                continue
            media = snapshot(path, destination, spec["md5"] + ".mp4", spec["size"])
            if media is None:
                continue
            with destination.open("rb") as f:
                if f.read(8)[4:8] != b"ftyp":
                    raise ValueError("video_not_mp4")
            # 仅处理稳定副本；只启用本地 file/pipe 协议，不下载、不转码源视频。
            common = ["-v", "error", "-max_alloc", "67108864", "-protocol_whitelist", "file,pipe"]
            raw = media_tool([self.ffprobe, *common, "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1", str(destination)], 30, destination.parent)
            seconds = float(raw.strip())
            if not math.isfinite(seconds) or not 0 < seconds <= 86400:
                raise ValueError("video_duration_invalid")
            reserve(thumbnail.parent, 16 * 1024 * 1024)
            media_tool([self.ffmpeg, *common, "-nostdin", "-threads", "1",
                "-i", str(destination), "-map", "0:v:0", "-frames:v", "1",
                "-vf", "scale=640:640:force_original_aspect_ratio=decrease", "-threads", "1",
                "-c:v", "mjpeg", "-f", "image2", "-n", str(thumbnail)], 60, destination.parent)
            if not thumbnail.is_file():
                raise ValueError("video_thumbnail_failed")
            return {"media": media, "thumbnail": {"filename": "cover.jpg",
                "size": thumbnail.stat().st_size, "sha256": file_hash(thumbnail)},
                "duration_seconds": math.ceil(seconds)}
        return None


class Transport:
    def __init__(self, cfg):
        self.root = Path(cfg["state_dir"])
        def literal(x):
            if not isinstance(x, str) or any(c in x for c in "\x00\r\n"):
                raise ValueError("invalid_remote_path")
            return "'" + x.replace("'", "''") + "'"
        script = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
                  "if($env:COMPUTERNAME -ne 'VW12'){throw 'wrong_guest'};"
                  "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
                  "& " + literal(cfg["guest_python"]) + " -B " + literal(cfg["guest_script"])
                  + " --config " + literal(cfg["guest_config"]) + ";exit $LASTEXITCODE")
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        self.command = ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                        "VW12", "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]

    def control(self, request):
        raw = (canonical(request) + "\n").encode()
        if len(raw) > MAX_WIRE:
            raise ValueError("control_memory_budget")
        r = subprocess.run(self.command, input=raw, capture_output=True, timeout=90)
        return self.response(r.returncode, r.stdout)

    @staticmethod
    def response(code, raw):
        if code or len(raw) > 16384:
            raise ValueError("ssh_request_unknown_no_retry")
        response = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise ValueError("guest_rejected_no_retry")
        return response

    def upload(self, request, role, descriptor):
        path = asset_path(self.root, request["job"]["id"], role)
        header = {"operation": "upload", "policy_sha256": request["policy_sha256"],
                  "job": request["job"], "role": role}
        # 文件输入重定向避免 Python/ssh 管道互等；控制帧加文件流写入临时 wire 文件。
        # 没有整块 base64，没有随文件大小增长的内存缓冲。
        reserve(self.root, descriptor["size"])
        with tempfile.TemporaryFile(dir=self.root) as wire:
            wire.write((canonical(header) + "\n").encode())
            with path.open("rb") as f:
                before = os.fstat(f.fileno())
                if before.st_size != descriptor["size"]:
                    raise ValueError("spool_size_changed")
                h = hashlib.sha256()
                for block in iter(lambda: f.read(BLOCK), b""):
                    reserve(self.root, len(block))
                    wire.write(block)
                    h.update(block)
                if signature(os.fstat(f.fileno())) != signature(before) or h.hexdigest() != descriptor["sha256"]:
                    raise ValueError("spool_changed")
            wire.seek(0)
            # 大文件传输仅受实际超时约束；失败后不再进入 dispatch、不自动重传。
            r = subprocess.run(self.command, stdin=wire, capture_output=True, timeout=900)
            result = self.response(r.returncode, r.stdout)
        if result.get("uploaded") != descriptor["sha256"]:
            raise ValueError("upload_receipt_mismatch")

    def request(self, request):
        if request.get("operation") == "dispatch":
            for role, descriptor in assets(request["job"]).items():
                self.upload(request, role, descriptor)
        return self.control(request)


def dispatch_once(store, policy, transport):
    if not policy["enabled"] or store.get("paused"):
        return False
    job = store.next_job()
    if job is None:
        return False
    validate_job(job, policy)
    if not 0 <= time.time() - job["source_ts"] <= 86400:
        raise ValueError("pending_job_expired")
    if not store.claim(job, policy):
        return False
    try:
        result = transport.request({"operation": "dispatch", "policy_sha256": digest(policy), "job": job})
        receipt = result.get("receipt", {})
        if (receipt.get("id") != job["id"] or receipt.get("digest") != digest(job)
                or receipt.get("state") != "submitted_unconfirmed"
                or receipt.get("delivery_confirmed") is not False or result.get("replayed") is not False
                or result.get("post_attempts") != 1):
            raise ValueError("remote_result_requires_review")
        store.finish(job["id"], "submitted_unconfirmed", receipt["evidence"])
    except Exception:
        store.finish(job["id"], "review_required", {"error": "remote_result_unknown", "no_retry": True})
        store.pause("remote_result_unknown")
        raise
    # 回执已持久记录；本地清理失败也不能改写成未知发送或重试。
    for role in assets(job):
        asset_path(store.root, job["id"], role).unlink()
    if assets(job):
        asset_path(store.root, job["id"], "media").parent.rmdir()
    return True


def notify_pause(store):
    reason = store.get("paused")
    if not reason or store.get("pause_alerted") == reason:
        return
    try:
        result = subprocess.run(["/opt/homebrew/bin/python3",
            str(Path.home() / ".local/bin/bark-notify.py"),
            "--title", "VW12 自动转发已暂停", "--body",
            "存在未决发送或执行异常，后续消息已暂停且不会自动重发。请检查转发账本。",
            "--group", "xiaomai", "--level", "active"], capture_output=True, timeout=15)
        sent = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        sent = False
    # 通知失败也只记录一次；持久暂停状态仍由 Healthchecks 探针报警。
    with store.connect() as db:
        store.put(db, "pause_alerted", reason)
        store.put(db, "pause_alert_request_ok", sent)


def run(cfg, store, config_path):
    global STOP
    import fcntl
    policy = validate_policy(cfg["policy"])
    if not policy["enabled"]:
        raise ValueError("automatic_policy_disabled")
    if sys.platform != "darwin":
        raise ValueError("expected_PM_macOS")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: globals().__setitem__("STOP", True))
    with (store.root / "collector.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        tail = Tail(cfg["archive"], store, policy)
        decoder, transport = Decoder(cfg), Transport(cfg)
        if store.get("cursor") is None:
            raise ValueError("explicit_baseline_required")
        with store.connect() as db:
            unresolved = db.execute("SELECT 1 FROM jobs WHERE state IN ('dispatching','review_required') LIMIT 1").fetchone()
        if unresolved:
            store.pause("prior_unknown_attempt")
        while not STOP:
            if store.get("paused"):
                notify_pause(store)
                # 保持暂停，不由 KeepAlive 自动恢复；探针从账本报告失败。
                time.sleep(5)
                continue
            try:
                # 运行中改配置只会暂停，绝不扩大范围；无需重启微信即可停用。
                if json.loads(config_path.read_text(encoding="utf-8")) != cfg:
                    raise ValueError("configuration_changed_pause")
                tail.poll()
                resolve_media(store, policy, decoder)
                if dispatch_once(store, policy, transport):
                    print(canonical({"event": "submitted_unconfirmed", "delivery_confirmed": False}), flush=True)
                    continue
            except Exception as exc:
                store.pause("relay_error_" + type(exc).__name__)
                print(canonical({"event": "paused", "error_type": type(exc).__name__, "no_retry": True}), flush=True)
            time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["baseline", "status", "pause", "run"])
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    validate_policy(cfg["policy"])
    store = Store(cfg["state_dir"])
    if args.command == "baseline":
        # 正式启用的一刻显式执行，不在代码开发/预览阶段保存生产水位。
        print(canonical({"cursor": Tail(cfg["archive"], store, cfg["policy"]).baseline(), "history_sent": 0}))
    elif args.command == "status":
        print(canonical(store.status()))
        return 1 if store.get("paused") else 0
    elif args.command == "pause":
        store.pause("manual_pause")
        print(canonical({"paused": True, "inflight_call_cannot_be_recalled": True}))
    else:
        run(cfg, store, args.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
