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

from relay_common import (MAX_MEDIA, MAX_WIRE, Store, canonical, digest,
                          make_job, validate_job, validate_policy)

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
            if len(text.encode("utf-16le")) // 2 <= 2000:
                return make_job(event, self.policy, "text", {"text": text}), "job"
            data = text.encode()
            if len(data) > MAX_MEDIA:
                raise ValueError("long_text_too_large")
            payload = {"filename": "原文.txt", "sha256": hashlib.sha256(data).hexdigest(),
                       "data_b64": base64.b64encode(data).decode()}
            return make_job(event, self.policy, "file", payload), "job"
        if base == 3 and re.fullmatch(r"[0-9a-f]{32}", str(event.get("image_md5") or "")):
            kind = "image"
        elif base == 49 and event.get("file") and not event.get("video"):
            spec = event["file"]
            if (not isinstance(spec, dict) or type(spec.get("size")) is not int
                    or not 0 < spec["size"] <= MAX_MEDIA or not isinstance(spec.get("name"), str)):
                raise ValueError("invalid_file_spec")
            kind = "file"
        else:
            return None, "unsupported_type"
        # 仅存附件定位所需元数据，不复制完整聊天正文。
        small = {k: event.get(k) for k in ("conversation_id", "sender_corp", "server_id",
                                          "local_id", "ts", "image_md5", "file")}
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
        if item["kind"] == "image":
            loaded = decoder.image(event["conversation_id"], event["image_md5"])
        else:
            spec = event["file"]
            loaded = decoder.file(spec["name"], spec["size"])
        if loaded is None:
            continue
        data, name = loaded
        if not data or len(data) > MAX_MEDIA:
            raise ValueError("attachment_size_limit")
        media = {"filename": name, "sha256": hashlib.sha256(data).hexdigest(),
                 "data_b64": base64.b64encode(data).decode()}
        job = make_job(event, policy, item["kind"], media)
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            store.add(db, job)
            db.execute("UPDATE media SET state='ready' WHERE id=? AND state='waiting'", (key,))


class Decoder:
    def __init__(self, cfg):
        sys.path.insert(0, cfg["xiaomai_root"])
        from app.ingest.image import ImageDecoder, image_size
        from Crypto.Cipher import AES
        self.decoder = ImageDecoder(cfg["account_dir"])
        self.image_size = image_size
        self.aes = AES

    @staticmethod
    def read_bounded(path):
        with Path(path).open("rb") as f:
            data = f.read(MAX_MEDIA + 1)
        if len(data) > MAX_MEDIA:
            raise ValueError("source_media_size_limit")
        return data

    def decode(self, path):
        # 小麦相同的 V2 解码步骤/缓存密钥推导，区别仅在于输入是有界读取。
        # 不调用原 decode(path) 的无限制 read，以免客户端并发增长越过预算。
        data = self.read_bounded(path)
        if not data.startswith(b"\x07\x08V2\x08\x07") or len(data) < 31:
            return None
        aes_size, xor_size = struct.unpack("<II", data[6:14])
        body = data[15:]
        padded = aes_size + 16 - aes_size % 16
        if padded + xor_size > len(body):
            return None
        for _ in range(2):
            if self.decoder._key is None:
                self.decoder._key = self.decoder._derive(data)
                if self.decoder._key is None:
                    return None
            key, xor = self.decoder._key
            head = self.aes.new(key, self.aes.MODE_ECB).decrypt(body[:padded])
            if head.startswith((b"\xff\xd8\xff", b"\x89PNG")):
                break
            self.decoder._key = None
        else:
            return None
        head = head[:-head[-1]]
        mid = body[padded:len(body) - xor_size]
        tail = bytes(b ^ xor for b in body[len(body) - xor_size:])
        return head + mid + tail

    def image(self, conversation, md5):
        best, score = None, (0, 0)
        for path in self.decoder.find(conversation, md5):
            p = Path(path)
            # 原解码器整文件读取，因此先限制输入文件，而不只限制输出。
            if p.stat().st_size > MAX_MEDIA:
                raise ValueError("encrypted_image_size_limit")
            data = self.decode(path)
            if not data:
                continue
            if len(data) > MAX_MEDIA:
                raise ValueError("decoded_image_size_limit")
            width, height = self.image_size(data)
            current = (width * height, len(data))
            if current > score:
                score = current
                best = data, md5 + (".png" if data.startswith(b"\x89PNG") else ".jpg")
        return best

    def file(self, name, size):
        # 沿用小麦的名称/重名后缀/大小规则，但不能无限制整文件读取。
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
                if not path.is_file() or path.stat().st_size != size:
                    continue
                data = self.read_bounded(path)
                if len(data) == size:
                    return data, name
        return None


class Transport:
    def __init__(self, cfg):
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

    def request(self, request):
        raw = canonical(request).encode()
        if len(raw) > MAX_WIRE:
            raise ValueError("wire_limit")
        r = subprocess.run(self.command, input=raw, capture_output=True, timeout=90)
        if r.returncode or len(r.stdout) > 16384:
            raise ValueError("ssh_request_unknown_no_retry")
        response = json.loads(r.stdout.decode("utf-8-sig"))
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise ValueError("guest_rejected_no_retry")
        return response


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
        return True
    except Exception:
        store.finish(job["id"], "review_required", {"error": "remote_result_unknown", "no_retry": True})
        store.pause("remote_result_unknown")
        raise


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
