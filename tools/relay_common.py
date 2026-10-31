"""PM → VW12 自动转发的离线协议和持久账本；不包含微信调用。"""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time

MAX_PENDING = 100 * 1024 * 1024
MIN_FREE = 1024 * 1024 * 1024
MAX_WIRE = 16 * 1024 * 1024  # 控制帧内存预算；附件不再进入 JSON/base64。
KINDS = {"text", "image", "file", "video", "link"}
SOURCE_MODULE = "f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36"
HOOK_MODULE = "eabf566a4dc063267b1773ab7e72fa0a606a7a76983fca3daaceb5fd14741ecf"

# Windows 3.13 的0700按令牌默认owner生成独立DACL；高权限SSH的owner可能是
# Administrators，桌面同一用户因此不可读。Windows继承预配置私有根的DACL，
# 不授予Everyone；POSIX仍使用0700。文件同卷rename会保留原ACL，须在创建时正确继承。
DIRECTORY_MODE = 0o777 if os.name == "nt" else 0o700

# 只记录 DLL 定义的固定码；不能把任意错误原文、路径或 token 写进账本。
HOOK_ERROR_CODES = frozenset("""
approval_required send_in_progress_no_new_attempt authorization_failed invalid_request
one_shot_already_used request_not_approved allocation_failed
native_retention_budget_exceeded native_ownership_fault_requires_investigation native_collector_start_failed
native_ownership_module_not_supported wechat_module_missing module_path_failed wechat_module_hash_mismatch
module_version_failed wechat_version_not_4_1_10_27 module_header_failed module_architecture_failed
function_address_not_executable data_address_not_readable send_context_unavailable
image_requires_local_absolute_path image_path_not_stable image_file_invalid image_header_invalid
image_format_unsupported image_hash_mismatch file_size_invalid file_read_failed file_changed hash_failed
guid_failed attachment_hash_mismatch attachment_name_invalid attachment_requires_local_absolute_path
attachment_path_not_stable attachment_file_invalid video_format_unsupported native_preflight_failed
durable_approval_consume_failed native_result_not_delivery_receipt native_exception_no_retry
native_ownership_fault_no_retry native_frame_allocation_failed_no_retry video_constructor_fault_no_retry
video_constructor_layout_unknown_no_retry link_constructor_fault_no_retry link_constructor_layout_unknown_no_retry
file_constructor_fault_no_retry file_constructor_layout_unknown_no_retry text_constructor_fault_no_retry
text_constructor_layout_unknown_no_retry ownership_observer_failed_no_retry parameter_constructor_fault_no_retry
submit_fault_no_retry source_destructor_fault_no_retry native_temporary_free_fault_no_retry
handler_exception_no_retry unrecognized_hook_error
""".split())


def hook_error_code(value):
    if value is None or value == "":
        return None
    return value if isinstance(value, str) and value in HOOK_ERROR_CODES else "unrecognized_hook_error"


def dispatch_diagnostics(evidence):
    """仅从关联正确的来宾回执保留有界执行证据，不复制任意远端字段。"""
    if not isinstance(evidence, dict):
        return {}
    result = {}
    for key in ("native_entered", "replayed"):
        if type(evidence.get(key)) is bool:
            result[key] = evidence[key]
    for key, low, high in (("http_status", 100, 599), ("post_attempts", 0, 1)):
        if type(evidence.get(key)) is int and low <= evidence[key] <= high:
            result[key] = evidence[key]
    if evidence.get("response_state") in ("not_attempted", "unconfirmed", "unknown"):
        result["response_state"] = evidence["response_state"]
    code = hook_error_code(evidence.get("hook_error"))
    if code:
        result["hook_error"] = code
    return result


def canonical(value):
    # 控制协议固定ASCII JSON；原生许可另用既有UTF-8摘要格式。
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def native_fingerprint(value):
    # C++ 原生许可沿用已有 UTF-8/nlohmann::json 格式，不能随中转协议改变。
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def validate_asset(payload):
    if not isinstance(payload, dict) or set(payload) != {"filename", "sha256", "size"}:
        raise ValueError("invalid_asset")
    name = payload["filename"]
    if (not isinstance(name, str) or not name or len(name) > 180
            or re.search(r'[<>:"/\\|?*\x00-\x1f]', name)
            or name.endswith((".", " ")) or name.split(".")[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}):
        raise ValueError("invalid_filename")
    if (type(payload["size"]) is not int or not 0 < payload["size"] < 2**63
            or not re.fullmatch(r"[0-9a-f]{64}", str(payload["sha256"]))):
        raise ValueError("invalid_asset_metadata")
    return payload


def assets(job):
    if job["kind"] in {"text", "link"}:
        return {}
    if job["kind"] == "video":
        return {key: job["payload"][key] for key in ("media", "thumbnail")}
    return {"media": job["payload"]}


def asset_path(root, job_id, role):
    if not re.fullmatch(r"[0-9a-f]{64}", job_id) or role not in {"media", "thumbnail"}:
        raise ValueError("invalid_asset_key")
    return Path(root) / "spool" / job_id / (role + ".bin")


def validate_link(payload):
    from urllib.parse import urlsplit
    if not isinstance(payload, dict) or set(payload) != {"title", "description", "url"}:
        raise ValueError("invalid_link")
    title, description, url = (payload[k] for k in ("title", "description", "url"))
    if (any(not isinstance(x, str) for x in (title, description, url))
            or not title.strip() or len(title.encode("utf-16le")) // 2 > 256
            or len(description.encode("utf-16le")) // 2 > 2000
            or len(url.encode("utf-16le")) // 2 > 2048
            or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in title + description)
            or not url.startswith(("http://", "https://"))
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)):
        raise ValueError("invalid_link_fields")
    authority = urlsplit(url).netloc
    if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", authority):
        raise ValueError("invalid_link_url")
    host, _, port = authority.partition(":")
    if host.startswith(".") or host.endswith(".") or ".." in host or port and not 1 <= int(port) <= 65535:
        raise ValueError("invalid_link_url")
    return payload


def validate_policy(policy):
    if (not isinstance(policy, dict) or policy.get("version") != 2
            or set(policy) != {"version", "enabled", "recipient", "source", "corporations"}
            or type(policy.get("enabled")) is not bool):
        raise ValueError("invalid_policy")
    for key in ("recipient", "source"):
        if not re.fullmatch(r"[0-9]{1,32}@chatroom", str(policy.get(key, ""))):
            raise ValueError("invalid_group_policy")
    if policy["source"] == policy["recipient"]:
        raise ValueError("source_recipient_loop")
    if (not isinstance(policy.get("corporations"), list) or not policy["corporations"]
            or any(not isinstance(x, str) or not x for x in policy["corporations"])):
        raise ValueError("missing_corporation_allowlist")
    return policy


def validate_job(job, policy):
    validate_policy(policy)
    if (not isinstance(job, dict) or set(job) != {
            "id", "recipient", "source", "message_id", "kind", "source_ts", "corporation", "payload"}
            or job["recipient"] != policy["recipient"] or job["source"] != policy["source"]
            or job["kind"] not in KINDS or type(job["source_ts"]) not in (int, float)
            or not math.isfinite(job["source_ts"]) or job["corporation"] not in policy["corporations"]
            or not isinstance(job["message_id"], str) or not job["message_id"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(job["id"]))):
        raise ValueError("invalid_job")
    expected = digest(["pm-vw12-relay-v1", job["recipient"], job["source"],
                       job["message_id"], job["kind"]])
    if job["id"] != expected:
        raise ValueError("job_id_mismatch")
    payload = job["payload"]
    if job["kind"] == "text":
        if (not isinstance(payload, dict) or set(payload) != {"text"}
                or not isinstance(payload["text"], str) or "\x00" in payload["text"]
                or not payload["text"].strip()):
            raise ValueError("invalid_text")
    elif job["kind"] == "link":
        validate_link(payload)
    elif job["kind"] == "video":
        if (not isinstance(payload, dict) or set(payload) != {"media", "thumbnail", "duration_seconds"}
                or type(payload["duration_seconds"]) is not int
                or not 1 <= payload["duration_seconds"] <= 86400):
            raise ValueError("invalid_video")
        validate_asset(payload["media"])
        validate_asset(payload["thumbnail"])
        if (not payload["media"]["filename"].endswith(".mp4")
                or not payload["thumbnail"]["filename"].endswith(".jpg")):
            raise ValueError("invalid_video_format")
    else:
        validate_asset(payload)
    return job


def make_job(event, policy, kind, payload):
    message_id = str(event.get("server_id") or event.get("local_id") or "")
    job = {"id": digest(["pm-vw12-relay-v1", policy["recipient"], policy["source"], message_id, kind]),
           "recipient": policy["recipient"], "source": policy["source"],
           "message_id": message_id, "kind": kind, "source_ts": event["ts"],
           "corporation": event["sender_corp"], "payload": payload}
    return validate_job(job, policy)


class Store:
    """SQLite FULL 同步；无变化不 UPDATE，不把 HTTP202 当作送达。"""
    def __init__(self, root):
        self.root = Path(root)
        # 附件轮询只在内存中记游标；空轮询不为调度位置写盘。
        self.media_scan_after = 0
        self.root.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
        self.path = self.root / "relay.sqlite"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(
                  id TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,
                  evidence TEXT NOT NULL,created REAL NOT NULL,
                  attempt REAL,completed REAL,media_bytes INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state,created);
                CREATE TABLE IF NOT EXISTS payloads(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS media(
                  id TEXT PRIMARY KEY,payload TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, key, default=None):
        with self.connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    @staticmethod
    def put(db, key, value):
        value = canonical(value)
        db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value "
                   "WHERE meta.value<>excluded.value", (key, value))

    def pause(self, reason):
        with self.connect() as db:
            self.put(db, "paused", reason)

    def status(self):
        with self.connect() as db:
            counts = dict(db.execute("SELECT state,count(*) FROM jobs GROUP BY state"))
        return {"counts": counts, "paused": self.get("paused"), "delivery_confirmed": False}

    def add(self, db, job, state="ready"):
        payload = canonical(job)
        fingerprint = hashlib.sha256(payload.encode()).hexdigest()
        old = db.execute("SELECT digest FROM jobs WHERE id=?", (job["id"],)).fetchone()
        if old:
            if old[0] != fingerprint:
                raise ValueError("job_conflict")
            return False
        used = db.execute("SELECT coalesce(sum(length(CAST(payload AS BLOB))),0) FROM payloads").fetchone()[0]
        if used + len(payload.encode()) > MAX_PENDING or self.path.stat().st_size > MAX_PENDING * 2:
            raise ValueError("queue_capacity")
        if shutil.disk_usage(self.root).free < MIN_FREE + len(payload.encode()) * 3:
            raise ValueError("disk_reserve")
        media = sum(x["size"] for x in assets(job).values())
        metadata = {k: job[k] for k in ("id", "recipient", "source", "message_id", "source_ts", "kind")}
        db.execute("INSERT INTO jobs(id,digest,state,evidence,created,media_bytes) "
                   "VALUES(?,?,?,?,?,?)", (job["id"], fingerprint, state, canonical(metadata), time.time(), media))
        db.execute("INSERT INTO payloads VALUES(?,?)", (job["id"], payload))
        return True

    def accept(self, job):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return self.add(db, job)

    def next_job(self):
        with self.connect() as db:
            row = db.execute("SELECT p.payload FROM jobs j JOIN payloads p ON p.id=j.id "
                             "WHERE j.state='ready' ORDER BY j.created,j.rowid LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def claim(self, job, policy, now=None):
        now = time.time() if now is None else now
        if self.get("paused"):
            return False
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM meta WHERE key='paused'").fetchone():
                return False
            if db.execute("SELECT 1 FROM jobs WHERE state IN ('dispatching','review_required') LIMIT 1").fetchone():
                raise ValueError("unresolved_attempt")
            return db.execute("UPDATE jobs SET state='dispatching',attempt=? WHERE id=? AND state='ready'",
                              (now, job["id"])).rowcount == 1

    def finish(self, job_id, state, evidence):
        if state not in {"submitted_unconfirmed", "review_required"}:
            raise ValueError("bad_result_state")
        with self.connect() as db:
            row = db.execute("SELECT evidence FROM jobs WHERE id=? AND state='dispatching'", (job_id,)).fetchone()
            if row is None:
                raise ValueError("bad_transition")
            evidence = {**json.loads(row[0]), **evidence}
            n = db.execute("UPDATE jobs SET state=?,evidence=?,completed=max(attempt,?) "
                           "WHERE id=? AND state='dispatching'",
                           (state, canonical(evidence), time.time(), job_id)).rowcount
            if n != 1:
                raise ValueError("bad_transition")
            db.execute("DELETE FROM payloads WHERE id=?", (job_id,))

    def receipt(self, job_id):
        with self.connect() as db:
            row = db.execute("SELECT digest,state,evidence FROM jobs WHERE id=?", (job_id,)).fetchone()
        return None if row is None else {"id": job_id, "digest": row[0], "state": row[1],
                                        "evidence": json.loads(row[2]), "delivery_confirmed": False}
