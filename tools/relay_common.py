"""PM → VW12 自动转发的离线协议和持久账本；不包含微信调用。"""
import base64
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import sqlite3
import time

MAX_MEDIA = 20 * 1024 * 1024
MAX_PENDING = 100 * 1024 * 1024
MIN_FREE = 1024 * 1024 * 1024
MAX_WIRE = 29 * 1024 * 1024
KINDS = {"text", "image", "file"}
SOURCE_MODULE = "f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36"
HOOK_MODULE = "2b88a8d697b9a7a52fd0b5e1d60c7e1477970e96d918d2b4e5f9a779a55e8171"


def canonical(value):
    # 附件 base64 很长；少量中文元数据不能让整个 JSON 变成双字节 Unicode 缓冲。
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


def validate_policy(policy):
    if (not isinstance(policy, dict) or policy.get("version") != 1
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
    for key, low, high in (("interval_seconds", 180, 86400),
                           ("daily_messages", 1, 480),
                           ("daily_media_bytes", 1, 128 * 1024 * 1024)):
        if type(policy.get(key)) is not int or not low <= policy[key] <= high:
            raise ValueError("invalid_rate_policy")
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
                or not payload["text"].strip()
                or len(payload["text"].encode("utf-16le")) // 2 > 2000):
            raise ValueError("invalid_text")
    else:
        if not isinstance(payload, dict) or set(payload) != {"filename", "sha256", "data_b64"}:
            raise ValueError("invalid_media")
        name = payload["filename"]
        if (not isinstance(name, str) or not name or len(name) > 180
                or re.search(r'[<>:"/\\|?*\x00-\x1f]', name)
                or name.endswith((".", " ")) or name.split(".")[0].upper() in
                {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                 *(f"LPT{i}" for i in range(1, 10))}):
            raise ValueError("invalid_filename")
        raw = payload["data_b64"]
        if not isinstance(raw, str) or len(raw) > (MAX_MEDIA + 2) // 3 * 4:
            raise ValueError("media_too_large")
        data = base64.b64decode(raw, validate=True)
        if not data or len(data) > MAX_MEDIA or hashlib.sha256(data).hexdigest() != payload["sha256"]:
            raise ValueError("media_hash_mismatch")
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
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
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
        encoded = job["payload"].get("data_b64", "")
        media = len(encoded) // 4 * 3 - (len(encoded) - len(encoded.rstrip("=")))
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
            # PM 完成时已收到来宾完成回执，以完成时刻限流，涵盖远端准备/清理耗时。
            # 两端均使用自己的完成时间；不把不同主机的绝对时间互相比较。
            last = db.execute("SELECT max(coalesce(completed,attempt)) FROM jobs").fetchone()[0]
            # 滚动配额同样保守地从完成计时，防止 PM 先释放旧任务的额度。
            count, size = db.execute("SELECT count(*),coalesce(sum(media_bytes),0) FROM jobs "
                                     "WHERE coalesce(completed,attempt)>?", (now - 86400,)).fetchone()
            encoded = job["payload"].get("data_b64", "")
            media = len(encoded) // 4 * 3 - (len(encoded) - len(encoded.rstrip("=")))
            if ((last is not None and now - last < policy["interval_seconds"])
                    or count >= policy["daily_messages"] or size + media > policy["daily_media_bytes"]):
                return False
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
