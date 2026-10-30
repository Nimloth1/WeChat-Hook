"""审核后停服务使用的v1→v2账本迁移；不清水位、不补历史、不触发发送。"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from relay_common import Store, digest, validate_policy
from relay_guest import single_executor


def upgrade(store, previous, current):
    validate_policy(current)
    expected = {k: v for k, v in previous.items()
                if k not in {"interval_seconds", "daily_messages", "daily_media_bytes"}}
    expected["version"] = 2
    if (previous.get("version") != 1 or expected != current
            or set(previous) != {"version", "enabled", "recipient", "source", "corporations",
                                 "interval_seconds", "daily_messages", "daily_media_bytes"}):
        raise ValueError("migration_scope_changed")
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM meta WHERE key='paused'").fetchone():
            raise ValueError("migration_paused_needs_review")
        if (db.execute("SELECT 1 FROM jobs WHERE state NOT IN ('submitted_unconfirmed') LIMIT 1").fetchone()
                or db.execute("SELECT 1 FROM payloads LIMIT 1").fetchone()
                or db.execute("SELECT 1 FROM media WHERE state='waiting' LIMIT 1").fetchone()):
            raise ValueError("migration_pending_jobs_need_drain")
        row = db.execute("SELECT value FROM meta WHERE key='policy_scope'").fetchone()
        old_scope = digest({**previous, "enabled": True})
        new_scope = digest({**current, "enabled": True})
        if row and json.loads(row[0]) not in {old_scope, new_scope}:
            raise ValueError("migration_scope_mismatch")
        if row:
            store.put(db, "policy_scope", new_scope)
        store.put(db, "relay_protocol", 2)
    return {"protocol": 2, "cursor_preserved": True, "attempts_preserved": True, "sends": 0}


@contextmanager
def stopped_collector(root):
    if os.name == "nt":
        if os.environ.get("COMPUTERNAME") != "VW12":
            raise ValueError("wrong_guest")
        with single_executor(root):
            yield
    else:
        import fcntl
        with (Path(root) / "collector.lock").open("a+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--previous-config", required=True, type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    previous = json.loads(args.previous_config.read_text(encoding="utf-8"))
    if cfg["state_dir"] != previous["state_dir"]:
        raise ValueError("migration_cannot_replace_ledger")
    store = Store(cfg["state_dir"])
    with stopped_collector(store.root):
        print(json.dumps(upgrade(store, previous["policy"], cfg["policy"])))


if __name__ == "__main__":
    main()
