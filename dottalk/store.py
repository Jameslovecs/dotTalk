"""Small durable store. Every state transition takes an SQLite write transaction."""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        with self.transaction() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, requester TEXT NOT NULL, owner TEXT NOT NULL,
                    command TEXT NOT NULL, command_hash TEXT NOT NULL, state TEXT NOT NULL,
                    created REAL NOT NULL, expires REAL NOT NULL,
                    payload TEXT, release_hash TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
                    role TEXT NOT NULL, request_id TEXT NOT NULL, kind TEXT NOT NULL,
                    created REAL NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS inbox ON events(user_id, role, acknowledged, id);
            """)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA secure_delete=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()


def event(db, user, role, request, kind, now):
    db.execute(
        "INSERT INTO events(user_id, role, request_id, kind, created) VALUES(?,?,?,?,?)",
        (user, role, request, kind, now),
    )


def audit(db, request, actor, action, now):
    db.execute(
        "INSERT INTO audit(request_id, actor, action, at) VALUES(?,?,?,?)",
        (request, actor, action, now),
    )


def decode(row):
    result = dict(row)
    result["command"] = json.loads(result["command"])
    if result["payload"] is not None:
        result["payload"] = json.loads(result["payload"])
    return result
