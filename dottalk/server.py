"""Trusted approval broker. Bearer roles are distinct; peers never get source tools."""

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from contextlib import asynccontextmanager, contextmanager, suppress
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from dottalk.models import Approval, Candidate, RequestCommand, canonical, digest, minimize
from dottalk.store import Store, audit, decode, event

MAX_BODY = 65_536


class BodyLimit:
    """Bound all incoming bodies before JSON parsing, including chunked uploads."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY:
                response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                return await response(scope, receive, send)
            if not message.get("more_body", False):
                break
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def create_app(config: dict, db_path: Path, clock=time.time) -> FastAPI:
    store = Store(db_path)
    with store.transaction() as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS blocked (owner TEXT, peer TEXT, PRIMARY KEY(owner,peer))"
        )

    @contextmanager
    def transaction():
        with store.transaction() as db:
            now = clock()
            db.execute(
                "UPDATE requests SET state='expired', payload=NULL, release_hash=NULL "
                "WHERE expires<=? AND state NOT IN ('expired','denied','revoked','failed')",
                (now,),
            )
            db.execute(
                "DELETE FROM events WHERE request_id IN (SELECT id FROM requests WHERE expires<?)",
                (now - 86400,),
            )
            db.execute("DELETE FROM requests WHERE expires<?", (now - 86400,))
            db.execute("DELETE FROM audit WHERE at<?", (now - 7 * 86400,))
            yield db

    @asynccontextmanager
    async def lifespan(app):
        async def sweep():
            while True:
                with transaction():
                    pass
                await asyncio.sleep(30)

        task = asyncio.create_task(sweep())
        yield
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    app = FastAPI(
        title="dotTalk", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None
    )
    app.add_middleware(BodyLimit)
    app.state.store = store

    @app.middleware("http")
    async def private_responses(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default errors echo invalid input, which might contain secrets.
        return JSONResponse(status_code=422, content={"detail": "Invalid request schema"})

    def actor(request: Request):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 256:
            raise HTTPException(401, "Bearer credential required")
        hashed = hashlib.sha256(authorization[7:].encode()).hexdigest()
        for credential in config["credentials"]:
            if hmac.compare_digest(hashed, credential["token_hash"]):
                return {"user": credential["user"], "role": credential["role"]}
        raise HTTPException(401, "Invalid credential")

    def require_role(who, role):
        if who["role"] != role:
            raise HTTPException(403, f"Requires {role} credential")

    def trusted(db, first, second):
        return (
            second in config["users"].get(first, {}).get("peers", [])
            and first in config["users"].get(second, {}).get("peers", [])
            and not db.execute(
                "SELECT 1 FROM blocked WHERE (owner=? AND peer=?) OR (owner=? AND peer=?)",
                (first, second, second, first),
            ).fetchone()
        )

    def load(db, request_id, who, owner_only=False):
        row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None or who["user"] not in {row["owner"], row["requester"]}:
            raise HTTPException(404, "Request not found")
        if owner_only and row["owner"] != who["user"]:
            raise HTTPException(403, "Only the data owner may perform this action")
        return decode(row)

    def active(db, row, state):
        if row["expires"] <= clock():
            raise HTTPException(410, "Request expired")
        if not trusted(db, row["owner"], row["requester"]):
            raise HTTPException(403, "Peer relationship revoked")
        if row["state"] != state:
            raise HTTPException(409, "Action unavailable in current state")

    def view(row, who):
        # The requester's view must never expose an unapproved candidate or its hash.
        result = {
            k: row[k]
            for k in (
                "id",
                "requester",
                "owner",
                "command",
                "command_hash",
                "state",
                "created",
                "expires",
            )
        }
        if who["user"] == row["owner"] or row["state"] == "shared":
            result["payload"] = row["payload"]
            result["release_hash"] = row["release_hash"]
        return result

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/v1/me")
    def me(who=Depends(actor)):
        with transaction() as db:
            return {
                **who,
                "peers": [
                    peer
                    for peer in config["users"][who["user"]]["peers"]
                    if trusted(db, who["user"], peer)
                ],
            }

    @app.post("/v1/requests", status_code=201)
    def create(command: RequestCommand, who=Depends(actor)):
        now, request_id = clock(), str(uuid.uuid4())
        with transaction() as db:
            if command.target == who["user"] or not trusted(db, who["user"], command.target):
                raise HTTPException(403, "Target is not an enrolled mutual peer")
            count = db.execute(
                "SELECT COUNT(*) FROM requests WHERE requester=? AND created>?",
                (who["user"], now - 3600),
            ).fetchone()[0]
            pending = db.execute(
                "SELECT COUNT(*) FROM requests WHERE requester=? AND state IN "
                "('pending_read','read_approved','preparing','awaiting_release')",
                (who["user"],),
            ).fetchone()[0]
            if count >= 30 or pending >= 10:
                raise HTTPException(429, "Request quota exceeded")
            command_data = command.model_dump(mode="json")
            envelope = {
                "version": 1,
                "request_id": request_id,
                "requester": who["user"],
                "owner": command.target,
                "command": command_data,
                "expires": now + command.ttl_minutes * 60,
            }
            command_hash = digest(envelope)
            db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    who["user"],
                    command.target,
                    canonical(command_data),
                    command_hash,
                    "pending_read",
                    now,
                    envelope["expires"],
                    None,
                    None,
                ),
            )
            event(db, command.target, "agent", request_id, "request.created", now)
            event(db, command.target, "human", request_id, "approval.read_required", now)
            audit(db, request_id, who["user"], "created", now)
            return view(load(db, request_id, who), who)

    @app.get("/v1/requests")
    def requests(who=Depends(actor)):
        with transaction() as db:
            rows = db.execute(
                "SELECT * FROM requests WHERE owner=? OR requester=? "
                "ORDER BY created DESC LIMIT 100",
                (who["user"], who["user"]),
            ).fetchall()
            return [view(decode(row), who) for row in rows]

    @app.get("/v1/requests/{request_id}")
    def get_request(request_id: str, who=Depends(actor)):
        with transaction() as db:
            return view(load(db, request_id, who), who)

    @app.post("/v1/requests/{request_id}/approve-read")
    def approve_read(request_id: str, approval: Approval, who=Depends(actor)):
        require_role(who, "human")
        with transaction() as db:
            row = load(db, request_id, who, owner_only=True)
            active(db, row, "pending_read")
            if not hmac.compare_digest(row["command_hash"], approval.digest):
                raise HTTPException(409, "Approval does not match this exact command")
            db.execute("UPDATE requests SET state='read_approved' WHERE id=?", (request_id,))
            event(db, row["owner"], "agent", request_id, "read.approved", clock())
            audit(db, request_id, who["user"], "read_approved", clock())
            return {"state": "read_approved"}

    @app.post("/v1/requests/{request_id}/claim")
    def claim(request_id: str, who=Depends(actor)):
        require_role(who, "agent")
        with transaction() as db:
            row = load(db, request_id, who, owner_only=True)
            active(db, row, "read_approved")
            db.execute("UPDATE requests SET state='preparing' WHERE id=?", (request_id,))
            audit(db, request_id, who["user"], "claimed", clock())
            return {
                "command": row["command"],
                "command_hash": row["command_hash"],
                "expires": row["expires"],
            }

    @app.post("/v1/requests/{request_id}/prepare")
    def prepare(request_id: str, candidate: Candidate, who=Depends(actor)):
        require_role(who, "agent")
        with transaction() as db:
            row = load(db, request_id, who, owner_only=True)
            active(db, row, "preparing")
            try:
                payload = minimize(row["command"], candidate.records)
            except (ValueError, TypeError, KeyError, OverflowError):
                raise HTTPException(422, "Candidate failed scope or privacy checks") from None
            release_hash = digest({"command_hash": row["command_hash"], "payload": payload})
            db.execute(
                "UPDATE requests SET state='awaiting_release',payload=?,release_hash=? WHERE id=?",
                (canonical(payload), release_hash, request_id),
            )
            event(db, row["owner"], "human", request_id, "approval.release_required", clock())
            audit(db, request_id, who["user"], "prepared", clock())
            return {"state": "awaiting_release", "payload": payload, "release_hash": release_hash}

    @app.post("/v1/requests/{request_id}/approve-release")
    def release(request_id: str, approval: Approval, who=Depends(actor)):
        require_role(who, "human")
        with transaction() as db:
            row = load(db, request_id, who, owner_only=True)
            active(db, row, "awaiting_release")
            if not hmac.compare_digest(row["release_hash"], approval.digest):
                raise HTTPException(409, "Approval does not match this exact response")
            db.execute("UPDATE requests SET state='shared' WHERE id=?", (request_id,))
            event(db, row["requester"], "agent", request_id, "response.shared", clock())
            event(db, row["requester"], "human", request_id, "response.shared", clock())
            audit(db, request_id, who["user"], "released", clock())
            return {"state": "shared"}

    @app.post("/v1/requests/{request_id}/deny")
    def deny(request_id: str, who=Depends(actor)):
        require_role(who, "human")
        with transaction() as db:
            row = load(db, request_id, who, owner_only=True)
            if row["state"] in {"expired", "denied", "revoked", "failed"}:
                raise HTTPException(409, "Request already closed")
            state = "revoked" if row["state"] == "shared" else "denied"
            db.execute(
                "UPDATE requests SET state=?,payload=NULL,release_hash=NULL WHERE id=?",
                (state, request_id),
            )
            event(db, row["requester"], "agent", request_id, f"request.{state}", clock())
            audit(db, request_id, who["user"], state, clock())
            return {"state": state}

    @app.post("/v1/requests/{request_id}/fail")
    def fail(request_id: str, who=Depends(actor)):
        require_role(who, "agent")
        with transaction() as db:
            row = load(db, request_id, who, owner_only=True)
            active(db, row, "preparing")
            db.execute("UPDATE requests SET state='failed' WHERE id=?", (request_id,))
            for user, role in ((row["owner"], "human"), (row["requester"], "agent")):
                event(db, user, role, request_id, "request.failed", clock())
            audit(db, request_id, who["user"], "failed", clock())
            return {"state": "failed"}

    @app.get("/v1/events")
    def events(who=Depends(actor)):
        with transaction() as db:
            rows = db.execute(
                "SELECT id,request_id,kind,created FROM events WHERE user_id=? AND role=? "
                "AND acknowledged=0 ORDER BY id LIMIT 100",
                (who["user"], who["role"]),
            ).fetchall()
            return [dict(row) for row in rows]

    @app.post("/v1/events/{event_id}/ack")
    def ack(event_id: int, who=Depends(actor)):
        with transaction() as db:
            result = db.execute(
                "UPDATE events SET acknowledged=1 WHERE id=? AND user_id=? AND role=?",
                (event_id, who["user"], who["role"]),
            )
            if result.rowcount != 1:
                raise HTTPException(404, "Event not found")
            return {"acknowledged": True}

    @app.post("/v1/peers/{peer}/revoke")
    def revoke_peer(peer: str, who=Depends(actor)):
        require_role(who, "human")
        if peer not in config["users"][who["user"]]["peers"]:
            raise HTTPException(404, "Peer not found")
        with transaction() as db:
            db.execute("INSERT OR IGNORE INTO blocked VALUES(?,?)", (who["user"], peer))
            rows = db.execute(
                "SELECT id FROM requests WHERE (owner=? AND requester=?) "
                "OR (owner=? AND requester=?)",
                (who["user"], peer, peer, who["user"]),
            ).fetchall()
            for row in rows:
                db.execute(
                    "UPDATE requests SET state='revoked',payload=NULL,release_hash=NULL WHERE id=?",
                    (row["id"],),
                )
                audit(db, row["id"], who["user"], "peer_revoked", clock())
            return {"revoked": True}

    @app.get("/v1/audit")
    def get_audit(who=Depends(actor)):
        require_role(who, "human")
        with transaction() as db:
            rows = db.execute(
                "SELECT audit.* FROM audit JOIN requests ON requests.id=audit.request_id "
                "WHERE requests.owner=? ORDER BY audit.id DESC LIMIT 100",
                (who["user"],),
            ).fetchall()
            return [dict(row) for row in rows]

    return app


def from_file(path: Path) -> FastAPI:
    return create_app(json.loads(path.read_text()), path.parent / "broker.sqlite3")
