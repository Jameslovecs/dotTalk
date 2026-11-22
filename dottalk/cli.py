"""Local setup, human approval terminal, and durable agent wake listener."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn

from dottalk.client import Client
from dottalk.demo import handle_demo_event
from dottalk.models import canonical
from dottalk.server import from_file


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(value, file, indent=2)
        file.write("\n")


def initialize(path):
    if path.exists():
        raise ValueError("State directory already exists; refusing to overwrite credentials")
    path.mkdir(parents=True, mode=0o700)
    profiles = path / "profiles"
    profiles.mkdir(mode=0o700)
    config = {
        "users": {"owner_a": {"peers": ["owner_b"]}, "owner_b": {"peers": ["owner_a"]}},
        "credentials": [],
    }
    for user in config["users"]:
        for role in ("agent", "human"):
            token = secrets.token_urlsafe(32)
            config["credentials"].append(
                {
                    "user": user,
                    "role": role,
                    "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                }
            )
            private_json(
                profiles / f"{user}.{role}.json",
                {
                    "base_url": "http://127.0.0.1:8765",
                    "user": user,
                    "role": role,
                    "token": token,
                },
            )
    private_json(path / "config.json", config)
    print(f"Created local demo identities in {path}. No tokens printed.")
    print(
        "Keep human profiles away from agent processes. "
        "These are demo identities, not verified people."
    )


def display(value):
    # Escapes control characters in untrusted values; never prints raw source text.
    print(json.dumps(value, indent=2, ensure_ascii=True), flush=True)


def approve(client, request_id, phase):
    me = client.call("GET", "/v1/me")
    if me["role"] != "human":
        raise ValueError("Approval requires a human profile")
    row = client.get_request(request_id)
    if row["owner"] != me["user"]:
        raise ValueError("Only the data owner can approve")
    expected = "pending_read" if phase == "read" else "awaiting_release"
    if row["state"] != expected:
        raise ValueError(f"Request is {row['state']}; cannot approve {phase}")
    print(f"ONE-TIME {phase.upper()} APPROVAL")
    print(f"Owner: {row['owner']}  |  Recipient: {row['requester']}")
    display({"request_id": row["id"], "expires_unix": row["expires"], "command": row["command"]})
    if phase == "release":
        print("Exactly this response will be made available to the recipient:")
        display(row["payload"])
    else:
        print("Allows one owner-agent preparation of this lookup. Does not allow sharing.")
    fingerprint = row["command_hash"] if phase == "read" else row["release_hash"]
    print(f"Approval digest: {fingerprint}")
    if not sys.stdin.isatty():
        raise ValueError("Approval requires an interactive human terminal")
    phrase = f"approve {request_id[-8:]}"
    if input(f"Type '{phrase}' to approve, or anything else to cancel: ") != phrase:
        print("Cancelled; no approval sent.")
        return
    display(
        client.call("POST", f"/v1/requests/{request_id}/approve-{phase}", {"digest": fingerprint})
    )


def watch(client, *, demo_worker=False, handler=None, once=False, interval=2):
    me = client.call("GET", "/v1/me")
    if (demo_worker or handler) and me["role"] != "agent":
        raise ValueError("Workers must use an agent profile")
    if demo_worker and handler:
        raise ValueError("Select either the demo worker or a local handler")
    if handler:
        handler = str(Path(handler).resolve(strict=True))
    while True:
        events = client.events()
        for event in events:
            display(event)
            if demo_worker:
                handle_demo_event(client, event)
            if handler:
                # Only the locally configured executable runs. No shell, peer text, URLs,
                # or source data in arguments. A nonzero exit leaves the event unacked.
                subprocess.run([handler], input=canonical(event), text=True, timeout=60, check=True)
            if demo_worker or handler:
                client.acknowledge(event["id"])
        if once:
            return
        if not (demo_worker or handler):
            # Observe without consuming the durable inbox. Avoid printing unchanged events.
            print("Inbox shown. Use 'events' to refresh or 'watch --handler' for delivery.")
            return
        time.sleep(interval)


def parser():
    root = argparse.ArgumentParser(description="dotTalk approval broker")
    root.add_argument("--state", type=Path, default=Path(".state"))
    root.add_argument("--profile", type=Path)
    sub = root.add_subparsers(dest="action", required=True)
    sub.add_parser("init")
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8765)
    for name in ("me", "inbox", "events", "audit"):
        sub.add_parser(name)
    request = sub.add_parser("request")
    request.add_argument("file", type=Path)
    for name in ("show", "approve-read", "approve-release", "deny"):
        command = sub.add_parser(name)
        command.add_argument("id")
    revoke = sub.add_parser("revoke-peer")
    revoke.add_argument("peer")
    listener = sub.add_parser("watch")
    listener.add_argument("--demo-worker", action="store_true")
    listener.add_argument("--handler", type=Path)
    listener.add_argument("--once", action="store_true")
    return root


def main():
    args = parser().parse_args()
    client = None
    try:
        if args.action == "init":
            initialize(args.state)
            return
        if args.action == "serve":
            uvicorn.run(
                from_file(args.state / "config.json"),
                host="127.0.0.1",
                port=args.port,
                access_log=False,
                log_level="warning",
            )
            return
        if not args.profile:
            raise ValueError("Select an explicit --profile; no implicit human credentials")
        client = Client.from_profile(args.profile)
        if args.action in {"me", "inbox", "events", "audit"}:
            route = "requests" if args.action == "inbox" else args.action
            display(client.call("GET", f"/v1/{route}"))
        elif args.action == "request":
            display(client.create_request(json.loads(args.file.read_text())))
        elif args.action == "show":
            display(client.get_request(args.id))
        elif args.action.startswith("approve-"):
            approve(client, args.id, args.action.removeprefix("approve-"))
        elif args.action == "deny":
            display(client.call("POST", f"/v1/requests/{args.id}/deny"))
        elif args.action == "revoke-peer":
            display(client.call("POST", f"/v1/peers/{args.peer}/revoke"))
        elif args.action == "watch":
            watch(client, demo_worker=args.demo_worker, handler=args.handler, once=args.once)
    except KeyboardInterrupt:
        print("Stopped.")
    except (ValueError, OSError, RuntimeError, httpx.HTTPError, subprocess.SubprocessError) as exc:
        # Network and subprocess exceptions can contain private URLs/arguments.
        message = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
        print(f"Error: {message}", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
