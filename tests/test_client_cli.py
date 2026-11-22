import json
import os
from unittest.mock import Mock

import pytest

from dottalk.cli import approve, initialize, watch
from dottalk.client import Client
from dottalk.demo import handle_demo_event


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "ftp://localhost",
        "https://x/?token=x",
        "https://user:password@example.com",
        "https://example.com/api",
    ],
)
def test_client_rejects_unsafe_origins(url):
    with pytest.raises(ValueError):
        Client(url, "test-only")


def test_init_generates_separate_roles_and_private_permissions(tmp_path):
    state = tmp_path / "state"
    initialize(state)
    profiles = list((state / "profiles").glob("*.json"))
    assert len(profiles) == 4
    tokens = {json.loads(path.read_text())["token"] for path in profiles}
    assert len(tokens) == 4
    assert not any(token in (state / "config.json").read_text() for token in tokens)
    if os.name == "posix":
        assert state.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in profiles)
    with pytest.raises(ValueError):
        initialize(state)


def test_worker_never_reads_source_before_successful_claim(monkeypatch):
    client = Mock()
    client.get_request.return_value = {"state": "read_approved"}
    client.claim.side_effect = RuntimeError("Rejected")
    source = Mock()
    monkeypatch.setattr("dottalk.demo.synthetic_records", source)
    with pytest.raises(RuntimeError):
        handle_demo_event(client, {"kind": "read.approved", "request_id": "test"})
    source.assert_not_called()
    client.prepare.assert_not_called()


def test_restarted_worker_fails_closed_after_claim():
    client = Mock()
    client.get_request.return_value = {"state": "preparing"}
    handle_demo_event(client, {"kind": "read.approved", "request_id": "test"})
    client.claim.assert_not_called()
    client.call.assert_called_once_with("POST", "/v1/requests/test/fail")


def test_human_approval_requires_tty_and_never_posts_automatically(monkeypatch):
    client = Mock()
    client.call.return_value = {"role": "human", "user": "owner_a"}
    client.get_request.return_value = {
        "owner": "owner_a",
        "requester": "owner_b",
        "state": "pending_read",
        "id": "test",
        "expires": 123,
        "command": {},
        "command_hash": "a" * 64,
    }
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(ValueError):
        approve(client, "test", "read")
    client.call.assert_called_once_with("GET", "/v1/me")


def test_wake_handler_receives_event_without_shell_and_ack_after_success(tmp_path, monkeypatch):
    handler = tmp_path / "handler"
    handler.write_text("test fixture")
    event = {"id": 1, "kind": "request.created", "request_id": "test", "created": 123}
    client = Mock()
    client.call.return_value = {"user": "owner_a", "role": "agent"}
    client.events.return_value = [event]
    run = Mock()
    monkeypatch.setattr("dottalk.cli.subprocess.run", run)
    watch(client, handler=handler, once=True)
    assert run.call_args.args == ([str(handler.resolve())],)
    assert "shell" not in run.call_args.kwargs
    assert json.loads(run.call_args.kwargs["input"]) == event
    client.acknowledge.assert_called_once_with(1)
