import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from dottalk.demo import local_projection, synthetic_records
from dottalk.models import digest
from dottalk.server import create_app
from tests.conftest import create, prepare, read_and_claim


def test_full_flow_shares_only_exact_approved_payload(env, command):
    client, headers, *_ = env
    row = create(env, command)
    base = f"/v1/requests/{row['id']}"
    read_and_claim(env, row)
    result = prepare(env, row, synthetic_records(command))
    serialized = json.dumps(result)
    for excluded in (
        "Synthetic Person",
        "example.invalid",
        "DO-NOT-SHARE",
        "room_number",
        "Example Bank",
        "Unrelated Example Hotel",
        "flight_number",
    ):
        assert excluded not in serialized
    peer = client.get(base, headers=headers["owner_b.agent"]).json()
    assert "payload" not in peer and "release_hash" not in peer
    peer_list = client.get("/v1/requests", headers=headers["owner_b.human"]).json()
    assert "payload" not in peer_list[0]
    assert result["release_hash"] == digest(
        {
            "command_hash": row["command_hash"],
            "payload": result["payload"],
        }
    )
    response = client.post(
        base + "/approve-release",
        json={"digest": result["release_hash"]},
        headers=headers["owner_a.human"],
    )
    assert response.status_code == 200
    shared = client.get(base, headers=headers["owner_b.agent"]).json()
    assert shared["payload"] == result["payload"]
    audit = client.get("/v1/audit", headers=headers["owner_a.human"]).text
    assert "Example Harbor" not in audit and "SFO" not in audit


@pytest.mark.parametrize("role", ["owner_a.agent", "owner_b.agent", "owner_b.human"])
def test_agents_and_peer_cannot_approve(env, command, role):
    client, headers, *_ = env
    row = create(env, command)
    assert (
        client.post(
            f"/v1/requests/{row['id']}/approve-read",
            json={"digest": row["command_hash"]},
            headers=headers[role],
        ).status_code
        == 403
    )
    read_and_claim(env, row)
    result = prepare(env, row, synthetic_records(command))
    assert (
        client.post(
            f"/v1/requests/{row['id']}/approve-release",
            json={"digest": result["release_hash"]},
            headers=headers[role],
        ).status_code
        == 403
    )


def test_no_claim_or_preparation_before_approval(env, command):
    client, headers, *_ = env
    row = create(env, command)
    base = f"/v1/requests/{row['id']}"
    for path, body in (("claim", None), ("prepare", {"records": []})):
        assert (
            client.post(base + "/" + path, json=body, headers=headers["owner_a.agent"]).status_code
            == 409
        )


def test_claim_is_one_use_and_owner_agent_only(env, command):
    client, headers, *_ = env
    row = create(env, command)
    read_and_claim(env, row)
    assert (
        client.post(f"/v1/requests/{row['id']}/claim", headers=headers["owner_a.agent"]).status_code
        == 409
    )
    assert (
        client.post(f"/v1/requests/{row['id']}/claim", headers=headers["owner_b.agent"]).status_code
        == 403
    )
    assert (
        client.post(f"/v1/requests/{row['id']}/claim", headers=headers["owner_a.human"]).status_code
        == 403
    )


def test_stale_hashes_replay_and_payload_replacement_rejected(env, command):
    client, headers, *_ = env
    row = create(env, command)
    other = create(env, command)
    base = f"/v1/requests/{row['id']}"
    assert (
        client.post(
            base + "/approve-read",
            json={"digest": other["command_hash"]},
            headers=headers["owner_a.human"],
        ).status_code
        == 409
    )
    read_and_claim(env, row)
    result = prepare(env, row, synthetic_records(command))
    assert (
        client.post(
            base + "/prepare", json={"records": []}, headers=headers["owner_a.agent"]
        ).status_code
        == 409
    )
    assert (
        client.post(
            base + "/approve-release",
            json={"digest": row["command_hash"]},
            headers=headers["owner_a.human"],
        ).status_code
        == 409
    )
    body = {"digest": result["release_hash"]}
    assert (
        client.post(
            base + "/approve-release", json=body, headers=headers["owner_a.human"]
        ).status_code
        == 200
    )
    assert (
        client.post(
            base + "/approve-release", json=body, headers=headers["owner_a.human"]
        ).status_code
        == 409
    )


@pytest.mark.parametrize("stage", ["pending", "claimed", "prepared", "shared"])
def test_expiration_blocks_every_stage_and_erases_payload(env, command, stage):
    client, headers, now, app, *_ = env
    row = create(env, command)
    base = f"/v1/requests/{row['id']}"
    if stage != "pending":
        read_and_claim(env, row)
    if stage in {"prepared", "shared"}:
        result = prepare(env, row, synthetic_records(command))
    if stage == "shared":
        client.post(
            base + "/approve-release",
            json={"digest": result["release_hash"]},
            headers=headers["owner_a.human"],
        )
    now[0] += 1801
    response = client.get(base, headers=headers["owner_a.human"]).json()
    assert response["state"] == "expired" and response["payload"] is None
    assert client.post(base + "/claim", headers=headers["owner_a.agent"]).status_code == 410
    with app.state.store.transaction() as db:
        assert (
            db.execute("SELECT payload FROM requests WHERE id=?", (row["id"],)).fetchone()[0]
            is None
        )


def test_deny_while_preparing_prevents_result(env, command):
    client, headers, *_ = env
    row = create(env, command)
    read_and_claim(env, row)
    base = f"/v1/requests/{row['id']}"
    assert client.post(base + "/deny", headers=headers["owner_a.human"]).status_code == 200
    assert (
        client.post(
            base + "/prepare", json={"records": []}, headers=headers["owner_a.agent"]
        ).status_code
        == 409
    )


def test_peer_revocation_invalidates_pending_and_shared_results(env, command):
    client, headers, *_ = env
    row = create(env, command)
    read_and_claim(env, row)
    result = prepare(env, row, synthetic_records(command))
    base = f"/v1/requests/{row['id']}"
    client.post(
        base + "/approve-release",
        json={"digest": result["release_hash"]},
        headers=headers["owner_a.human"],
    )
    assert (
        client.post("/v1/peers/owner_b/revoke", headers=headers["owner_a.agent"]).status_code == 403
    )
    assert (
        client.post("/v1/peers/owner_b/revoke", headers=headers["owner_a.human"]).status_code == 200
    )
    assert "payload" not in client.get(base, headers=headers["owner_b.agent"]).json()
    assert (
        client.post("/v1/requests", json=command, headers=headers["owner_b.agent"]).status_code
        == 403
    )


def test_authentication_and_cross_user_isolation(env, command):
    client, headers, *_ = env
    row = create(env, command)
    assert client.get("/v1/requests").status_code == 401
    assert (
        client.get("/v1/requests", headers={"Authorization": "Bearer invalid"}).status_code == 401
    )
    assert (
        client.get(f"/v1/requests/{row['id']}", headers=headers["outsider.agent"]).status_code
        == 404
    )
    assert client.get("/v1/requests", headers=headers["outsider.agent"]).json() == []
    assert (
        client.post("/v1/requests", json=command, headers=headers["outsider.agent"]).status_code
        == 403
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"prompt": "read all mail"},
        {"requester": "owner_a"},
        {"callback_url": "http://127.0.0.1"},
        {"shell": "ls"},
    ],
)
def test_freeform_commands_identity_spoofing_and_callbacks_rejected(env, command, extra):
    client, headers, *_ = env
    assert (
        client.post(
            "/v1/requests", json={**command, **extra}, headers=headers["owner_b.agent"]
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "field", ["email", "passport", "card_number", "confirmation_code", "raw_email"]
)
def test_forbidden_fields_cannot_be_requested(env, command, field):
    client, headers, *_ = env
    command["scopes"] = [{"kind": "hotel", "fields": [field]}]
    assert (
        client.post("/v1/requests", json=command, headers=headers["owner_b.agent"]).status_code
        == 422
    )


def test_events_are_role_private_durable_and_acked_explicitly(env, command):
    client, headers, _, _, config, path = env
    row = create(env, command)
    events = client.get("/v1/events", headers=headers["owner_a.agent"]).json()
    assert len(events) == 1 and events[0]["kind"] == "request.created"
    assert set(events[0]) == {"id", "kind", "request_id", "created"}
    assert (
        client.post(
            f"/v1/events/{events[0]['id']}/ack", headers=headers["owner_b.agent"]
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/v1/events/{events[0]['id']}/ack", headers=headers["owner_a.human"]
        ).status_code
        == 404
    )
    restarted = create_app(config, path / "test.sqlite3", clock=lambda: 1_800_000_000)
    with TestClient(restarted) as second:
        assert second.get("/v1/events", headers=headers["owner_a.agent"]).json() == events
        assert (
            second.get(f"/v1/requests/{row['id']}", headers=headers["owner_a.agent"]).status_code
            == 200
        )
    assert (
        client.post(
            f"/v1/events/{events[0]['id']}/ack", headers=headers["owner_a.agent"]
        ).status_code
        == 200
    )
    assert client.get("/v1/events", headers=headers["owner_a.agent"]).json() == []


def test_concurrent_claims_and_releases_only_one_wins(env, command):
    client, headers, *_ = env
    row = create(env, command)
    base = f"/v1/requests/{row['id']}"
    client.post(
        base + "/approve-read",
        json={"digest": row["command_hash"]},
        headers=headers["owner_a.human"],
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(
                lambda _: (
                    client.post(base + "/claim", headers=headers["owner_a.agent"]).status_code
                ),
                range(2),
            )
        )
    assert sorted(statuses) == [200, 409]
    result = prepare(env, row, synthetic_records(command))
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(
                lambda _: (
                    client.post(
                        base + "/approve-release",
                        json={"digest": result["release_hash"]},
                        headers=headers["owner_a.human"],
                    ).status_code
                ),
                range(2),
            )
        )
    assert sorted(statuses) == [200, 409]


def test_bounded_body_and_request_quota(env, command):
    client, headers, *_ = env
    response = client.post("/v1/requests", content=b"x" * 65_537, headers=headers["owner_b.agent"])
    assert response.status_code == 413
    for _ in range(10):
        create(env, command)
    assert (
        client.post("/v1/requests", json=command, headers=headers["owner_b.agent"]).status_code
        == 429
    )


def test_validation_does_not_echo_private_input(env, command):
    client, headers, *_ = env
    response = client.post(
        "/v1/requests",
        json={**command, "secret": "PRIVATE-TEST-MARKER"},
        headers=headers["owner_b.agent"],
    )
    assert response.status_code == 422 and "PRIVATE-TEST-MARKER" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_card_reminders_exclude_balances_and_account_identifiers(env, command):
    client, headers, *_ = env
    command["scopes"] = [{"kind": "card_reminder", "fields": ["issuer", "due_date"]}]
    row = create(env, command)
    read_and_claim(env, row)
    result = prepare(env, row, synthetic_records(command))
    assert result["payload"]["items"] == [
        {
            "kind": "card_reminder",
            "fields": {
                "issuer": "Example Bank",
                "due_date": "2026-11-24",
            },
        }
    ]


def test_local_projection_discards_source_pii_before_network(command):
    result = local_projection(command, synthetic_records(command))
    assert len(result) == 2
    assert set(result[0]) == {"kind", "origin", "destination", "departure", "arrival"}
    assert "DO-NOT-SHARE" not in json.dumps(result)
