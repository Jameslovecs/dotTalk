import hashlib

import pytest
from fastapi.testclient import TestClient

from dottalk.server import create_app


@pytest.fixture
def env(tmp_path):
    credentials = []
    headers = {}
    for user in ("owner_a", "owner_b", "outsider"):
        for role in ("agent", "human"):
            # Public test-only strings; setup generates random secrets for real profiles.
            token = f"TEST-ONLY-{user}-{role}"
            headers[f"{user}.{role}"] = {"Authorization": f"Bearer {token}"}
            credentials.append(
                {
                    "user": user,
                    "role": role,
                    "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                }
            )
    config = {
        "users": {
            "owner_a": {"peers": ["owner_b"]},
            "owner_b": {"peers": ["owner_a"]},
            "outsider": {"peers": []},
        },
        "credentials": credentials,
    }
    now = [1_800_000_000.0]
    app = create_app(config, tmp_path / "test.sqlite3", clock=lambda: now[0])
    with TestClient(app) as client:
        yield client, headers, now, app, config, tmp_path


@pytest.fixture
def command():
    return {
        "target": "owner_a",
        "date": "2026-11-24",
        "time_zone": "America/Los_Angeles",
        "scopes": [
            {"kind": "flight", "fields": ["origin", "destination", "departure"]},
            {"kind": "hotel", "fields": ["hotel_name", "city"]},
        ],
        "ttl_minutes": 30,
    }


def create(env, command):
    client, headers, *_ = env
    response = client.post("/v1/requests", json=command, headers=headers["owner_b.agent"])
    assert response.status_code == 201, response.text
    return response.json()


def read_and_claim(env, row):
    client, headers, *_ = env
    base = f"/v1/requests/{row['id']}"
    response = client.post(
        base + "/approve-read",
        json={"digest": row["command_hash"]},
        headers=headers["owner_a.human"],
    )
    assert response.status_code == 200, response.text
    response = client.post(base + "/claim", headers=headers["owner_a.agent"])
    assert response.status_code == 200, response.text


def prepare(env, row, records):
    client, headers, *_ = env
    response = client.post(
        f"/v1/requests/{row['id']}/prepare",
        json={"records": records},
        headers=headers["owner_a.agent"],
    )
    assert response.status_code == 200, response.text
    return response.json()
