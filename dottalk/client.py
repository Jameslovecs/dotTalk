"""Small HTTP SDK suitable for an owner-controlled agent tool."""

import json
from pathlib import Path
from urllib.parse import urlparse

import httpx


class Client:
    def __init__(self, base_url: str, token: str):
        url = urlparse(base_url)
        if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
            raise ValueError("Use a plain broker origin")
        if url.scheme != "https" and not (
            url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}
        ):
            raise ValueError("Remote brokers require HTTPS")
        self.http = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
            follow_redirects=False,
            trust_env=False,
        )

    @classmethod
    def from_profile(cls, path: Path):
        profile = json.loads(path.read_text())
        return cls(profile["base_url"], profile["token"])

    def call(self, method, path, data=None):
        response = self.http.request(method, path, json=data)
        if not response.is_success:
            # Do not echo server bodies or request credentials into agent logs.
            raise RuntimeError(f"Broker rejected operation (HTTP {response.status_code})")
        return response.json()

    def close(self):
        self.http.close()

    def create_request(self, command):
        return self.call("POST", "/v1/requests", command)

    def get_request(self, request_id):
        return self.call("GET", f"/v1/requests/{request_id}")

    def events(self):
        return self.call("GET", "/v1/events")

    def acknowledge(self, event_id):
        return self.call("POST", f"/v1/events/{event_id}/ack")

    def claim(self, request_id):
        return self.call("POST", f"/v1/requests/{request_id}/claim")

    def prepare(self, request_id, records):
        return self.call("POST", f"/v1/requests/{request_id}/prepare", {"records": records})
