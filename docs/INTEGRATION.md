# Agent integration contract

Use the Python SDK, CLI, or the REST API. OpenAPI is available at `/openapi.json`; it contains
schemas only. There is no unauthenticated access to requests, candidates, inboxes, or audit.

## Two people, two trust boundaries

The loopback demo is deliberately easy to run on one computer. For two machines, use an
operator-controlled HTTPS broker reachable by both agents, or authenticated SSH tunnels to
its loopback listener. Configure each profile's `base_url` accordingly. Public deployment
is not included. Do not expose a plain HTTP listener to a network.

1. Verify each other outside the agent channel. A nickname or claim of marriage is not proof.
2. Assign opaque owner IDs, enroll each other in the trusted server configuration, and
   distribute each person's agent credential privately. Never put tokens in prompts, URLs,
   GitHub, or shell history. The `init` command supplies fictional demo IDs only.
3. Keep human credentials and the approval terminal on a boundary inaccessible to agents.
   For production, replace local bearer-human profiles with a separate passkey approval app.
4. Keep Gmail/card-provider credentials on the owner's device, in a constrained source
   gateway. The broker and remote agent must never receive these credentials.
5. Run one persistent listener for each agent. Run it under your service manager if you
   need it to survive logouts/reboots. The repository does not install background services.

## Requester tools

```python
from pathlib import Path
from dottalk.client import Client

client = Client.from_profile(Path("/private/owner_b.agent.json"))
try:
    request = client.create_request(
        {
            "target": "owner_a",
            "date": "2026-11-24",
            "time_zone": "America/Los_Angeles",
            "scopes": [{"kind": "hotel", "fields": ["hotel_name", "check_in", "check_out"]}],
            "ttl_minutes": 30,
        }
    )
    # No result is available until the owner reviews and releases it.
    status = client.get_request(request["id"])
finally:
    client.close()
```

A person can also submit a request with their own human profile. Being the requester does
not grant permission to approve the other person's data.

## Owner agent and source gateway

On `request.created`, notify the owner with the exact typed request and the identity bound
by the broker. Direct them to the human approval terminal. Do not request source access yet.

On `read.approved`:

```python
from dottalk.demo import local_projection

claim = client.claim(request_id)  # Exactly once; fails without human approval.
command = claim["command"]
# Implement this function inside the owner's constrained gateway:
records = trusted_local_source.lookup(command, expires=claim["expires"])
candidate = local_projection(command, records)
client.prepare(request_id, candidate)
```

`trusted_local_source` is a contract, not a bundled Gmail implementation. Its implementation
must validate the approved claim with the broker, use bounded and read-only access, enforce
the exact scope and expiry, and never accept arbitrary tool names, Gmail queries, shell code,
or destination addresses from peers. It should keep source content out of agent conversation
history when unnecessary. The supplied `demo` worker provides the complete runnable example.

Normalize source records to these shapes, locally:

| Kind | Filtering evidence required | Shareable fields |
| --- | --- | --- |
| `flight` | Offset-aware `departure`, `arrival` | `airline`, `flight_number`, `origin`, `destination`, `departure`, `arrival` |
| `hotel` | ISO `check_in`, `check_out` | `hotel_name`, `city`, `check_in`, `check_out` |
| `card_reminder` | ISO `due_date` | `issuer`, `due_date` |

Include `kind` in each record. The local projection sends only requested fields plus the
minimum date-filtering evidence. The broker rechecks filtering and returns only requested
fields. The owner sees the exact result before approving release. A failed lookup should call
`POST /v1/requests/{id}/fail` without including provider errors or source content. A crash after
claim is not retried automatically; create a new request. Denied/revoked/expired work must stop.

## Wake delivery

`GET /v1/events` returns up to 100 unacknowledged events for the authenticated owner and role:

```json
{"id": 1, "request_id": "opaque-request-uuid", "kind": "request.created", "created": 1800000000}
```

Events never contain source data or executable commands. Fetch the request using your own
credential and recheck its current state; events may be duplicated or stale. Human events
are separate from agent events. `POST /v1/events/{id}/ack` is idempotent for its own recipient.
No recipient can read or acknowledge another owner's or role's inbox.

The listener polls every two seconds. With `--handler /absolute/path`, it starts that local
executable, feeds one JSON event to stdin, and acknowledges after a zero exit. It does not
pass the agent credential as an argument. Configure the handler's own private profile path
locally. Do not send event strings to a shell. A timeout (60 seconds), nonzero exit, or network
error stops the listener and leaves unhandled events queued; a supervisor can restart it.

Example locally configured entrypoint:

```python
#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from dottalk.client import Client
from dottalk.demo import handle_demo_event

client = Client.from_profile(Path("/private/owner_a.agent.json"))
try:
    event = json.load(sys.stdin)
    # Replace with your agent runtime dispatch; never grant the human profile.
    handle_demo_event(client, event)
finally:
    client.close()
```

An MCP adapter can expose `create_request`, `get_request`, and owner preparation tools with
only an agent credential. A2A can carry these envelopes between runtimes. Neither transport
should expose human approval tools to the agent, add automatic approval, or forward OAuth
tokens. These protocol adapters are future work; the HTTP interface already works today.

## API reference

All `/v1` routes require `Authorization: Bearer <credential>`.

| Route | Authorized caller | Effect |
| --- | --- | --- |
| `GET /v1/me` | Any enrolled role | Identity, role, currently trusted peers |
| `POST /v1/requests` | Any enrolled role | Create a closed-schema request |
| `GET /v1/requests[/{id}]` | Participants | View permitted status/data |
| `POST /v1/requests/{id}/approve-read` | Owner human | Approve `{"digest": command_hash}` |
| `POST /v1/requests/{id}/claim` | Owner agent | Consume approved preparation once |
| `POST /v1/requests/{id}/prepare` | Owner agent after claim | Submit `{"records": [...]}` |
| `POST /v1/requests/{id}/approve-release` | Owner human | Approve `{"digest": release_hash}` |
| `POST /v1/requests/{id}/deny` | Owner human | Deny or revoke future result access |
| `POST /v1/requests/{id}/fail` | Owner agent during preparation | Close failed preparation |
| `GET /v1/events` | Any enrolled role | Own role's durable event inbox |
| `POST /v1/events/{id}/ack` | Event's exact owner/role | Acknowledge delivery |
| `POST /v1/peers/{peer}/revoke` | Human | Persistently revoke relationship and requests |
| `GET /v1/audit` | Owner human | Content-free action history for surviving requests |

Errors are sanitized: 401 authentication, 403 authorization, 404 unknown/inaccessible
resource, 409 wrong state/digest, 410 expired transition, 413 body too large, 422 invalid
schema/candidate, 429 quota. HTTP success must be checked; a failed claim never authorizes
source access. Display structured strings safely. Never let source text change tool policy.
