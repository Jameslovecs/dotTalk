"""Entirely fictional connector. No network, Gmail, card account, or purchase access."""

from dottalk.models import minimize


def synthetic_records(command):
    # Fixed dates let the demo exercise exclusion of unrelated reservations.
    return [
        {
            "kind": "flight",
            "airline": "Example Air",
            "flight_number": "EX204",
            "origin": "SFO",
            "destination": "SEA",
            "departure": "2026-11-24T09:00:00-08:00",
            "arrival": "2026-11-24T11:00:00-08:00",
            "traveler_name": "Synthetic Person",
            "email": "synthetic@example.invalid",
            "confirmation_code": "DO-NOT-SHARE",
        },
        {
            "kind": "hotel",
            "hotel_name": "Example Harbor Hotel",
            "city": "Seattle",
            "check_in": "2026-11-24",
            "check_out": "2026-11-26",
            "room_number": "999",
            "guest_name": "Synthetic Person",
            "confirmation_code": "DO-NOT-SHARE",
        },
        {
            "kind": "hotel",
            "hotel_name": "Unrelated Example Hotel",
            "city": "Portland",
            "check_in": "2026-12-01",
            "check_out": "2026-12-02",
        },
        {
            "kind": "card_reminder",
            "issuer": "Example Bank",
            "due_date": "2026-11-24",
            "card_number": "SYNTHETIC-NOT-A-CARD",
            "balance": "DO-NOT-SHARE",
        },
    ]


def local_projection(command, records):
    """Minimize locally before the broker sees a candidate; retain filter evidence only."""
    filters = {
        "flight": {"departure", "arrival"},
        "hotel": {"check_in", "check_out"},
        "card_reminder": {"due_date"},
    }
    scopes = {s["kind"]: set(s["fields"]) for s in command["scopes"]}
    result = []
    for record in records:
        kind = record.get("kind")
        if not isinstance(kind, str) or kind not in scopes:
            continue
        if not minimize(command, [record])["items"]:
            continue
        allowed = scopes[kind] | filters[kind] | {"kind"}
        result.append({key: value for key, value in record.items() if key in allowed})
    return result


def handle_demo_event(client, event):
    if event["kind"] != "read.approved":
        return
    request_id = event["request_id"]
    state = client.get_request(request_id)["state"]
    if state == "preparing":
        # A prior process crashed after claiming. Do not repeat a source read blindly.
        client.call("POST", f"/v1/requests/{request_id}/fail")
        return
    if state != "read_approved":
        return
    claim = client.claim(request_id)  # Must succeed BEFORE accessing any source.
    try:
        records = local_projection(claim["command"], synthetic_records(claim["command"]))
        client.prepare(request_id, records)
    except Exception:
        client.call("POST", f"/v1/requests/{request_id}/fail")
        raise
