"""Closed commands and deterministic minimization; no executable peer-supplied text."""

import hashlib
import json
import re
from datetime import date, datetime
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Kind = Literal["flight", "hotel", "card_reminder"]
FIELDS = {
    "flight": {"airline", "flight_number", "origin", "destination", "departure", "arrival"},
    "hotel": {"hotel_name", "city", "check_in", "check_out"},
    "card_reminder": {"issuer", "due_date"},
}


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Scope(StrictModel):
    kind: Kind
    fields: list[str] = Field(min_length=1, max_length=6)

    @model_validator(mode="after")
    def valid_fields(self):
        if len(set(self.fields)) != len(self.fields) or not set(self.fields) <= FIELDS[self.kind]:
            raise ValueError("Unsupported or duplicate fields")
        self.fields = sorted(self.fields)
        return self


class RequestCommand(StrictModel):
    target: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    date: date
    time_zone: str = Field(max_length=64)
    scopes: list[Scope] = Field(min_length=1, max_length=3)
    ttl_minutes: int = Field(default=30, ge=1, le=60, strict=True)

    @field_validator("time_zone")
    @classmethod
    def valid_zone(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("Unknown IANA time zone") from exc
        return value

    @model_validator(mode="after")
    def distinct_scopes(self):
        if len({s.kind for s in self.scopes}) != len(self.scopes):
            raise ValueError("Duplicate scopes")
        self.scopes.sort(key=lambda s: s.kind)
        return self


class Approval(StrictModel):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class Candidate(StrictModel):
    records: list[dict] = Field(max_length=50)


class EventAck(StrictModel):
    pass


def safe_text(value: object) -> str:
    """Defense in depth, NOT a guarantee that arbitrary text contains no personal data."""
    if not isinstance(value, str) or not 1 <= len(value) <= 80:
        raise ValueError("Invalid text field")
    if not re.fullmatch(r"[A-Za-z0-9 .,'&()/:-]+", value):
        raise ValueError("Unsupported characters in text field")
    if re.search(r"\d(?:[ -]?\d){6,}", value) or re.search(
        r"(?i)https?:|www\.|passport|password|secret|token|confirmation|booking code", value
    ):
        raise ValueError("Potential sensitive content")
    return value


def iso_day(value: object) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Expected ISO date")
    return date.fromisoformat(value)


def instant(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Expected timestamp")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Timestamp must include offset")
    return result


def minimize(command: dict, records: list[dict]) -> dict:
    """Filter by scope/date, project explicit fields, discard all other source keys.

    An owner-controlled adapter must establish source authenticity. This function cannot
    determine whether a hotel name is actually a person's name. The owner reviews bytes.
    """
    requested = {s["kind"]: s["fields"] for s in command["scopes"]}
    day = iso_day(command["date"])
    zone = ZoneInfo(command["time_zone"])
    items = []
    seen = set()
    for record in records:
        kind = record.get("kind")
        if not isinstance(kind, str) or kind not in requested:
            continue
        if kind == "flight":
            start, end = instant(record.get("departure")), instant(record.get("arrival"))
            if end < start:
                raise ValueError("Arrival precedes departure")
            if start.astimezone(zone).date() != day:
                continue
        elif kind == "hotel":
            start, end = iso_day(record.get("check_in")), iso_day(record.get("check_out"))
            if end <= start:
                raise ValueError("Invalid hotel stay")
            if not start <= day < end:
                continue
        elif iso_day(record.get("due_date")) != day:
            continue
        fields = {}
        for field in requested[kind]:
            value = record.get(field)
            if field in {"departure", "arrival"}:
                value = instant(value).isoformat()
            elif field in {"check_in", "check_out", "due_date"}:
                value = iso_day(value).isoformat()
            else:
                value = safe_text(value)
                if field in {"origin", "destination"} and not re.fullmatch(r"[A-Z]{3}", value):
                    raise ValueError("Expected three-letter airport code")
                if field == "flight_number" and not re.fullmatch(r"[A-Z0-9]{2,3} ?\d{1,4}", value):
                    raise ValueError("Invalid flight number")
            fields[field] = value
        item = {"kind": kind, "fields": fields}
        signature = canonical(item)
        if signature not in seen:
            seen.add(signature)
            items.append(item)
    items.sort(key=canonical)
    return {"date": command["date"], "time_zone": command["time_zone"], "items": items}
