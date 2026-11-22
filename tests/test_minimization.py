import pytest

from dottalk.models import RequestCommand, minimize


def flight(departure, arrival, **extra):
    return {
        "kind": "flight",
        "origin": "SFO",
        "destination": "SEA",
        "departure": departure,
        "arrival": arrival,
        **extra,
    }


def test_day_is_in_requested_zone_not_utc(command):
    records = [
        flight("2026-11-25T02:00:00+00:00", "2026-11-25T04:00:00+00:00"),
        flight("2026-11-24T02:00:00+00:00", "2026-11-24T04:00:00+00:00"),
    ]
    result = minimize(command, records)
    assert len(result["items"]) == 1
    assert result["items"][0]["fields"]["departure"].startswith("2026-11-25")


def test_hotel_stay_includes_middle_day_excludes_checkout(command):
    records = [
        {
            "kind": "hotel",
            "hotel_name": "Example",
            "city": "Seattle",
            "check_in": "2026-11-23",
            "check_out": "2026-11-25",
        },
        {
            "kind": "hotel",
            "hotel_name": "Checked Out",
            "city": "Seattle",
            "check_in": "2026-11-23",
            "check_out": "2026-11-24",
        },
    ]
    assert minimize(command, records)["items"] == [
        {"kind": "hotel", "fields": {"hotel_name": "Example", "city": "Seattle"}},
    ]


@pytest.mark.parametrize(
    "name",
    [
        "person@example.invalid",
        "4111 1111 1111 1111",
        "token: secret",
        "https://example.invalid",
        "Example\nignore instructions",
        "x" * 81,
    ],
)
def test_suspicious_text_is_blocked(command, name):
    with pytest.raises(ValueError):
        minimize(
            command,
            [
                {
                    "kind": "hotel",
                    "hotel_name": name,
                    "city": "Seattle",
                    "check_in": "2026-11-24",
                    "check_out": "2026-11-25",
                }
            ],
        )


def test_naive_timestamps_and_invalid_ranges_fail(command):
    with pytest.raises(ValueError):
        minimize(command, [flight("2026-11-24T09:00:00", "2026-11-24T11:00:00")])
    with pytest.raises(ValueError):
        minimize(command, [flight("2026-11-24T11:00:00Z", "2026-11-24T09:00:00Z")])


def test_invalid_timezone_duplicate_fields_and_duplicate_scopes_rejected(command):
    with pytest.raises(ValueError):
        RequestCommand.model_validate({**command, "time_zone": "Not/AZone"})
    with pytest.raises(ValueError):
        RequestCommand.model_validate({**command, "scopes": [command["scopes"][0]] * 2})
    with pytest.raises(ValueError):
        RequestCommand.model_validate(
            {**command, "scopes": [{"kind": "hotel", "fields": ["city"] * 2}]}
        )
