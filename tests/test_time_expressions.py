"""Tests for time expression parsing and resolution."""

import pytest
from datetime import datetime, timedelta, timezone

from echolake.utils.time import (
    parse_time_expression,
    TimeExpression,
    _unit_to_seconds,
)


class TestUnitConversion:
    """Test time unit conversion."""

    def test_seconds(self):
        assert _unit_to_seconds(30, 's') == 30

    def test_minutes(self):
        assert _unit_to_seconds(5, 'm') == 300

    def test_hours(self):
        assert _unit_to_seconds(2, 'h') == 7200

    def test_days(self):
        assert _unit_to_seconds(1, 'd') == 86400

    def test_weeks(self):
        assert _unit_to_seconds(2, 'w') == 1209600

    def test_months(self):
        assert _unit_to_seconds(1, 'mon') == 2592000

    def test_years(self):
        assert _unit_to_seconds(1, 'y') == 31536000

    def test_invalid_unit(self):
        with pytest.raises(ValueError, match="Unknown time unit"):
            _unit_to_seconds(1, 'x')


class TestTimeExpressionParsing:
    """Test parsing of time expressions."""

    def test_parse_simple_now(self):
        expr = parse_time_expression("now")
        assert expr.base == "now"
        assert expr.offsets == []

    def test_parse_simple_earliest(self):
        expr = parse_time_expression("earliest")
        assert expr.base == "earliest"
        assert expr.offsets == []

    def test_parse_simple_latest(self):
        expr = parse_time_expression("latest")
        assert expr.base == "latest"
        assert expr.offsets == []

    def test_parse_iso8601_timestamp(self):
        expr = parse_time_expression("2024-01-15T10:00:00Z")
        assert expr.base == "2024-01-15T10:00:00Z"
        assert expr.offsets == []

    def test_parse_iso8601_with_offset(self):
        expr = parse_time_expression("2024-01-15T10:00:00+05:00")
        assert expr.base == "2024-01-15T10:00:00+05:00"
        assert expr.offsets == []

    def test_parse_now_minus_2h(self):
        expr = parse_time_expression("now-2h")
        assert expr.base == "now"
        assert expr.offsets == [("-", 7200)]

    def test_parse_now_plus_1d(self):
        expr = parse_time_expression("now+1d")
        assert expr.base == "now"
        assert expr.offsets == [("+", 86400)]

    def test_parse_earliest_plus_1h(self):
        expr = parse_time_expression("earliest+1h")
        assert expr.base == "earliest"
        assert expr.offsets == [("+", 3600)]

    def test_parse_latest_minus_30m(self):
        expr = parse_time_expression("latest-30m")
        assert expr.base == "latest"
        assert expr.offsets == [("-", 1800)]

    def test_parse_complex_expression(self):
        expr = parse_time_expression("now-1d-12h-30m")
        assert expr.base == "now"
        assert len(expr.offsets) == 3
        # 1d = 86400, 12h = 43200, 30m = 1800
        assert expr.offsets[0] == ("-", 86400)
        assert expr.offsets[1] == ("-", 43200)
        assert expr.offsets[2] == ("-", 1800)

    def test_parse_multiple_same_units(self):
        expr = parse_time_expression("now-2h-3h")
        assert expr.base == "now"
        assert len(expr.offsets) == 2
        assert expr.offsets[0] == ("-", 7200)
        assert expr.offsets[1] == ("-", 10800)

    def test_parse_mixed_signs(self):
        expr = parse_time_expression("now+1d-12h")
        assert expr.base == "now"
        assert len(expr.offsets) == 2
        assert expr.offsets[0] == ("+", 86400)
        assert expr.offsets[1] == ("-", 43200)

    def test_parse_all_units(self):
        expr = parse_time_expression("now-1y-1mon-1w-1d-1h-1m-1s")
        assert expr.base == "now"
        assert len(expr.offsets) == 7

    def test_parse_invalid_expression(self):
        with pytest.raises(ValueError, match="Invalid time expression"):
            parse_time_expression("invalid-expression")

    def test_parse_invalid_base(self):
        with pytest.raises(ValueError, match="Invalid time expression"):
            parse_time_expression("future+1d")

    def test_parse_invalid_unit(self):
        with pytest.raises(ValueError, match="Invalid time expression"):
            parse_time_expression("now-1x")


class TestTimeExpressionResolution:
    """Test resolution of time expressions to datetime."""

    def test_resolve_now(self):
        expr = parse_time_expression("now")
        before = datetime.now(timezone.utc)
        result = expr.resolve()
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    def test_resolve_now_with_offset(self):
        expr = parse_time_expression("now-2h")
        before = datetime.now(timezone.utc) - timedelta(hours=2)
        result = expr.resolve()
        after = datetime.now(timezone.utc) - timedelta(hours=2)
        # Allow small timing difference
        assert abs((result - before).total_seconds()) < 2
        assert abs((result - after).total_seconds()) < 2

    def test_resolve_earliest(self):
        earliest = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        latest = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

        expr = parse_time_expression("earliest")
        result = expr.resolve(earliest=earliest, latest=latest)

        assert result == earliest

    def test_resolve_latest(self):
        earliest = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        latest = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

        expr = parse_time_expression("latest")
        result = expr.resolve(earliest=earliest, latest=latest)

        assert result == latest

    def test_resolve_earliest_plus_offset(self):
        earliest = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        latest = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

        expr = parse_time_expression("earliest+1h")
        result = expr.resolve(earliest=earliest, latest=latest)

        expected = datetime(2024, 1, 1, 13, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_resolve_latest_minus_offset(self):
        earliest = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        latest = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

        expr = parse_time_expression("latest-30m")
        result = expr.resolve(earliest=earliest, latest=latest)

        expected = datetime(2024, 1, 2, 11, 30, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_resolve_complex_offset(self):
        earliest = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        latest = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

        expr = parse_time_expression("earliest+1d+12h+30m")
        result = expr.resolve(earliest=earliest, latest=latest)

        # 1d + 12h + 30m = 36.5 hours from earliest
        expected = earliest + timedelta(days=1, hours=12, minutes=30)
        assert result == expected

    def test_resolve_iso8601(self):
        expr = parse_time_expression("2024-01-15T10:00:00Z")
        result = expr.resolve()

        expected = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_resolve_earliest_without_data(self):
        expr = parse_time_expression("earliest")
        with pytest.raises(ValueError, match="Cannot resolve 'earliest' without event data"):
            expr.resolve()

    def test_resolve_latest_without_data(self):
        expr = parse_time_expression("latest")
        with pytest.raises(ValueError, match="Cannot resolve 'latest' without event data"):
            expr.resolve()


class TestTimeExpressionEdgeCases:
    """Test edge cases for time expressions."""

    def test_case_insensitive(self):
        expr1 = parse_time_expression("NOW")
        expr2 = parse_time_expression("EARLIEST")
        expr3 = parse_time_expression("LATEST")

        assert expr1.base == "now"
        assert expr2.base == "earliest"
        assert expr3.base == "latest"

    def test_zero_offset(self):
        expr = parse_time_expression("now-0h")
        assert expr.offsets == [("-", 0)]

    def test_large_offset(self):
        expr = parse_time_expression("now-100y")
        assert expr.offsets == [("-", 3153600000)]  # 100 * 365 * 86400

    def test_alternating_signs(self):
        expr = parse_time_expression("now+1d-2h+30m-15s")
        assert len(expr.offsets) == 4
        assert expr.offsets[0] == ("+", 86400)
        assert expr.offsets[1] == ("-", 7200)
        assert expr.offsets[2] == ("+", 1800)
        assert expr.offsets[3] == ("-", 15)
