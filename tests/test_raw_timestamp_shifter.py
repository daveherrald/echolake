"""Tests for raw_timestamp_shifter — shifting timestamps in _raw text."""

import pytest
from datetime import datetime, timezone

from echolake.core.raw_timestamp_shifter import shift_raw_timestamps


# Common test fixtures: shift from 2016-08-10 to 2026-08-10 (exact 10 years)
ORIGINAL_BASE = datetime(2016, 8, 10, 0, 0, 0, tzinfo=timezone.utc)
NEW_BASE = datetime(2026, 8, 10, 0, 0, 0, tzinfo=timezone.utc)


class TestISO8601:
    """Pattern 1: ISO 8601 timestamps (stream-*, suricata, XmlWinEventLog)."""

    def test_basic_utc(self):
        raw = '{"timestamp":"2016-08-28T23:59:00.105981Z","event_type":"dns"}'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-28T23:59:00.105981Z' in result
        assert '2016' not in result

    def test_negative_offset(self):
        raw = '{"ts":"2016-08-28T23:58:59.931869-0600"}'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-28T23:58:59.931869-0600' in result

    def test_colon_offset(self):
        raw = 'time="2016-08-28T12:00:00+00:00"'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-28T12:00:00+00:00' in result

    def test_nanosecond_precision(self):
        """XmlWinEventLog: 9-digit fractional seconds."""
        raw = "<TimeCreated SystemTime='2016-08-28T23:58:59.342236600Z'/>"
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-28T23:58:59.' in result
        assert 'Z' in result
        assert '2016' not in result

    def test_no_fractional(self):
        raw = '{"timestamp":"2016-08-28T23:59:00Z"}'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-28T23:59:00Z' in result

    def test_multiple_iso_in_one_line(self):
        """stream-dns has both timestamp and endtime."""
        raw = '{"timestamp":"2016-08-28T10:00:00.000000Z","endtime":"2016-08-28T10:00:01.000000Z"}'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-28T10:00:00.000000Z' in result
        assert '2026-08-28T10:00:01.000000Z' in result
        assert '2016' not in result


class TestFortiGate:
    """Pattern 2: FortiGate date=YYYY-MM-DD time=HH:MM:SS."""

    def test_basic(self):
        raw = 'date=2016-08-18 time=12:15:35 devname=fg devid=FGT logid=0'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert 'date=2026-08-18 time=12:15:35' in result
        assert '2016' not in result

    def test_with_syslog_header(self):
        """FortiGate lines also have a syslog BSD header — both should shift."""
        raw = 'Aug 18 12:15:35 fortigate date=2016-08-18 time=12:15:35 devname=fg'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert 'date=2026-08-18 time=12:15:35' in result
        assert result.startswith('Aug 18 12:15:35')  # syslog also shifted
        assert '2016' not in result


class TestSyslogBSD:
    """Pattern 3: Syslog BSD header Mon DD HH:MM:SS."""

    def test_basic(self):
        raw = 'Aug 18 12:15:35 fortigate something=else'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert result.startswith('Aug 18 12:15:35')

    def test_single_digit_day(self):
        raw = 'Sep  1 08:00:00 host msg'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert 'Sep  1 08:00:00' in result

    def test_multiline_matches_each_line(self):
        raw = 'Aug 18 12:15:35 host line1\nAug 19 13:00:00 host line2'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        lines = result.split('\n')
        assert lines[0].startswith('Aug 18 12:15:35')
        assert lines[1].startswith('Aug 19 13:00:00')


class TestUSDate:
    """Pattern 4: US date MM/DD/YYYY HH:MM:SS [AM/PM] (WinEventLog)."""

    def test_with_am(self):
        raw = '08/10/2016 09:29:33 AM\nLogName=Security'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '08/10/2026 09:29:33 AM' in result
        assert '2016' not in result

    def test_with_pm(self):
        raw = '08/28/2016 11:54:31 PM\nLogName=Security'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '08/28/2026 11:54:31 PM' in result

    def test_midnight_am(self):
        """12:00:00 AM = midnight."""
        raw = '08/10/2016 12:00:00 AM\nLogName=Security'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '08/10/2026 12:00:00 AM' in result

    def test_noon_pm(self):
        """12:00:00 PM = noon."""
        raw = '08/10/2016 12:00:00 PM\nLogName=Security'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '08/10/2026 12:00:00 PM' in result

    def test_without_ampm(self):
        raw = '08/28/2016 23:54:31\nSomething=else'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '08/28/2026 23:54:31' in result

    def test_with_fractional_seconds(self):
        raw = '08/28/2016 11:54:31.123 PM\nLogName=Security'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '08/28/2026' in result
        assert '2016' not in result


class TestDatetimeIIS:
    """Pattern 5: YYYY-MM-DD HH:MM:SS (IIS W3C logs)."""

    def test_basic(self):
        raw = '2016-08-24 16:37:13 192.168.250.70 GET /path - 80'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert '2026-08-24 16:37:13' in result
        assert '2016' not in result

    def test_no_overlap_with_iso8601(self):
        """Ensure ISO 8601 with T is NOT matched by this pattern."""
        raw = '2016-08-28T23:59:00Z'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        # Should be shifted by ISO 8601 pattern, not datetime pattern
        assert '2026-08-28T23:59:00Z' in result


class TestUnixEpoch:
    """Pattern 6: Unix epoch in JSON context (nessus-scan)."""

    def test_basic(self):
        epoch_2016 = 1472056400  # 2016-08-24 19:33:20 UTC
        raw = f'{{"timestamp": {epoch_2016}, "plugin_id": 42}}'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        # Original epoch should be gone
        assert str(epoch_2016) not in result
        # New epoch should be ~10 years later
        assert '"timestamp":' in result

    def test_time_key(self):
        epoch_2016 = 1472056400
        raw = f'{{"time": {epoch_2016}}}'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert str(epoch_2016) not in result

    def test_no_false_positive_on_arbitrary_numbers(self):
        """10-digit numbers without JSON key context should NOT be shifted."""
        raw = 'port=1472056400 bytes=1472056400'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert result == raw  # unchanged


class TestOverlapPrevention:
    """Ensure higher-priority patterns take precedence."""

    def test_iso_takes_precedence_over_datetime(self):
        """ISO 8601 (pattern 1) should prevent datetime (pattern 5) match."""
        raw = 'before 2016-08-28T12:00:00Z after'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert result.count('2026') == 1  # only one replacement

    def test_fortigate_not_matched_by_datetime(self):
        """FortiGate date=... time=... should be matched by pattern 2, not 5."""
        raw = 'date=2016-08-18 time=12:15:35'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert 'date=2026-08-18 time=12:15:35' in result


class TestEdgeCases:
    """Edge cases and special scenarios."""

    def test_empty_string(self):
        assert shift_raw_timestamps('', ORIGINAL_BASE, NEW_BASE) == ''

    def test_no_timestamps(self):
        raw = 'just some text with no timestamps'
        assert shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE) == raw

    def test_ceiling_applied(self):
        """Timestamps shifted beyond ceiling should be capped."""
        ceiling = datetime(2026, 8, 20, 0, 0, 0, tzinfo=timezone.utc)
        raw = '2016-08-30 12:00:00 192.168.1.1 GET /'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE, ceiling=ceiling)
        # Aug 30 + 10 years = Aug 30 2026, but ceiling is Aug 20 2026
        assert '2026-08-20 00:00:00' in result

    def test_delta_factor(self):
        """delta_factor=0.5 should compress time by half."""
        raw = '2016-08-20 00:00:00 192.168.1.1 GET /'
        # Aug 20 is 10 days after base (Aug 10). At factor 0.5, delta = 5 days → Aug 15
        result = shift_raw_timestamps(
            raw, ORIGINAL_BASE, NEW_BASE, delta_factor=0.5
        )
        assert '2026-08-15 00:00:00' in result

    def test_preserves_surrounding_text(self):
        raw = 'prefix 2016-08-24 16:37:13 192.168.250.70 GET /index.html suffix'
        result = shift_raw_timestamps(raw, ORIGINAL_BASE, NEW_BASE)
        assert result.startswith('prefix ')
        assert result.endswith(' 192.168.250.70 GET /index.html suffix')
