"""Tests for the Splunk HEC output destination."""

import gzip
import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from echolake.outputs.destinations.splunk_hec import SplunkHECDestination
from echolake.outputs.destinations import get_destination


URL = "https://http-inputs-example.splunkcloud.com/services/collector"


def _mk(**kw):
    kw.setdefault("hec_url", URL)
    kw.setdefault("token", "tok")
    return SplunkHECDestination(**kw)


class TestEndpointAndEpoch:
    def test_endpoint_appends_event_path(self):
        d = _mk(hec_url="https://x.splunkcloud.com", dry_run=True)
        assert d.endpoint == "https://x.splunkcloud.com/services/collector/event"

    def test_endpoint_raw_path(self):
        d = _mk(hec_url="https://x.splunkcloud.com", use_raw_endpoint=True, dry_run=True)
        assert d.endpoint == "https://x.splunkcloud.com/services/collector/raw"

    def test_endpoint_preserved_when_already_full(self):
        d = _mk(dry_run=True)
        assert d.endpoint == URL

    def test_to_epoch_numeric(self):
        assert SplunkHECDestination._to_epoch(1740808471) == 1740808471.0
        assert SplunkHECDestination._to_epoch("1740808471.5") == 1740808471.5

    def test_to_epoch_iso(self):
        assert SplunkHECDestination._to_epoch("2025-03-01T05:54:31+00:00") == pytest.approx(1740808471.0)

    def test_to_epoch_iso_z(self):
        assert SplunkHECDestination._to_epoch("2025-03-01T05:54:31Z") == pytest.approx(1740808471.0)

    def test_to_epoch_invalid(self):
        assert SplunkHECDestination._to_epoch(None) is None
        assert SplunkHECDestination._to_epoch("not-a-time") is None


class TestEnvelope:
    def test_dict_maps_raw_and_fields(self):
        d = _mk(index="bots", dry_run=True)
        line = json.dumps({
            "_time": "2025-03-01T05:54:31+00:00", "_raw": "hello world",
            "host": "h1", "source": "s1", "sourcetype": "WinEventLog:Application",
        })
        env = d._build_envelope(line, None)
        assert env["event"] == "hello world"
        assert env["host"] == "h1"
        assert env["source"] == "s1"
        assert env["sourcetype"] == "WinEventLog:Application"
        assert env["index"] == "bots"
        assert env["time"] == pytest.approx(1740808471.0)

    def test_non_dict_line_sent_verbatim(self):
        d = _mk(dry_run=True)
        env = d._build_envelope("plain log line", "syslog")
        assert env["event"] == "plain log line"
        assert env["sourcetype"] == "syslog"  # from per-file metadata
        assert "time" not in env

    def test_overrides_win(self):
        d = _mk(sourcetype_override="forced", source_override="src", default_host="H", dry_run=True)
        line = json.dumps({"_raw": "x", "host": "orig", "sourcetype": "orig_st"})
        env = d._build_envelope(line, None)
        assert env["sourcetype"] == "forced"
        assert env["source"] == "src"
        assert env["host"] == "H"

    def test_object_event_when_no_raw(self):
        d = _mk(dry_run=True)
        env = d._build_envelope(json.dumps({"a": 1, "sourcetype": "st"}), None)
        assert env["event"] == {"a": 1, "sourcetype": "st"}


def _patch_requests():
    """Return (patcher, captured) where captured collects posted (decompressed) bodies."""
    captured = []
    lock = threading.Lock()

    def post(self, url, data=None, params=None, timeout=None, verify=None):
        with lock:
            captured.append(gzip.decompress(data).decode("utf-8"))
        resp = MagicMock()
        resp.status_code = 200
        return resp

    session = MagicMock()
    session.post = post.__get__(session)
    session.headers = {}
    fake_requests = MagicMock()
    fake_requests.Session.return_value = session
    fake_requests.RequestException = Exception
    return patch("echolake.outputs.destinations.splunk_hec.requests", fake_requests), captured


class TestWrite:
    def _events(self, n):
        return [json.dumps({"_time": 1700000000 + i, "_raw": f"evt{i}",
                            "host": "h", "sourcetype": "st"}) for i in range(n)]

    def test_sync_write_posts_all(self):
        patcher, captured = _patch_requests()
        with patcher:
            d = _mk(index="bots", batch_size=10)
            d.write("f", self._events(25))
            d.close()
        posted = "\n".join(captured)
        assert d.events_sent == 25
        assert d.events_failed == 0
        assert posted.count('"event": "evt') == 25
        assert '"index": "bots"' in posted

    def test_parallel_write_posts_all(self):
        patcher, captured = _patch_requests()
        with patcher:
            d = _mk(index="bots", batch_size=10, max_workers=4)
            assert d._executor is not None
            for i in range(4):
                d.write(f"f{i}", self._events(50))
            d.close()  # joins the pool
        total = "\n".join(captured).count('"event": "evt')
        assert d.events_sent == 200
        assert d.events_failed == 0
        assert total == 200

    def test_factory_registers_hec(self):
        d = get_destination("splunk_hec", hec_url=URL, token="t", dry_run=True)
        assert isinstance(d, SplunkHECDestination)
        d2 = get_destination("hec", hec_url=URL, token="t", dry_run=True)
        assert isinstance(d2, SplunkHECDestination)

    def test_dry_run_counts_without_session(self):
        d = _mk(index="bots", dry_run=True, batch_size=5)
        d.write("f", self._events(12))
        d.close()
        assert d.events_sent == 12
        assert d.requests_sent == 0
