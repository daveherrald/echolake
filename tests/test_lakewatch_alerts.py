"""Tests for case alert specs: model validation, README rendering, and the Lakewatch loader."""

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from echolake.datasets.models import DatasetManifest
from echolake.lakewatch.alerts import (
    README_END,
    README_START,
    create_case_alerts,
    record_in_load_manifest,
    render_alert_section,
    update_readme,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"

ALERT = {
    "title": "Outbound connections to 121.43.243.13 from 192.168.4.233",
    "description": "{count} outbound connections to 121.43.243.13 between {first_seen} and {last_seen}. "
                   "A threat-intel match is a pivot, not a verdict.",
    "severity": "Medium",
    "anchors": ["121.43.243.13", "192.168.4.233"],
    "evidence": {"table": "zeek_conn", "where": "`id.resp_h` = '121.43.243.13'", "expected_count": 38},
}


def manifest_with(alert=ALERT, extra_cases=()):
    data = yaml.safe_load(FIXTURE.read_text())
    case = {"id": "c2-entry", "name": "C2 indicator", "rule": "https://example.com/rules/sigma/c2.yml",
            "disposition": "true-positive"}
    if alert is not None:
        case["alert"] = alert
    data["cases"] = [case, *extra_cases]
    return DatasetManifest.model_validate(data)


# ------------------------------------------------------------------ model

def test_alert_spec_parses_with_defaults():
    a = manifest_with().cases[0].alert
    assert a.alert_type == "SECURITY_ALERT" and a.alert_state == "OPEN" and a.collection == "triage_queue"
    assert a.evidence.time_column == "time" and a.evidence.count_tolerance == 0


def test_alert_optional():
    assert manifest_with(alert=None).cases[0].alert is None


@pytest.mark.parametrize("patch,match", [
    ({"severity": "Severe"}, "severity"),
    ({"title": "Hits on {host}"}, "placeholder"),
    ({"description": "unbalanced {count"}, "brace"),
    ({"collection": "triage queue"}, "collection"),
    ({"anchors": [""]}, "anchors"),
    ({"evidence": {**ALERT["evidence"], "where": "x = 1; DROP TABLE t"}}, "single predicate"),
    ({"evidence": {**ALERT["evidence"], "table": "a.b"}}, "identifier"),
    ({"evidence": {**ALERT["evidence"], "expected_count": 0}}, "expected_count"),
    ({"unknown_field": 1}, "unknown_field"),
])
def test_alert_spec_rejects(patch, match):
    with pytest.raises(ValidationError, match=match):
        manifest_with(alert={**ALERT, **patch})


# ------------------------------------------------------------------ rendering

def test_render_section_has_markers_and_evidence():
    s = render_alert_section(manifest_with())
    assert s.startswith(README_START) and s.rstrip().endswith(README_END)
    assert "### c2-entry" in s and "**Severity:** Medium" in s
    assert "|> WHERE `id.resp_h` = '121.43.243.13'" in s and "38 row(s)" in s


def test_update_readme_appends_then_replaces_idempotently():
    m = manifest_with()
    once = update_readme("# Title\n\nBody.\n", render_alert_section(m))
    assert once.count(README_START) == 1 and once.startswith("# Title")
    assert update_readme(once, render_alert_section(m)) == once
    m2 = manifest_with(alert={**ALERT, "severity": "High"})
    twice = update_readme(once, render_alert_section(m2))
    assert twice.count(README_START) == 1 and "**Severity:** High" in twice and "**Severity:** Medium" not in twice


# ------------------------------------------------------------------ loader

class FakeClient:
    def __init__(self, events=38, anchors=(5, 3), collections=(), alerts=()):
        self.events, self.anchors = events, anchors
        self.collections = list(collections)
        self.alerts = list(alerts)
        self.sql_log, self.created = [], []
        self.manifest_rows = {"load-1": json.dumps({"entry_alerts": [{"case_id": "c2-entry", "seq_id": "sec-old"},
                                                                     {"case_id": "other", "seq_id": "sec-9"}]})}

    def sql(self, statement):
        self.sql_log.append(statement)
        if statement.startswith("UPDATE"):
            self.updated = statement
            return []
        if "load_manifests" in statement:
            lid = statement.split("load_id = '")[1].split("'")[0]
            return [{"artifact": self.manifest_rows[lid]}] if lid in self.manifest_rows else []
        row = {"events": str(self.events), "first_seen": "2026-11-02 01:25:12.881", "last_seen": "2026-11-02 01:25:12.881"}
        row.update({f"anchor_{i}": str(n) for i, n in enumerate(self.anchors)})
        return [row]

    def list_collections(self, catalog):
        return self.collections

    def create_collection(self, catalog, schema, name):
        c = {"name": "alert-collections/new-1", "alert_collection_name": name, "schema_name": schema}
        self.collections.append(c)
        return c

    def list_alerts(self, catalog, parent):
        return [a for a in self.alerts if a.get("parent") == parent]

    def create_alert(self, collection_name, body):
        self.created.append((collection_name, body))
        a = {"alert_id": "aid-1", "seq_id": "sec-100", "name": f"{collection_name}/alerts/aid-1",
             "create_time": "2026-11-10T00:00:00Z", "parent": collection_name, **body}
        self.alerts.append(a)
        return a


def test_loader_creates_collection_and_alert_with_filled_text():
    c = FakeClient()
    [r] = create_case_alerts(c, manifest_with(), "currentis_soc", alert_url_base="https://lw/alerts")
    assert r["status"] == "created" and r["seq_id"] == "sec-100" and r["url"] == "https://lw/alerts/sec-100"
    assert r["collection"] == "alert-collections/new-1"
    _, body = c.created[0]
    assert body["description"].startswith("38 outbound connections") and "2026-11-02T01:25:12.881Z" in body["description"]
    assert body["alert_state"] == "OPEN" and body["annotations"]["created_via"].startswith("echolake")
    q = c.sql_log[0]
    assert q.startswith("FROM currentis_soc.default.zeek_conn") and "|> AGGREGATE count(*) AS events" in q
    assert "lower('121.43.243.13')" in q


def test_loader_reuses_existing_collection_and_skips_duplicate_title():
    coll = {"name": "alert-collections/c-1", "alert_collection_name": "triage_queue", "schema_name": "default"}
    prior = {"parent": "alert-collections/c-1", "title": ALERT["title"], "alert_id": "aid-0", "seq_id": "sec-50"}
    c = FakeClient(collections=[coll], alerts=[prior])
    [r] = create_case_alerts(c, manifest_with(), "currentis_soc")
    assert r["status"] == "exists" and r["seq_id"] == "sec-50" and not c.created


@pytest.mark.parametrize("kw,needle", [({"events": 37}, "matched 37 rows"), ({"anchors": (5, 0)}, "192.168.4.233")])
def test_loader_refuses_when_evidence_is_wrong(kw, needle):
    c = FakeClient(**kw)
    [r] = create_case_alerts(c, manifest_with(), "currentis_soc")
    assert r["status"] == "failed" and needle in r["error"] and not c.created and not c.collections


def test_loader_tolerance_and_dry_run():
    c = FakeClient(events=40)
    m = manifest_with(alert={**ALERT, "evidence": {**ALERT["evidence"], "count_tolerance": 2}})
    [r] = create_case_alerts(c, m, "currentis_soc", dry_run=True)
    assert r["status"] == "would-create" and not c.created and not c.collections


def test_loader_case_filter_and_cases_without_alert():
    extra = {"id": "no-alert", "name": "n", "rule": "r.yml", "disposition": "benign-positive"}
    c = FakeClient()
    assert create_case_alerts(c, manifest_with(extra_cases=[extra]), "x", case_ids=["no-alert"]) == []
    assert len(create_case_alerts(FakeClient(), manifest_with(extra_cases=[extra]), "x")) == 1


def test_record_in_load_manifest_replaces_same_case_only():
    c = FakeClient()
    recs = create_case_alerts(c, manifest_with(), "currentis_soc")
    assert record_in_load_manifest(c, "ops.ingest.load_manifests", "load-1", recs) == 1
    art = json.loads(c.updated.split("SET artifact = '", 1)[1].rsplit("' WHERE", 1)[0].replace("\\'", "'").replace("\\\\", "\\"))
    seqs = {e["case_id"]: e["seq_id"] for e in art["entry_alerts"]}
    assert seqs == {"other": "sec-9", "c2-entry": "sec-100"}
    assert record_in_load_manifest(c, "ops.ingest.load_manifests", "missing", recs) == 0
