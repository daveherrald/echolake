"""Case entry alerts: README rendering and the Lakewatch loader.

A dataset case may carry an ``alert`` spec (see ``echolake.datasets.models.AlertSpec``). The
spec is the single source for two things:

* ``render_alert_section`` turns it into the README's alert section, so people read the same
  text the loader uses.
* ``create_case_alerts`` loads it into a Lakewatch catalog: it runs the evidence query, checks
  the count and the anchors, finds or creates the alert collection, creates the alert through
  the Lakewatch alert API (``alert-collections/*/alerts``), and returns a record suitable for a
  load manifest. It never creates detection rules, so a catalog loaded this way holds no rule
  signals, rule-born alerts, or rule names.

The Lakewatch alert-collection API is DEVELOPMENT stage. Two properties shape how these alerts
behave: they carry no linked events (the spec's evidence query is the record of what the alert
covers), and they do not appear in the unfiltered alert list (reach them by URL, seq id, or a
``parent=`` filter).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol

from echolake.datasets.models import AlertSpec, DatasetManifest, ScenarioCase

README_START = "<!-- echolake:alerts:start -->"
README_END = "<!-- echolake:alerts:end -->"


# ---------------------------------------------------------------------------- rendering

def _evidence_sql(spec: AlertSpec, catalog: str = "<catalog>", schema: str = "<schema>") -> str:
    ev = spec.evidence
    return (f"FROM {catalog}.{schema}.{ev.table}\n"
            f"|> WHERE {ev.where.strip()}\n"
            f"|> AGGREGATE count(*) AS events, min({ev.time_column}) AS first_seen, "
            f"max({ev.time_column}) AS last_seen")


def render_alert_section(manifest: DatasetManifest) -> str:
    """Markdown for every case that carries an alert spec, wrapped in the README markers."""
    lines = [README_START, "## Entry alerts", "",
             "Generated from the `alert` blocks in `dataset.yaml` by `echolake render-alerts`; edit "
             "the manifest, not this section. Each alert is created through the Lakewatch alert API "
             "by `echolake create-lakewatch-alerts`, which first confirms the evidence below is "
             "present in the loaded catalog. API-created alerts carry no linked events, so the "
             "description is the alert's full content.", ""]
    cases = [c for c in manifest.cases if c.alert is not None]
    if not cases:
        lines.append("This dataset defines no entry alerts.")
    for c in cases:
        a = c.alert
        ev = a.evidence
        tol = f" (plus or minus {ev.count_tolerance})" if ev.count_tolerance else ""
        lines += [
            f"### {c.id}", "",
            f"- **Title:** {a.title}",
            f"- **Severity:** {a.severity}",
            f"- **Description:** {a.description}",
            f"- **Expected disposition:** {c.disposition}",
            f"- **Detection rule:** [{c.rule.rsplit('/', 1)[-1]}]({c.rule})",
            f"- **Evidence:** {ev.expected_count} row(s){tol} in `{ev.table}`",
        ]
        if a.anchors:
            lines.append("- **Anchors:** " + ", ".join(f"`{x}`" for x in a.anchors))
        lines += ["", "```sql", _evidence_sql(a), "```", ""]
    lines.append(README_END)
    return "\n".join(lines) + "\n"


def update_readme(readme_text: str, section: str) -> str:
    """Replace the marked section, or append it when the markers are absent."""
    if README_START in readme_text and README_END in readme_text:
        head, rest = readme_text.split(README_START, 1)
        _, tail = rest.split(README_END, 1)
        return head + section.rstrip("\n") + tail
    sep = "" if readme_text.endswith("\n\n") else ("\n" if readme_text.endswith("\n") else "\n\n")
    return readme_text + sep + section


# ---------------------------------------------------------------------------- loader

class LakewatchClient(Protocol):
    """The calls the loader needs; ``DatabricksLakewatchClient`` implements them over the SDK."""

    def sql(self, statement: str) -> List[Dict[str, Any]]: ...

    def list_collections(self, catalog: str) -> List[Dict[str, Any]]: ...

    def create_collection(self, catalog: str, schema: str, name: str) -> Dict[str, Any]: ...

    def list_alerts(self, catalog: str, parent: str) -> List[Dict[str, Any]]: ...

    def create_alert(self, collection_name: str, body: Dict[str, Any]) -> Dict[str, Any]: ...


class AlertLoadError(RuntimeError):
    """Evidence check failed; no alert was created."""


def _lit(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _iso(v: Any) -> str:
    s = str(v)
    s = s.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", s) else s
    return s if s.endswith("Z") or "+" in s[10:] else s + "Z"


@dataclass
class EvidenceResult:
    events: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    anchors_missing: List[str] = field(default_factory=list)


def check_evidence(client: LakewatchClient, spec: AlertSpec, catalog: str, schema: str) -> EvidenceResult:
    ev = spec.evidence
    anchor_cols = "".join(
        f", count_if(contains(lower(to_json(struct(*))), lower({_lit(a)}))) AS anchor_{i}"
        for i, a in enumerate(spec.anchors))
    q = (f"FROM {catalog}.{schema}.{ev.table}\n|> WHERE {ev.where.strip()}\n"
         f"|> AGGREGATE count(*) AS events, min({ev.time_column}) AS first_seen, "
         f"max({ev.time_column}) AS last_seen{anchor_cols}")
    rows = client.sql(q)
    r = rows[0] if rows else {}
    events = int(r.get("events") or 0)
    missing = [a for i, a in enumerate(spec.anchors) if int(r.get(f"anchor_{i}") or 0) == 0]
    return EvidenceResult(events=events,
                          first_seen=_iso(r["first_seen"]) if r.get("first_seen") else None,
                          last_seen=_iso(r["last_seen"]) if r.get("last_seen") else None,
                          anchors_missing=missing)


def fill(template: str, ev: EvidenceResult) -> str:
    return (template.replace("{count}", str(ev.events))
            .replace("{first_seen}", ev.first_seen or "")
            .replace("{last_seen}", ev.last_seen or ""))


def create_case_alerts(client: LakewatchClient, manifest: DatasetManifest, catalog: str,
                       schema: str = "default", case_ids: Optional[Iterable[str]] = None,
                       dry_run: bool = False, alert_url_base: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check evidence and create the entry alert for each selected case. Returns one record per
    case (``status`` created, exists, would-create, or failed). Raises nothing for a single
    failed case; the record says why."""
    wanted = set(case_ids) if case_ids else None
    records: List[Dict[str, Any]] = []
    collections: Dict[str, str] = {}
    for case in manifest.cases:
        if case.alert is None or (wanted is not None and case.id not in wanted):
            continue
        spec = case.alert
        rec: Dict[str, Any] = {"case_id": case.id, "dataset": manifest.metadata.name,
                               "catalog": catalog, "schema": schema, "rule": case.rule,
                               "disposition": case.disposition, "collection_name": spec.collection}
        ev = check_evidence(client, spec, catalog, schema)
        rec["evidence"] = {"table": spec.evidence.table, "events": ev.events,
                           "expected": spec.evidence.expected_count,
                           "tolerance": spec.evidence.count_tolerance,
                           "first_seen": ev.first_seen, "last_seen": ev.last_seen}
        problems = []
        if abs(ev.events - spec.evidence.expected_count) > spec.evidence.count_tolerance:
            problems.append(f"evidence matched {ev.events} rows, expected {spec.evidence.expected_count}"
                            f" +/- {spec.evidence.count_tolerance}")
        if ev.anchors_missing:
            problems.append(f"anchors not found in evidence: {ev.anchors_missing}")
        if problems:
            rec.update(status="failed", error="; ".join(problems))
            records.append(rec)
            continue
        title, description = fill(spec.title, ev), fill(spec.description, ev)
        rec["title"] = title
        if dry_run:
            rec.update(status="would-create", description=description)
            records.append(rec)
            continue
        cname = collections.get(spec.collection)
        if cname is None:
            existing = [c for c in client.list_collections(catalog)
                        if c.get("alert_collection_name") == spec.collection and c.get("schema_name", schema) == schema]
            cname = existing[0]["name"] if existing else client.create_collection(catalog, schema, spec.collection)["name"]
            collections[spec.collection] = cname
        rec["collection"] = cname
        dup = [a for a in client.list_alerts(catalog, cname) if a.get("title") == title]
        if dup:
            a = dup[0]
            rec.update(status="exists")
        else:
            body = {"title": title, "description": description, "alert_type": spec.alert_type,
                    "severity": spec.severity, "alert_state": spec.alert_state,
                    "annotations": {"created_via": "echolake create-lakewatch-alerts", **spec.annotations}}
            a = client.create_alert(cname, body)
            rec.update(status="created")
        rec.update(alert_id=a.get("alert_id"), seq_id=a.get("seq_id"), name=a.get("name"),
                   create_time=a.get("create_time"))
        if alert_url_base and a.get("seq_id"):
            rec["url"] = f"{alert_url_base.rstrip('/')}/{a['seq_id']}"
        records.append(rec)
    return records


# ---------------------------------------------------------------------------- Databricks client

class DatabricksLakewatchClient:
    """``LakewatchClient`` over databricks-sdk with CLI-profile auth (no tokens handled here)."""

    def __init__(self, profile: Optional[str], warehouse_id: str):
        try:
            from databricks.sdk import WorkspaceClient
        except ImportError as e:  # pragma: no cover - exercised only without the extra
            raise RuntimeError('databricks-sdk is required: pip install "echolake[lakewatch]"') from e
        self.w = WorkspaceClient(profile=profile) if profile else WorkspaceClient()
        self.warehouse_id = warehouse_id

    def _do(self, method: str, path: str, query: Optional[dict] = None, body: Optional[dict] = None) -> Dict[str, Any]:
        # Unified (account-level) hosts route a raw request to a workspace only when it names the
        # workspace; without the header the Lakewatch API answers 503 TEMPORARILY_UNAVAILABLE,
        # which the SDK retries for minutes. The SDK's typed services add it themselves.
        headers = {"X-Databricks-Org-Id": str(self.w.config.workspace_id)} if getattr(self.w.config, "workspace_id", None) else None
        return self.w.api_client.do(method, path, query=query, body=body, headers=headers) or {}

    def sql(self, statement: str) -> List[Dict[str, Any]]:
        r = self.w.statement_execution.execute_statement(warehouse_id=self.warehouse_id, statement=statement,
                                                         wait_timeout="50s")
        state = r.status.state.value if r.status and r.status.state else "UNKNOWN"
        if state != "SUCCEEDED":
            msg = r.status.error.message if r.status and r.status.error else state
            raise AlertLoadError(f"evidence query failed: {msg}")
        cols = [c.name for c in r.manifest.schema.columns]
        return [dict(zip(cols, row)) for row in (r.result.data_array or [])] if r.result else []

    def list_collections(self, catalog: str) -> List[Dict[str, Any]]:
        out, tok = [], None
        while True:
            q = {"catalog_name": catalog, **({"page_token": tok} if tok else {})}
            d = self._do("GET", "/api/2.0/lakewatch/alert-collections", query=q)
            out += d.get("alert_collections", [])
            tok = d.get("next_page_token")
            if not tok:
                return out

    def create_collection(self, catalog: str, schema: str, name: str) -> Dict[str, Any]:
        return self._do("POST", "/api/2.0/lakewatch/alert-collections",
                        body={"catalog_name": catalog, "schema_name": schema, "alert_collection_name": name})

    def list_alerts(self, catalog: str, parent: str) -> List[Dict[str, Any]]:
        out, tok = [], None
        while True:
            q = {"catalog_name": catalog, "parent": parent, "page_size": 100, **({"page_token": tok} if tok else {})}
            d = self._do("GET", "/api/2.0/lakewatch/alerts", query=q)
            out += d.get("alerts", [])
            tok = d.get("next_page_token")
            if not tok:
                return out

    def create_alert(self, collection_name: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._do("POST", f"/api/2.0/lakewatch/{collection_name}/alerts", body=body)


def record_in_load_manifest(client: LakewatchClient, table: str, load_id: str, records: List[Dict[str, Any]]) -> int:
    """Merge created/existing alert records into ``artifact.entry_alerts`` of one load_manifests row,
    replacing any prior record for the same case. Returns the number of rows updated (0 or 1)."""
    rows = client.sql(f"FROM {table}\n|> WHERE load_id = {_lit(load_id)}\n|> SELECT artifact")
    if not rows:
        return 0
    art = json.loads(rows[0]["artifact"] or "{}")
    keep = {r["case_id"] for r in records if r.get("status") in ("created", "exists")}
    prior = [e for e in art.get("entry_alerts", []) if e.get("case_id") not in keep]
    art["entry_alerts"] = prior + [r for r in records if r.get("status") in ("created", "exists")]
    client.sql(f"UPDATE {table} SET artifact = {_lit(json.dumps(art, sort_keys=True))} WHERE load_id = {_lit(load_id)}")
    return 1
