"""Round-trip tests for the scenario blocks and the Attack Flow builder.

A manifest with entities, observables, and kill_chain is turned into a STIX 2.1
bundle carrying the Attack Flow 2.0.0 extension. These tests pin the structure
(one action per technique, one asset per entity, indicators for marked
observables, the relationship types that attach them), determinism, and
validation against the Attack Flow schema when the validator is installed.
"""

import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

from echolake.datasets.attack_flow_build import (
    AttackFlowBuildError,
    build_attack_flow,
    write_attack_flow,
)
from echolake.datasets.models import DatasetManifest

SHA256 = "a" * 64

SAMPLE = {
    "metadata": {
        "name": "sample-scenario",
        "version": "1.0.0",
        "description": "A synthetic four-stage intrusion used to exercise the scenario blocks.",
        "created": "2026-10-20",
        "timestamp_range": {"earliest": "2026-01-01T10:00:00Z", "latest": "2026-01-01T11:00:00Z"},
        "mitre_attack": {
            "techniques": [
                {"id": "T1566", "name": "Phishing", "tactics": ["initial-access"]},
                {"id": "T1204", "name": "User Execution", "tactics": ["execution"]},
                {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactics": ["persistence"]},
                {"id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"]},
                {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactics": ["lateral-movement"]},
            ]
        },
    },
    "entities": [
        {"id": "ws-01", "type": "infrastructure", "name": "CORP-WS-01", "role": "patient-zero",
         "description": "Engineering workstation", "infrastructure_types": ["workstation"],
         "observables": ["ws-01-ip", "ws-01-fqdn"]},
        {"id": "dc-01", "type": "infrastructure", "name": "CORP-DC-01", "role": "target",
         "infrastructure_types": ["domain-controller"], "observables": []},
        {"id": "alice", "type": "user-account", "account_login": "alice", "account_type": "windows-domain",
         "name": "Alice Example", "role": "victim"},
        {"id": "svc-backup", "type": "user-account", "account_login": "svc-backup",
         "account_type": "windows-domain", "is_service_account": True, "role": "compromised-service"},
        {"id": "acme", "type": "identity", "name": "ACME Corp", "identity_class": "organization",
         "sectors": ["technology"]},
        {"id": "actor", "type": "threat-actor", "name": "SAMPLE ACTOR", "threat_actor_types": ["crime-syndicate"]},
        {"id": "c2", "type": "infrastructure", "name": "Sample C2", "role": "attacker",
         "infrastructure_types": ["command-and-control"], "observables": ["c2-ip", "c2-url"]},
    ],
    "observables": [
        {"id": "ws-01-ip", "type": "ipv4-addr", "value": "10.20.30.40"},
        {"id": "ws-01-fqdn", "type": "domain-name", "value": "corp-ws-01.example.test"},
        {"id": "c2-ip", "type": "ipv4-addr", "value": "203.0.113.9", "indicator_types": ["malicious-activity"],
         "kill_chain_phases": ["command-and-control"], "techniques": ["T1071.001"], "confidence": 70,
         "first_seen": "2026-01-01T10:20:00Z", "description": "Beacon destination"},
        {"id": "c2-url", "type": "url", "value": "http://203.0.113.9/push", "indicator_types": ["malicious-activity"],
         "kill_chain_phases": ["command-and-control"], "techniques": ["T1071.001"]},
        {"id": "dropper", "type": "file", "name": "update-helper.exe", "hashes": {"SHA-256": SHA256},
         "indicator_types": ["malicious-activity"], "kill_chain_phases": ["execution"], "techniques": ["T1204"]},
        {"id": "runkey", "type": "windows-registry-key",
         "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "values": [{"name": "UpdateHelper", "data": "C:\\Users\\alice\\update-helper.exe", "data_type": "REG_SZ"}],
         "indicator_types": ["malicious-activity"], "kill_chain_phases": ["persistence"], "techniques": ["T1547.001"]},
        {"id": "pipe", "type": "indicator", "name": "Suspicious named pipe", "pattern_type": "sigma",
         "pattern": "logsource: {category: pipe_created, product: windows}\ndetection: {selection: {PipeName: '\\\\sample-pipe'}, condition: selection}",
         "indicator_types": ["malicious-activity"], "kill_chain_phases": ["lateral-movement"], "techniques": ["T1021.001"]},
    ],
    "kill_chain": [
        {"id": "S0", "name": "Initial access", "tactic": "initial-access", "techniques": ["T1566", "T1204"],
         "assets": ["ws-01", "alice"], "observables": ["dropper"],
         "execution_start": "2026-01-01T10:00:00Z", "execution_end": "2026-01-01T10:05:00Z",
         "description": "A phishing message delivers the dropper, which alice runs."},
        {"id": "S1", "name": "Persistence", "tactic": "persistence", "techniques": ["T1547.001"],
         "assets": ["ws-01"], "observables": ["runkey"], "execution_start": "2026-01-01T10:06:00Z"},
        {"id": "S2", "name": "Beacon", "tactic": "command-and-control", "techniques": ["T1071.001"],
         "assets": ["ws-01", "c2"], "observables": ["c2-ip", "c2-url"], "execution_start": "2026-01-01T10:20:00Z"},
        {"id": "S3", "name": "Lateral movement", "tactic": "lateral-movement", "techniques": ["T1021.001"],
         "assets": ["ws-01", "dc-01", "svc-backup"], "observables": ["pipe"], "execution_start": "2026-01-01T10:40:00Z"},
    ],
}


def _types(bundle):
    return Counter(o["type"] for o in bundle["objects"])


def _by_type(bundle, t):
    return [o for o in bundle["objects"] if o["type"] == t]


def test_bundle_structure():
    bundle = build_attack_flow(DatasetManifest.model_validate(SAMPLE))
    t = _types(bundle)
    assert t["attack-flow"] == 1
    assert t["attack-action"] == 5  # S0 has two techniques
    assert t["attack-asset"] == 7  # one per entity
    assert t["attack-pattern"] == 5
    # SCOs: 2 host observables + c2-ip + c2-url + file + regkey, plus 2 user-account entities
    assert t["ipv4-addr"] == 2 and t["domain-name"] == 1 and t["url"] == 1
    assert t["file"] == 1 and t["windows-registry-key"] == 1 and t["user-account"] == 2
    # indicators: 4 marked observables + the sigma one
    assert t["indicator"] == 5
    assert t["extension-definition"] == 1 and t["identity"] == 3  # CTID, EchoLake, ACME
    rels = Counter(r["relationship_type"] for r in _by_type(bundle, "relationship"))
    assert rels["consists-of"] == 4  # ws-01 (2) + c2 (2)
    assert rels["based-on"] == 4  # one per SCO-backed indicator
    assert rels["indicates"] == 2  # c2-ip and c2-url indicate the C2 infrastructure
    assert rels["related-to"] == 5  # dropper, runkey, c2-ip, c2-url, pipe -> stage actions


def test_assets_point_at_stix_objects():
    bundle = build_attack_flow(DatasetManifest.model_validate(SAMPLE))
    ids = {o["id"] for o in bundle["objects"]}
    for asset in _by_type(bundle, "attack-asset"):
        assert asset["object_ref"] in ids
        assert asset["extensions"] == {"extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {"extension_type": "new-sdo"}}
    by_name = {a["name"]: a for a in _by_type(bundle, "attack-asset")}
    assert by_name["CORP-WS-01"]["object_ref"].startswith("infrastructure--")
    assert by_name["Alice Example"]["object_ref"].startswith("user-account--")  # account assets are named by display name
    assert by_name["CORP-WS-01"]["description"].startswith("patient-zero")


def test_action_chain_and_timeline():
    bundle = build_attack_flow(DatasetManifest.model_validate(SAMPLE))
    actions = {a["name"]: a for a in _by_type(bundle, "attack-action")}
    flow = _by_type(bundle, "attack-flow")[0]
    s0a, s0b = actions["S0 Initial access (T1566)"], actions["S0 Initial access (T1204)"]
    assert flow["start_refs"] == [s0a["id"]]
    assert s0a["effect_refs"] == [s0b["id"]]  # chained inside the stage
    assert s0b["effect_refs"] == [actions["S1 Persistence"]["id"]]
    assert actions["S2 Beacon"]["effect_refs"] == [actions["S3 Lateral movement"]["id"]]
    assert "effect_refs" not in actions["S3 Lateral movement"]
    assert s0a["execution_start"] == "2026-01-01T10:00:00Z" and s0a["execution_end"] == "2026-01-01T10:05:00Z"
    assert s0a["tactic_id"] == "TA0001" and s0a["technique_id"] == "T1566"
    assert len(actions["S3 Lateral movement"]["asset_refs"]) == 3
    ap = {p["external_references"][0]["external_id"]: p for p in _by_type(bundle, "attack-pattern")}
    assert ap["T1547.001"]["name"] == "Registry Run Keys / Startup Folder"
    assert ap["T1547.001"]["external_references"][0]["url"] == "https://attack.mitre.org/techniques/T1547/001/"


def test_indicator_patterns_and_phases():
    bundle = build_attack_flow(DatasetManifest.model_validate(SAMPLE))
    ind = {i["name"]: i for i in _by_type(bundle, "indicator")}
    assert ind["203.0.113.9"]["pattern"] == "[ipv4-addr:value = '203.0.113.9']"
    assert ind["203.0.113.9"]["pattern_type"] == "stix" and ind["203.0.113.9"]["confidence"] == 70
    assert ind["203.0.113.9"]["kill_chain_phases"] == [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]
    assert ind["203.0.113.9"]["valid_from"].startswith("2026-01-01T10:20:00")
    assert ind["update-helper.exe"]["pattern"] == f"[file:hashes.'SHA-256' = '{SHA256}']"
    assert ind["Suspicious named pipe"]["pattern_type"] == "sigma"
    assert ind["203.0.113.9"]["labels"] == ["T1071.001"]


def test_deterministic_and_canonical_sco_ids():
    import stix2

    m = DatasetManifest.model_validate(SAMPLE)
    a, b = build_attack_flow(m), build_attack_flow(m)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    ips = {o["value"]: o["id"] for o in _by_type(a, "ipv4-addr")}
    # Observables carry the STIX canonical UUIDv5, so any STIX tool computes the same id.
    assert ips["203.0.113.9"] == stix2.IPv4Address(value="203.0.113.9").id
    accts = {o["account_login"]: o for o in _by_type(a, "user-account")}
    assert accts["svc-backup"]["is_service_account"] is True
    assert accts["alice"]["display_name"] == "Alice Example"


def test_write_and_validate(tmp_path: Path):
    ds = tmp_path / "sample-scenario"
    ds.mkdir()
    (ds / "dataset.yaml").write_text(yaml.safe_dump(SAMPLE, sort_keys=False))
    out = write_attack_flow(ds / "dataset.yaml")
    assert out == ds / "attack_flow.json" and out.exists()
    bundle = json.loads(out.read_text())
    assert bundle["type"] == "bundle" and _types(bundle)["attack-flow"] == 1

    from echolake.datasets.attack_flow import validate_attack_flow

    result = validate_attack_flow(out)
    if result.skipped:
        pytest.skip(f"attack-flow validator not installed: {result.reason}")
    assert result.valid, result.errors


def test_fail_loud_on_bad_stix_property():
    bad = json.loads(json.dumps(SAMPLE))
    bad["observables"].append({"id": "proc", "type": "process", "name": "evil.exe"})  # process has no name in STIX
    with pytest.raises(AttackFlowBuildError, match="proc"):
        build_attack_flow(DatasetManifest.model_validate(bad))


def test_requires_kill_chain():
    bare = {"metadata": {"name": "x", "version": "1.0.0", "description": "d", "created": "2026-10-20"}}
    with pytest.raises(AttackFlowBuildError, match="kill_chain"):
        build_attack_flow(DatasetManifest.model_validate(bare))
