"""Contract tests for the versioned, lossless dataset manifest model."""

from copy import deepcopy
from typing import Any, Dict

import pytest
import yaml
from pydantic import ValidationError

from echolake.datasets.models import BadactorsQuality, DatasetManifest, MANIFEST_VERSION


def _full_manifest() -> Dict[str, Any]:
    """Return one valid manifest that exercises every major contract block."""
    return {
        "manifest_version": "1.0.0",
        "metadata": {
            "name": "contract-fixture",
            "version": "1.2.3",
            "description": "A complete manifest contract fixture.",
            "author": "security@example.test",
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-02T00:00:00Z",
            "license": "Apache-2.0",
            "tags": ["contract", "security"],
            "timestamp_range": {
                "earliest": "2026-01-01T10:00:00Z",
                "latest": "2026-01-01T11:00:00Z",
                "field": "_time",
            },
            "mitre_attack": {
                "techniques": [
                    {
                        "id": "T1059.001",
                        "name": "PowerShell",
                        "tactics": ["execution"],
                    }
                ],
                "tactics": ["execution"],
            },
            "attack_flow": {
                "path": "attack_flow.json",
                "format": "stix-2.1",
                "schema_version": "2.0.0",
            },
            "source_url": "https://example.test/datasets/contract-fixture",
            "data_sources": [
                {
                    "name": "Windows events",
                    "sourcetypes": ["XmlWinEventLog:Security"],
                }
            ],
            "size": {"download": "1 MiB"},
            "checksums": {"archive_sha256": "abc123"},
            "references": ["https://example.test/reference"],
            "extensions": {"x_echolake": {"owner": "security"}},
        },
        "files": {
            "bundled": [
                {
                    "path": "logs/events.jsonl",
                    "description": "Scenario events",
                    "format": "jsonl",
                    "schema": "raw",
                    "event_count": 4,
                    "sourcetype": "XmlWinEventLog:Security",
                    "log_source": {
                        "vendor": "Microsoft",
                        "product": "Windows",
                        "category": "Security",
                        "event_ids": [4688],
                        "extensions": {"x_channel": "Security"},
                    },
                    "platforms": {"splunk": {"index": "main"}},
                    "extensions": {"x_capture": {"batch": 7}},
                }
            ],
            "references": [
                {
                    "uri": "https://example.test/reference.jsonl",
                    "format": "jsonl",
                    "schema": "raw",
                    "event_count": 2,
                    "sourcetype": "stream:dns",
                    "platforms": {"lakehouse": {"table": "bronze.dns"}},
                    "extensions": {"x_remote": True},
                }
            ],
        },
        "dependencies": [
            {
                "dataset": "example/baseline",
                "version": ">=1.0.0",
                "description": "Baseline context",
            }
        ],
        "defaults": {
            "replay": {
                "delta_factor": 2.0,
                "base_time": "earliest",
                "target_time": "now",
                "prevent_future": True,
                "shift_payload": True,
            },
            "schema": "raw",
            "input": {
                "format": "jsonl",
                "timestamp_patterns": [
                    {"field": "timestamp", "format": "iso8601", "is_base": True}
                ],
                "extensions": {"x_parser": "strict"},
            },
            "extensions": {"x_runtime": {"workers": 2}},
        },
        "environment": {
            "host": {
                "hostname": "LAB-WS-01",
                "os": "Windows",
                "os_version": "11",
                "architecture": "x86_64",
                "domain": "LAB.EXAMPLE",
                "ip": "10.0.0.10",
                "extensions": {"x_vmid": 101},
            },
            "collection": {
                "collector": "wef",
                "channels": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "extensions": {"x_transport": "https"},
            },
            "execution": {
                "user": "LAB\\alice",
                "method": "powershell",
                "tool": "scenario-runner",
                "extensions": {"x_run_id": "run-2"},
            },
            "windows": {
                "sysmon": {
                    "installed": True,
                    "version": "15.0",
                    "network_connect": True,
                },
                "powershell": {"script_block_logging": True},
                "audit_policy": {
                    "process_creation": "success",
                    "command_line_logging": True,
                },
                "endpoint_protection": {
                    "product": "Microsoft Defender",
                    "real_time_protection": True,
                },
            },
            "linux": {
                "auditd": {"enabled": True},
                "security_module": {"name": "SELinux", "mode": "enforcing"},
            },
            "macos": {
                "endpoint_security_framework": True,
                "sip_enabled": True,
            },
            "cloud": {
                "provider": "AWS",
                "region": "us-west-2",
                "logging": {"cloudtrail": True},
            },
            "network": {
                "capture_type": "span",
                "zeek": {"installed": True, "logs": ["conn", "dns"]},
                "proxy": {"type": "squid", "port": 3128},
            },
            "container": {
                "runtime": "containerd",
                "orchestrator": "kubernetes",
                "monitoring": {"falco": True},
            },
            "versions": {"scenario_runner": "2.1.0"},
            "extensions": {"x_lab": {"isolated": True}},
        },
        "provenance": {
            "build": {
                "host": {"hostname": "builder", "vmid": 9001},
                "timestamps": {"start_epoch": 100, "end_epoch": 200},
                "tool": "dataset-builder",
                "filtered_orchestration_events": 1,
                "window_utc": {
                    "start": "2026-01-01T10:00:00Z",
                    "end": "2026-01-01T11:00:00Z",
                },
                "campaign_utc": {
                    "t0": "2026-01-01T10:05:00Z",
                    "t_end": "2026-01-01T10:55:00Z",
                },
                "translation": {
                    "from": "lab time",
                    "to": "UTC",
                    "reason": "Normalize collection clocks",
                },
                "extensions": {"x_build": {"revision": 4}},
            },
            "verification": {
                "source_counts": {"windows": 4},
                "dest_counts": {"events": 4},
                "signatures": {"process_create": 1},
                "window_epoch": [100, 200],
                "scaffolding_leaks": 0,
                "lineage_clean": True,
                "technique_parent": ["T1059"],
                "total_events": 4,
                "extensions": {"x_verifier": "v2"},
            },
            "regenerated": {
                "from": "source-v1",
                "reason": "Normalize timestamps",
                "total_events": 4,
            },
            "extensions": {"x_lineage": {"job": "job-123"}},
        },
        "badactors_quality": {
            "Q": 0.79,
            "disqualified": False,
            "gates": {
                "scaffolding_hard_leaks_zero": True,
                "no_future_events": True,
                "lineage_clean": True,
                "required_signatures_present": True,
                "ingest_integrity": True,
            },
            "components": {
                "coverage": 0.8,
                "signal_completeness": 0.7,
                "attribution": 0.75,
                "purity": 0.8,
                "integrity": 1.0,
            },
            "weights": {
                "coverage": 0.4,
                "signal_completeness": 0.2,
                "attribution": 0.2,
                "purity": 0.1,
                "integrity": 0.1,
            },
            "visibility": {
                "coverage": 0.8,
                "observable_primitives": 5,
                "observed_primitives": 4,
                "blind_primitives": ["memory"],
                "missed_observable": ["credential-read"],
            },
            "attribution": {
                "attributed": 3,
                "technique_events": 4,
                "ambient_filtered": 1,
                "per_step": {"S0": 4},
            },
            "selection": "highest valid score",
            "spec": "badactors-quality-v1",
            "best_of_n": {
                "runs": 2,
                "selected": "run-2",
                "all_Q": {"run-1": 0.7, "run-2": 0.79},
                "selection": "max_Q",
            },
            "extensions": {"x_quality": {"reviewed": True}},
        },
        "entities": [
            {
                "id": "host-1",
                "type": "infrastructure",
                "name": "LAB-WS-01",
                "description": "Scenario endpoint",
                "role": "patient-zero",
                "observables": ["ip-1"],
                "infrastructure_types": ["workstation"],
                "properties": {"x_echolake_asset_id": "asset-123"},
            }
        ],
        "observables": [
            {
                "id": "ip-1",
                "type": "ipv4-addr",
                "value": "203.0.113.10",
                "description": "Scenario destination",
                "indicator_types": ["malicious-activity"],
                "kill_chain_phases": ["execution"],
                "techniques": ["T1059.001"],
                "confidence": 80,
                "first_seen": "2026-01-01T10:10:00Z",
                "last_seen": "2026-01-01T10:20:00Z",
                "properties": {"x_echolake_source": "fixture"},
            }
        ],
        "kill_chain": [
            {
                "id": "S0",
                "name": "Execution",
                "description": "PowerShell execution",
                "tactic": "execution",
                "techniques": ["T1059.001"],
                "assets": ["host-1"],
                "observables": ["ip-1"],
                "execution_start": "2026-01-01T10:10:00Z",
                "execution_end": "2026-01-01T10:20:00Z",
            }
        ],
        "notes": "Complete contract fixture",
        "extensions": {"x_manifest": {"catalog": "test"}},
    }


def _set(data: Dict[str, Any], path, value: Any) -> None:
    target = data
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def _assert_invalid(data: Dict[str, Any]) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        DatasetManifest.model_validate(data)
    return exc_info.value


def test_full_manifest_is_lossless_and_preserves_authored_replay(tmp_path):
    manifest = DatasetManifest.model_validate(_full_manifest())

    dumped = manifest.model_dump(exclude_none=True, by_alias=True)
    assert dumped["metadata"]["extensions"]["x_echolake"]["owner"] == "security"
    assert dumped["files"]["bundled"][0]["platforms"]["splunk"]["index"] == "main"
    assert dumped["files"]["bundled"][0]["extensions"]["x_capture"]["batch"] == 7
    assert dumped["environment"]["extensions"]["x_lab"]["isolated"] is True
    assert dumped["provenance"]["extensions"]["x_lineage"]["job"] == "job-123"
    assert dumped["badactors_quality"]["extensions"]["x_quality"]["reviewed"] is True
    assert dumped["entities"][0]["properties"]["x_echolake_asset_id"] == "asset-123"
    assert dumped["observables"][0]["properties"]["x_echolake_source"] == "fixture"
    assert "replay" in dumped["defaults"]
    assert "echo" not in dumped["defaults"]
    assert manifest.defaults is not None
    assert manifest.defaults.echo is None
    assert manifest.defaults.replay is not None
    assert manifest.defaults.effective_echo == manifest.defaults.replay
    assert manifest.defaults.effective_echo.delta_factor == 2.0

    manifest_path = tmp_path / "dataset.yaml"
    manifest.to_file(manifest_path)
    serialized = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert serialized["manifest_version"] == "1.0.0"
    assert "replay" in serialized["defaults"]
    assert "echo" not in serialized["defaults"]
    assert serialized["defaults"]["replay"]["target_time"] == "now"
    assert serialized["defaults"]["replay"]["prevent_future"] is True
    assert serialized["metadata"]["attack_flow"]["format"] == "stix-2.1"
    assert serialized["metadata"]["attack_flow"]["schema_version"] == "2.0.0"

    reloaded = DatasetManifest.from_file(manifest_path)
    assert reloaded.model_dump(exclude_none=True, by_alias=True) == dumped
    assert reloaded.defaults is not None
    assert reloaded.defaults.echo is None
    assert reloaded.defaults.effective_echo is not None
    assert reloaded.defaults.effective_echo.shift_payload is True


def test_writer_preserves_explicit_nulls_and_nested_container_mutations(tmp_path):
    data = {
        "metadata": {
            "name": "writer-state",
            "version": "1.0.0",
            "description": "Writer state preservation",
        },
        "files": {"bundled": [{"path": "events.jsonl"}]},
        "defaults": {"echo": {"ceiling_time": None}},
    }
    manifest = DatasetManifest.model_validate(data)
    manifest.files.bundled[0].extensions["x_added"] = True

    manifest_path = tmp_path / "dataset.yaml"
    manifest.to_file(manifest_path)
    serialized = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    assert serialized["defaults"]["echo"]["ceiling_time"] is None
    assert serialized["files"]["bundled"][0]["extensions"] == {"x_added": True}
    reloaded = DatasetManifest.from_file(manifest_path)
    assert reloaded.defaults is not None
    assert reloaded.defaults.echo is not None
    assert reloaded.defaults.echo.ceiling_time is None
    assert reloaded.files.bundled[0].extensions == {"x_added": True}


@pytest.mark.parametrize(
    ("echo", "replay"),
    [
        (None, {"delta_factor": 2.0}),
        ({"delta_factor": 2.0}, None),
    ],
)
def test_authored_echo_and_replay_aliases_must_agree_including_null(echo, replay):
    data = {
        "metadata": {
            "name": "alias-conflict",
            "version": "1.0.0",
            "description": "Conflicting aliases",
        },
        "defaults": {"echo": echo, "replay": replay},
    }

    _assert_invalid(data)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param((), id="top-level"),
        pytest.param(("metadata",), id="metadata"),
        pytest.param(("files", "bundled", 0), id="bundled-file"),
        pytest.param(("environment",), id="environment"),
        pytest.param(("environment", "host"), id="environment-host"),
        pytest.param(("provenance",), id="provenance"),
        pytest.param(("provenance", "build"), id="provenance-build"),
        pytest.param(("badactors_quality",), id="quality"),
        pytest.param(("entities", 0), id="scenario-entity"),
        pytest.param(("observables", 0), id="scenario-observable"),
        pytest.param(("kill_chain", 0), id="scenario-stage"),
    ],
)
def test_unknown_fields_are_rejected_at_contract_boundaries(path):
    data = _full_manifest()
    target = data
    for part in path:
        target = target[part]
    target["unknown_field"] = True

    error = _assert_invalid(data)
    assert any(
        item["type"] == "extra_forbidden" and item["loc"][-1] == "unknown_field"
        for item in error.errors()
    )


def test_declared_extensions_and_scenario_properties_are_allowed():
    manifest = DatasetManifest.model_validate(_full_manifest())

    assert manifest.extensions["x_manifest"] == {"catalog": "test"}
    assert manifest.metadata.extensions["x_echolake"] == {"owner": "security"}
    assert manifest.entities[0].properties["x_echolake_asset_id"] == "asset-123"
    assert manifest.observables[0].properties["x_echolake_source"] == "fixture"


def test_manifest_version_is_implicit_or_explicit_and_rejects_unsupported_versions():
    implicit = _full_manifest()
    implicit.pop("manifest_version")
    explicit = _full_manifest()

    assert DatasetManifest.model_validate(implicit).manifest_version == MANIFEST_VERSION
    assert DatasetManifest.model_validate(explicit).manifest_version == "1.0.0"

    unsupported = _full_manifest()
    unsupported["manifest_version"] = "2.0.0"
    _assert_invalid(unsupported)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("files", "bundled", 0, "schema"), "ocsf", id="bundled-schema"),
        pytest.param(("files", "references", 0, "schema"), "native", id="reference-schema"),
        pytest.param(("defaults", "schema"), "ecs", id="defaults-schema"),
        pytest.param(("files", "bundled", 0, "format"), "parquet", id="bundled-format"),
        pytest.param(("files", "references", 0, "format"), "avro", id="reference-format"),
        pytest.param(("defaults", "input", "format"), "protobuf", id="input-format"),
        pytest.param(
            ("files", "bundled", 0, "path"),
            "https://example.test/events.jsonl",
            id="bundled-uri-path",
        ),
        pytest.param(
            ("files", "bundled", 0, "path"),
            "logs/events\x00.jsonl",
            id="bundled-nul-path",
        ),
        pytest.param(
            ("metadata", "attack_flow", "path"),
            "s3://bucket/flow.json",
            id="attack-flow-uri-path",
        ),
        pytest.param(("files", "bundled", 0, "sourcetype"), "", id="blank-sourcetype"),
        pytest.param(
            ("files", "references", 0, "sourcetype"),
            " stream:dns ",
            id="untrimmed-sourcetype",
        ),
        pytest.param(
            ("metadata", "data_sources", 0, "sourcetypes", 0),
            "bad\nsource",
            id="control-character-sourcetype",
        ),
        pytest.param(("files", "bundled", 0, "event_count"), -1, id="bundled-count"),
        pytest.param(("files", "references", 0, "event_count"), -1, id="reference-count"),
        pytest.param(
            ("provenance", "build", "filtered_orchestration_events"),
            -1,
            id="filtered-count",
        ),
        pytest.param(
            ("provenance", "verification", "source_counts", "windows"),
            -1,
            id="verification-map-count",
        ),
        pytest.param(
            ("provenance", "verification", "total_events"),
            -1,
            id="verification-total",
        ),
    ],
)
def test_schema_format_sourcetype_and_counts_are_constrained(path, value):
    data = _full_manifest()
    _set(data, path, value)

    _assert_invalid(data)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(
            ("metadata", "created"),
            "2026-01-03T00:00:00Z",
            id="metadata-created-after-updated",
        ),
        pytest.param(
            ("metadata", "timestamp_range", "earliest"),
            "2026-01-01T12:00:00Z",
            id="metadata-range",
        ),
        pytest.param(
            ("observables", 0, "first_seen"),
            "2026-01-01T10:30:00Z",
            id="observable-range",
        ),
        pytest.param(
            ("kill_chain", 0, "execution_start"),
            "2026-01-01T10:30:00Z",
            id="stage-range",
        ),
        pytest.param(
            ("provenance", "build", "timestamps", "start_epoch"),
            300,
            id="provenance-epoch-range",
        ),
        pytest.param(
            ("provenance", "build", "window_utc", "start"),
            "2026-01-01T12:00:00Z",
            id="provenance-window",
        ),
        pytest.param(
            ("provenance", "build", "campaign_utc", "t0"),
            "2026-01-01T12:00:00Z",
            id="provenance-campaign",
        ),
        pytest.param(
            ("provenance", "verification", "window_epoch", 0),
            300,
            id="provenance-verification-window",
        ),
    ],
)
def test_timestamp_ranges_must_be_ordered(path, value):
    data = _full_manifest()
    _set(data, path, value)

    _assert_invalid(data)


@pytest.mark.parametrize("field", ["created", "updated"])
def test_lone_metadata_date_must_be_iso8601(field):
    data = _full_manifest()
    other = "updated" if field == "created" else "created"
    data["metadata"].pop(other)
    data["metadata"][field] = "not-a-date"

    _assert_invalid(data)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(
            ("provenance", "regenerated", "total_events"),
            3,
            id="regenerated-total",
        ),
        pytest.param(
            ("badactors_quality", "attribution", "technique_events"),
            3,
            id="quality-technique-total",
        ),
    ],
)
def test_packaged_counts_match_regenerated_and_quality_totals(path, value):
    data = _full_manifest()
    _set(data, path, value)

    _assert_invalid(data)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("badactors_quality", "Q"), 0.5, id="weighted-score"),
        pytest.param(
            ("badactors_quality", "weights", "coverage"),
            0.3,
            id="weight-sum",
        ),
        pytest.param(
            ("badactors_quality", "components", "coverage"),
            1.1,
            id="component-range",
        ),
        pytest.param(
            ("badactors_quality", "visibility", "observed_primitives"),
            6,
            id="observed-over-total",
        ),
        pytest.param(
            ("badactors_quality", "attribution", "attributed"),
            5,
            id="attributed-over-technique-events",
        ),
        pytest.param(
            ("badactors_quality", "visibility", "coverage"),
            0.7,
            id="visibility-coverage-ratio",
        ),
        pytest.param(
            ("badactors_quality", "attribution", "attributed"),
            2,
            id="attribution-component-ratio",
        ),
        pytest.param(
            ("badactors_quality", "attribution", "per_step", "S0"),
            -1,
            id="negative-step-count",
        ),
        pytest.param(
            ("badactors_quality", "best_of_n", "runs"),
            3,
            id="run-count",
        ),
        pytest.param(
            ("badactors_quality", "best_of_n", "selected"),
            "missing",
            id="selected-run",
        ),
        pytest.param(
            ("badactors_quality", "best_of_n", "all_Q", "run-1"),
            1.1,
            id="run-score-range",
        ),
        pytest.param(
            ("badactors_quality", "disqualified"),
            True,
            id="disqualification-gates",
        ),
        pytest.param(
            ("badactors_quality", "components", "purity"),
            0.7,
            id="purity-ratio",
        ),
        pytest.param(
            ("badactors_quality", "components", "integrity"),
            0.0,
            id="integrity-gate",
        ),
        pytest.param(
            ("badactors_quality", "best_of_n", "all_Q", "run-2"),
            0.8,
            id="selected-run-score",
        ),
        pytest.param(
            ("badactors_quality", "best_of_n", "all_Q", "run-1"),
            0.9,
            id="selected-run-is-not-maximum",
        ),
    ],
)
def test_quality_formula_and_count_invariants(path, value):
    data = _full_manifest()
    _set(data, path, value)

    _assert_invalid(data)


def test_disqualified_quality_uses_zero_score_and_failed_integrity_component():
    quality = deepcopy(_full_manifest()["badactors_quality"])
    quality["gates"]["ingest_integrity"] = False
    quality["components"]["integrity"] = 0.0
    quality["disqualified"] = True
    quality["Q"] = 0.0
    quality["best_of_n"]["all_Q"]["run-1"] = 0.0
    quality["best_of_n"]["all_Q"]["run-2"] = 0.0

    parsed = BadactorsQuality.model_validate(quality)

    assert parsed.disqualified is True
    assert parsed.Q == 0.0


def test_quality_zero_denominators_use_generator_defaults():
    quality = deepcopy(_full_manifest()["badactors_quality"])
    quality["visibility"].update(
        coverage=1.0,
        observable_primitives=0,
        observed_primitives=0,
    )
    quality["components"].update(coverage=1.0, attribution=0.0, purity=0.0)
    quality["attribution"].update(
        attributed=0,
        technique_events=0,
        ambient_filtered=0,
        per_step={},
    )
    quality["Q"] = 0.64
    quality["best_of_n"]["all_Q"]["run-1"] = 0.5
    quality["best_of_n"]["all_Q"]["run-2"] = 0.64

    parsed = BadactorsQuality.model_validate(quality)

    assert parsed.visibility.coverage == 1.0
    assert parsed.components.attribution == 0.0
    assert parsed.components.purity == 0.0


@pytest.mark.parametrize(
    "case",
    [
        "duplicate-bundled-path",
        "duplicate-reference-uri",
        "duplicate-dependency",
        "duplicate-entity",
        "duplicate-observable",
        "duplicate-stage",
        "unknown-entity-observable",
        "unknown-stage-asset",
        "unknown-stage-observable",
        "unknown-next-stage",
        "kill-chain-without-entities",
        "kill-chain-without-attack-flow",
        "undeclared-technique",
        "malformed-technique",
        "duplicate-stage-technique",
    ],
)
def test_duplicates_scenario_references_and_techniques_are_rejected(case):
    data = _full_manifest()
    if case == "duplicate-bundled-path":
        data["files"]["bundled"].append(deepcopy(data["files"]["bundled"][0]))
    elif case == "duplicate-reference-uri":
        data["files"]["references"].append(deepcopy(data["files"]["references"][0]))
    elif case == "duplicate-dependency":
        duplicate = deepcopy(data["dependencies"][0])
        duplicate["version"] = "2.0.0"
        data["dependencies"].append(duplicate)
    elif case == "duplicate-entity":
        data["entities"].append(deepcopy(data["entities"][0]))
    elif case == "duplicate-observable":
        data["observables"].append(deepcopy(data["observables"][0]))
    elif case == "duplicate-stage":
        data["kill_chain"].append(deepcopy(data["kill_chain"][0]))
    elif case == "unknown-entity-observable":
        data["entities"][0]["observables"] = ["missing-observable"]
    elif case == "unknown-stage-asset":
        data["kill_chain"][0]["assets"] = ["missing-entity"]
    elif case == "unknown-stage-observable":
        data["kill_chain"][0]["observables"] = ["missing-observable"]
    elif case == "unknown-next-stage":
        data["kill_chain"][0]["next"] = ["missing-stage"]
    elif case == "kill-chain-without-entities":
        data["entities"] = []
        data["kill_chain"][0]["assets"] = []
    elif case == "kill-chain-without-attack-flow":
        data["metadata"].pop("attack_flow")
    elif case == "undeclared-technique":
        data["kill_chain"][0]["techniques"] = ["T1111"]
    elif case == "malformed-technique":
        data["kill_chain"][0]["techniques"] = ["powershell"]
    elif case == "duplicate-stage-technique":
        data["kill_chain"][0]["techniques"] = ["T1059.001", "T1059.001"]
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(case)

    _assert_invalid(data)
