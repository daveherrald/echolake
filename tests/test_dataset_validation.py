"""Focused tests for offline dataset file validation."""

import gzip
from pathlib import Path
from types import SimpleNamespace

import pytest

from echolake.datasets.validation import validate_manifest_files


def _bundled(
    path,
    *,
    file_format="text",
    event_count=1,
    schema_type="raw",
    sourcetype="XmlWinEventLog",
):
    return SimpleNamespace(
        path=path,
        format=file_format,
        event_count=event_count,
        schema_type=schema_type,
        sourcetype=sourcetype,
    )


def _manifest(*, bundled=None, references=None, attack_flow=None, observables=None):
    return SimpleNamespace(
        files=SimpleNamespace(
            bundled=list(bundled or []),
            references=list(references or []),
        ),
        metadata=SimpleNamespace(attack_flow=attack_flow),
        observables=list(observables or []),
    )


def _codes(issues):
    return [issue.code for issue in issues]


@pytest.mark.parametrize(
    "bad_path",
    [
        "../outside.log",
        "/tmp/outside.log",
        "logs\\events.log",
        "C:/outside.log",
        "C:outside.log",
        "https://x/y",
        ".",
        "./",
        ".//",
        "././",
        "a/",
    ],
)
def test_rejects_non_posix_relative_bundled_paths(tmp_path, bad_path):
    report = validate_manifest_files(
        _manifest(bundled=[_bundled(bad_path)]),
        tmp_path,
    )

    assert "invalid_local_path" in _codes(report.errors)


def test_rejects_symlink_escape(tmp_path):
    dataset_root = tmp_path / "dataset"
    dataset_root.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_text("event\n", encoding="utf-8")
    try:
        (dataset_root / "linked.log").symlink_to(outside)
    except OSError as error:
        pytest.skip("symlinks are unavailable: {}".format(error))

    report = validate_manifest_files(
        _manifest(bundled=[_bundled("linked.log")]),
        dataset_root,
    )

    assert "path_escape" in _codes(report.errors)


def test_reports_missing_and_non_regular_local_files(tmp_path):
    (tmp_path / "directory").mkdir()
    report = validate_manifest_files(
        _manifest(
            bundled=[
                _bundled("missing.log"),
                _bundled("directory"),
            ]
        ),
        tmp_path,
    )

    assert "missing_local_file" in _codes(report.errors)
    assert "not_regular_file" in _codes(report.errors)


def test_reports_duplicate_bundled_paths_and_reference_uris(tmp_path):
    (tmp_path / "events.log").write_text("event\n", encoding="utf-8")
    reference = SimpleNamespace(uri="s3://bucket/events.jsonl", sourcetype="unknown:remote")
    report = validate_manifest_files(
        _manifest(
            bundled=[
                _bundled("events.log"),
                _bundled("./events.log"),
            ],
            references=[reference, reference],
        ),
        tmp_path,
    )

    assert "duplicate_bundled_path" in _codes(report.errors)
    assert "duplicate_reference_uri" in _codes(report.errors)
    assert "unregistered_sourcetype" not in _codes(report.errors)
    assert "remote_content_unchecked" in _codes(report.warnings)


def test_counts_supported_plain_and_gzip_formats(tmp_path):
    (tmp_path / "events.xml").write_text(
        '<Events xmlns:w="urn:test"><Event/><w:Event/></Events>',
        encoding="utf-8",
    )
    with gzip.open(tmp_path / "events.xml.gz", "wt", encoding="utf-8") as stream:
        stream.write("<Events><Event/><Event/><Event/></Events>")
    (tmp_path / "events.jsonl").write_text(
        '{"a": 1}\n42\n[]\n\n{"a": 2}\n', encoding="utf-8"
    )
    (tmp_path / "array.json").write_text(
        '[{"a": 1}, 42, [], {"a": 2}]', encoding="utf-8"
    )
    (tmp_path / "object.json").write_text('{"a": 1}', encoding="utf-8")
    (tmp_path / "events.log").write_bytes(b"one\n\ntwo\n")
    (tmp_path / "events.csv").write_text(
        'id,message\n1,"first line\nsecond line"\n', encoding="utf-8"
    )
    (tmp_path / "auto.json").write_text("plain text\n", encoding="utf-8")

    report = validate_manifest_files(
        _manifest(
            bundled=[
                _bundled("events.xml", file_format="xml", event_count=2),
                _bundled("events.xml.gz", file_format="xml", event_count=3),
                _bundled("events.jsonl", file_format="jsonl", event_count=2),
                _bundled("array.json", file_format="json", event_count=2),
                _bundled("object.json", file_format="json", event_count=1),
                _bundled("events.log", file_format="text", event_count=2),
                _bundled("events.csv", file_format="csv", event_count=1),
                _bundled(
                    "auto.json",
                    file_format="auto",
                    event_count=1,
                    sourcetype="custom:auto",
                ),
            ]
        ),
        tmp_path,
    )

    assert report.valid
    assert report.is_valid
    assert report.files_checked == 8
    assert report.counts_checked == 8
    assert report.to_dict()["valid"] is True


def test_count_mismatch_and_malformed_content_are_errors(tmp_path):
    (tmp_path / "short.log").write_text("one\n", encoding="utf-8")
    (tmp_path / "bad.jsonl").write_text("{not json}\n", encoding="utf-8")
    (tmp_path / "bad.log.gz").write_bytes(b"not gzip")
    manifest = _manifest(
        bundled=[
            _bundled("short.log", event_count=2),
            _bundled("bad.jsonl", file_format="jsonl", event_count=1),
            _bundled("bad.log.gz", file_format="text", event_count=1),
        ]
    )

    report = validate_manifest_files(manifest, tmp_path)

    assert "event_count_mismatch" in _codes(report.errors)
    assert _codes(report.errors).count("content_count_failed") == 2

    skipped = validate_manifest_files(manifest, tmp_path, check_counts=False)
    assert skipped.valid
    assert skipped.counts_checked == 0
    assert "count_checks_skipped" in _codes(skipped.warnings)


def test_attack_flow_and_observable_rule_paths_are_checked(tmp_path):
    (tmp_path / "flow.json").write_text("{}", encoding="utf-8")
    (tmp_path / "rule.yml").write_text("title: local\n", encoding="utf-8")
    manifest = _manifest(
        attack_flow=SimpleNamespace(path="flow.json"),
        observables=[
            SimpleNamespace(rule="rule.yml"),
            SimpleNamespace(rule="https://example.test/rule.yml"),
        ],
    )

    report = validate_manifest_files(manifest, tmp_path)

    assert report.valid
    assert report.files_checked == 2
    assert "external_rule_unchecked" in _codes(report.warnings)

    invalid = validate_manifest_files(
        _manifest(
            attack_flow=SimpleNamespace(path="missing-flow.json"),
            observables=[SimpleNamespace(rule="../outside.yml")],
        ),
        tmp_path,
    )
    assert "missing_local_file" in _codes(invalid.errors)
    assert "invalid_local_path" in _codes(invalid.errors)


def test_bundled_runtime_schema_must_be_raw_or_omitted(tmp_path):
    for name in ("raw.log", "none.log", "native.log"):
        (tmp_path / name).write_text("event\n", encoding="utf-8")
    report = validate_manifest_files(
        _manifest(
            bundled=[
                _bundled("raw.log", schema_type="raw"),
                _bundled("none.log", schema_type=None),
                _bundled("native.log", schema_type="native"),
            ]
        ),
        tmp_path,
    )

    assert _codes(report.errors).count("unsupported_runtime_schema") == 1


def test_bundled_sourcetypes_validate_registered_values_and_warn_on_fallback(tmp_path):
    names = ["blank.log", "control.log", "missing.log", "unknown.log", "valid.log"]
    for name in names:
        (tmp_path / name).write_text("event\n", encoding="utf-8")
    report = validate_manifest_files(
        _manifest(
            bundled=[
                _bundled("blank.log", sourcetype=""),
                _bundled("control.log", sourcetype="bad\nvalue"),
                _bundled("missing.log", sourcetype=None),
                _bundled("unknown.log", sourcetype="unknown:local"),
                _bundled("valid.log", sourcetype="XmlWinEventLog:Security"),
            ]
        ),
        tmp_path,
    )

    assert _codes(report.errors).count("invalid_sourcetype") == 2
    assert "missing_sourcetype" not in _codes(report.errors)
    assert "missing_sourcetype" in _codes(report.warnings)
    assert "unregistered_sourcetype" not in _codes(report.errors)
    assert "unregistered_sourcetype" in _codes(report.warnings)


def test_remote_sourcetype_is_not_registry_checked(tmp_path):
    reference = SimpleNamespace(
        uri="https://example.test/events.jsonl",
        sourcetype="unknown:remote",
    )
    report = validate_manifest_files(
        _manifest(references=[reference]),
        tmp_path,
    )

    assert report.valid
    assert "unregistered_sourcetype" not in _codes(report.errors)
    assert "remote_content_unchecked" in _codes(report.warnings)


def test_registry_requirement_can_be_disabled_with_warning(tmp_path):
    (tmp_path / "unknown.log").write_text("event\n", encoding="utf-8")
    (tmp_path / "missing.log").write_text("event\n", encoding="utf-8")
    report = validate_manifest_files(
        _manifest(
            bundled=[
                _bundled("unknown.log", sourcetype="unknown:local"),
                _bundled("missing.log", sourcetype=None),
            ]
        ),
        tmp_path,
        require_registered_sourcetypes=False,
    )

    assert report.valid
    assert "registry_check_skipped" in _codes(report.warnings)
    assert "missing_sourcetype" in _codes(report.warnings)


def test_missing_event_count_is_a_warning(tmp_path):
    (tmp_path / "events.log").write_text("event\n", encoding="utf-8")
    report = validate_manifest_files(
        _manifest(bundled=[_bundled("events.log", event_count=None)]),
        tmp_path,
    )

    assert report.valid
    assert "event_count_missing" in _codes(report.warnings)
    assert report.counts_checked == 0
