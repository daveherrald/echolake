# Dataset Manifest Migration

**Contract:** 1.0.0
**Last Updated:** 2026-11-01

This guide moves an existing `dataset.yaml` to EchoLake manifest contract
1.0.0. The contract preserves authored metadata while rejecting fields that
EchoLake cannot interpret or preserve safely.

## Compatibility

`manifest_version` selects the manifest contract. It is separate from
`metadata.version`, which versions the dataset content.

```yaml
manifest_version: "1.0.0"
metadata:
  name: example-dataset
  version: "2.3.1"
  description: Example dataset
```

Existing manifests without `manifest_version` load as version 1. The canonical
writer adds `manifest_version: "1.0.0"`. Any other explicit manifest version is
rejected. Adding the field does not require a dataset content version change by
itself.

## Migration Procedure

### 1. Parse the Current Manifest

Run the base validator first:

```bash
echolake validate-dataset path/to/dataset
```

This checks the typed contract without reading bundled content. Fix parse
errors before running file checks.

### 2. Move Unknown Fields

Contract 1.0.0 rejects unknown keys at typed boundaries. Choose one of these
destinations for every custom value:

- Use a modeled field when one exists.
- Use the nearest declared `extensions` map for namespaced custom JSON.
- Use `entities[].properties` or `observables[].properties` for additional STIX properties.
- Keep platform-specific SIEM values inside `files.*.platforms`.
- Keep provider-specific values inside a documented free-form map, such as `environment.cloud.logging`.

Before:

```yaml
environment:
  host:
    hostname: LAB-WS02
    asset_id: asset-204
```

After:

```yaml
environment:
  host:
    hostname: LAB-WS02
    extensions:
      com.example.asset_id: asset-204
```

Use stable, namespaced extension keys. Extension values must be
JSON-compatible YAML. Do not place an arbitrary key beside typed fields.

### 3. Use the Typed Metadata Blocks

The following blocks are modeled and preserved during round trips:

- `environment`, including host, collection, execution, Windows, Linux, macOS, cloud, network, container, and named versions
- `provenance`, including build, verification, regeneration, ordered ranges, count maps, and extensions
- `badactors_quality`, including gates, components, weights, visibility, attribution, and best-of-N selection
- source metadata such as `metadata.source_url`, `data_sources`, `size`, `checksums`, and `references`

Move data into the documented field names. Unknown direct keys in these blocks
are rejected. See [Collection Environment](COLLECTION_ENVIRONMENT.md) and
[Dataset Format](DATASET_FORMAT.md) for supported fields.

The parser also checks cross-field invariants. Examples include ordered time
ranges, non-negative counts, regenerated totals, quality score calculations,
visibility and attribution ratios, and best-of-N consistency. Correct the
source values rather than copying an inconsistent calculation into an
extension.

### 4. Normalize Runtime Schemas

The only supported schema value is `raw`. Omission also selects raw runtime
handling. This rule applies to bundled files, remote references, and
`defaults.schema`.

Before:

```yaml
files:
  bundled:
    - path: logs/security.xml
      schema: windows_events_xml
```

After:

```yaml
files:
  bundled:
    - path: logs/security.xml
      schema: raw
```

Supported file formats are `auto`, `csv`, `jsonl`, `json`, `text`, and `xml`.

### 5. Review Sourcetypes

`sourcetype` is optional. A present value must be a nonempty, trimmed string
without control characters.

For bundled files, offline validation warns when the sourcetype is missing or
not registered. Raw replay can still use `defaults.input.timestamp_patterns`
or generic fallback patterns. Registering a known type gives replay a stable,
specific timestamp rule.

Remote reference sourcetypes receive syntax checks only. Offline validation
does not compare them with the local timestamp registry.

See [Log Source Metadata](LOG_SOURCE_METADATA.md) for the distinction between
runtime `sourcetype`, descriptive `log_source`, and free-form `platforms`.

### 6. Preserve Replay Defaults

Older manifests may use `defaults.replay`. EchoLake preserves that authored key
when parsing and writing. Runtime resolution reads `effective_echo`, which uses
`defaults.echo` when present and otherwise uses `defaults.replay`.

```yaml
defaults:
  replay:
    delta_factor: 2.0
    base_time: auto
    target_time: now
```

New manifests should use `defaults.echo`. If a manifest declares both keys,
their values must be equal. The parser does not rename `replay` in the source
model, and the canonical writer does not rename it in output.

Echo defaults are:

- `delta_factor: 1.0`
- `base_time: auto`
- `target_time: now`
- `prevent_future: true`
- `ceiling_time: now`
- `no_shift: false`
- `shift_payload: false`

### 7. Validate Local Files

Run contextual validation after the manifest parses:

```bash
echolake validate-dataset path/to/dataset --check-files
```

Declared local paths must use POSIX separators, be relative, avoid `..`, and
name regular files inside the resolved dataset root. The containment check
follows symlinks. It covers bundled files, the referenced Attack Flow file, and
local observable rule files.

HTTP and HTTPS observable rules produce warnings because they are not fetched.
Remote dataset references are checked statically. The validator does not
download their content, verify checksums, count records, or check timestamp
registry membership.

### 8. Validate Declared Counts

Run count validation:

```bash
echolake validate-dataset path/to/dataset --check-counts
```

This option includes the file checks. Every declared bundled `event_count` must
equal the count produced by the current EchoLake replay path. Missing counts
produce warnings. JSON and JSONL count object records only. CSV counts logical
data rows after the header, text skips blank lines, and `auto` applies runtime
line detection without inferring from the filename. XML uses the runtime XML
path, including the Windows Event XML in-place path when applicable.
Gzip-compressed inputs are supported. Malformed structured input fails the check.

If all bundled files declare counts, these additional invariants apply:

- `provenance.regenerated.total_events` must equal their sum.
- `badactors_quality.attribution.technique_events` must equal their sum.

### 9. Write Canonical YAML When Needed

The Python writer emits a canonical representation:

```python
from echolake.datasets import DatasetManifest

manifest = DatasetManifest.from_file("dataset.yaml")
manifest.to_file("dataset.canonical.yaml")
```

`to_file()` adds the manifest version, uses YAML aliases such as `schema` and
`from`, and preserves explicitly authored values even when they equal model
defaults. It preserves an authored `defaults.replay` key. Review the diff before
replacing an existing manifest.

The writer cannot recover a field that failed strict parsing. Move unknown
fields to a supported location before canonicalizing.

## Python API Compatibility

Manifest sections are typed Pydantic models. Prefer attribute access in new
code:

```python
manifest = DatasetManifest.from_file("dataset.yaml")
dataset_name = manifest.metadata.name
echo_defaults = manifest.defaults.effective_echo if manifest.defaults else None
```

Read-only dict-style access remains available for callers migrating from the
former dict-backed sections:

```python
same_name = manifest.metadata["name"]
same_version = manifest.metadata.get("version")
```

Use `model_dump(by_alias=True)` when a dictionary is required. The canonical
file writer has additional logic to retain explicitly authored default values,
so use `to_file()` for YAML output.

## Common Migration Errors

| Error | Action |
|-------|--------|
| `extra_forbidden` | Move the custom value to a modeled field, `extensions`, `properties`, or a documented free-form map. |
| Unsupported manifest version | Omit the field for implicit version 1 or set it to `"1.0.0"`. |
| Unsupported schema | Change the value to `raw` or omit it. |
| Missing or unregistered bundled sourcetype warning | Add or register a specific sourcetype when available, or confirm the custom or generic fallback is intentional. |
| Path escape or missing local file | Use a relative path that resolves to a regular file inside the dataset root. |
| Event count mismatch | Recount events with the declared EchoLake input path and correct either the file or its declaration. |
| Reversed timestamp range | Correct the source timestamps so the start is not after the end. |
| `defaults.echo` and `defaults.replay` disagree | Keep one key, or make both values equal. |
| BadActors quality invariant failure | Recalculate the score, ratios, run selection, and packaged event total. |

## Completion Checklist

- The manifest parses under contract 1.0.0.
- Custom data uses supported extension boundaries.
- Every explicit schema is `raw`.
- Sourcetype warnings are reviewed.
- Local file and containment checks pass.
- Declared count checks pass.
- A canonical write preserves every authored value that should remain.
- The repository validator passes across the complete dataset collection.

## Related Documentation

- [Dataset Format](DATASET_FORMAT.md)
- [Collection Environment](COLLECTION_ENVIRONMENT.md)
- [Log Source Metadata](LOG_SOURCE_METADATA.md)
