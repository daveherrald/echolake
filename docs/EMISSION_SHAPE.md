# Emission Shape (`--emit`)

Controls what EchoLake writes for each event: the native log the source
originally produced, or that log still wrapped in its Lakewatch bronze
envelope.

```bash
echolake echo --input ./logs --output ./replayed --emit raw     # default
echolake echo --input ./logs --output ./replayed --emit bronze
```

```yaml
echo:
  emit: raw
```

## The two shapes

A Lakewatch bronze row wraps the real log in an envelope:

```json
{
  "_event_time": "2026-06-29T15:21:23.162Z",
  "_ingest_time": "2026-06-29T15:21:23.162Z",
  "lw_id": "6556602da7b9099062631357",
  "_meta": { "file_path": "s3://...", "file_name": "..." },
  "data": { "Id": 4728, "MachineName": "EMU-WS01", "TimeCreated": "/Date(1782746483162)/" }
}
```

`--emit raw` writes the contents of `data` and nothing else. `--emit bronze`
writes the row unchanged, envelope included.

## Why raw is the default

Downstream parsers expect the log in the shape its vendor emits. A built-in
Windows parser reads `Id` and `TimeCreated` at the top level, so handing it a
bronze row means it sees `_event_time`, `lw_id` and an opaque `data` blob, and
matches nothing. Emitting the native log lets those parsers work on replayed
data without a per-source unwrapping step.

Use `--emit bronze` when the destination is itself a Lakewatch bronze table,
which already expects the envelope.

## Applies to bronze input only

The flag only changes behavior when the input schema is `lakehouse_bronze`.
The `raw` and `ocsf` schemas already carry the native log, so both settings
emit them identically.

## Timestamps inside the payload

The envelope is not the only place timestamps live. A Windows event carries
its own, and those are the ones a parser reads:

```json
"data": { "_time": 1782746483.162, "TimeCreated": "/Date(1782746483162)/" }
```

EchoLake shifts these along with the envelope fields, by the same delta, so an
unwrapped event is stamped at its replayed time rather than its original
capture time. Both fields keep the shape the source used: `_time` stays a
numeric epoch, `TimeCreated` stays a .NET JSON date. Rewriting either as an
ISO8601 string would make the event unparseable by the very parsers this mode
exists to feed.

Two fields describing one instant must agree, so rendering never drops below
millisecond precision on either path. A field the source wrote as a whole
number of seconds keeps that type and lands on the nearest second, so it stays
exact only to its own one-second resolution.

Recognized payload timestamps:

| Field | Format | Seen in |
|---|---|---|
| `data._time` | epoch seconds | Windows events, proxy logs |
| `data.TimeCreated` | .NET JSON date | Windows events |
| `data.ts` | epoch seconds | Zeek |
| `data._raw` | timestamps embedded in the log line | Squid and other text formats |

`data._raw` holds the original log line, which for a format like Squid *is*
the native log. Timestamps inside it are shifted in place, including the
leading epoch that starts a Squid access-log line.

A payload whose timestamp field is not on this list fails the run rather than
emitting an event at its original time. Add the field to the
`lakehouse_bronze` schema patterns to support a new source.

## Failure behavior

With `--emit raw`, an event whose envelope has no usable `data` object fails
the run:

```
emit=raw needs the native log in the bronze envelope's 'data' key, but this
event has no usable 'data' object (top-level keys: [...]). Refusing to emit a
mix of unwrapped and enveloped events.
```

This aborts rather than skipping the record. Writing the events that happened
to unwrap would produce a silently incomplete dataset that still reports a
successful run. Either fix the input schema or use `--emit bronze`.

## Upgrading

`raw` is the default, so a run that previously produced bronze rows now
produces native logs. Add `--emit bronze` (or `emit: bronze` in config) to any
pipeline whose destination expects the envelope, such as one loading a
Lakewatch bronze table.
