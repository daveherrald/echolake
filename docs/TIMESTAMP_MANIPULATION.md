# Timestamp Manipulation in EchoLake

## Overview

EchoLake intelligently manipulates event timestamps while preserving the temporal relationships between events. This is critical for replaying security logs in a realistic manner.

## Core Algorithm

The timestamp manipulation follows this process:

1. **Find Base Time**: Identify the earliest timestamp in the original data (the "base")
2. **Calculate Max Delta**: Find the maximum time span from base to latest event
3. **Set New Base Time**:
   - If `prevent_future=True`: `new_base = now - (max_delta * delta_factor)`
   - If `prevent_future=False`: `new_base = target_time`
4. **Transform Each Event**: `new_timestamp = new_base + (original_delta * delta_factor)`

This ensures:
- ✅ Original time deltas are preserved/expanded/compressed correctly
- ✅ Latest event never exceeds current time (when `prevent_future=True`)
- ✅ All events are properly spaced relative to each other

## Example

**Original Events:**
```
Event 1: 2024-01-01 10:00:00 (base)
Event 2: 2024-01-01 10:05:00 (+5 min)
Event 3: 2024-01-01 10:10:00 (+5 min)
```

**With `delta_factor=2.0` and `prevent_future=True`:**
```
Event 1: 2026-01-28 22:25:34 (new_base)
Event 2: 2026-01-28 22:35:34 (+10 min, 2x original)
Event 3: 2026-01-28 22:45:34 (+10 min, 2x original)
```

The algorithm calculated:
- Original max_delta: 10 minutes
- Scaled max_delta: 20 minutes (10 * 2.0)
- New base time: now - 20 minutes = 22:25:34
- This ensures Event 3 lands at "now" (22:45:34)

## Configuration Options

### `delta_factor`

Controls time delta scaling:
- `1.0` - Preserve original deltas (default)
- `> 1.0` - Expand timeline (events spread out)
- `< 1.0` - Compress timeline (events closer together)

**Example:**
```yaml
echo:
  delta_factor: 2.0  # Double all time deltas
```

### `base_time`

Determines which original timestamp to use as reference:
- `"auto"` or `"earliest"` - Use earliest timestamp (default)
- `"latest"` - Use latest timestamp
- ISO8601 string - Use specific timestamp

**Example:**
```yaml
echo:
  base_time: "2024-01-01T10:00:00Z"  # Use specific base
```

### `target_time`

Sets where to replay events to:
- `"now"` - Current time (default)
- ISO8601 string - Specific target time

**Example:**
```yaml
echo:
  target_time: "now"  # Replay to current time
```

### `prevent_future`

Controls whether to prevent timestamps beyond current time:
- `true` - Adjust base so latest event is at/before "now" (default)
- `false` - Allow events in the future

**Example:**
```yaml
echo:
  prevent_future: true  # Keep all events in past/present
  ceiling_time: "now"   # Maximum allowed timestamp
```

## Use Cases

### 1. Testing with Recent Data

Replay old logs as if they just happened:

```yaml
echo:
  delta_factor: 1.0
  target_time: "now"
  prevent_future: true
```

**Result:** Events maintain original spacing but are shifted to end at current time.

### 2. Expanding Timeline for Analysis

Spread events out for easier analysis:

```yaml
echo:
  delta_factor: 10.0
  prevent_future: true
```

**Result:** 1 hour of original logs becomes 10 hours, easier to analyze individual events.

### 3. Compressing Timeline

Compress long datasets for faster ingestion testing:

```yaml
echo:
  delta_factor: 0.1
  prevent_future: true
```

**Result:** 10 hours of original logs becomes 1 hour.

### 4. Replay to Specific Time Window

Replay events to a specific time in the past:

```yaml
echo:
  delta_factor: 1.0
  target_time: "2026-01-15T12:00:00Z"
  prevent_future: false  # Allow timestamps after target
```

**Result:** Latest event at 2026-01-15 12:00:00, earlier events proportionally in the past.

## Multi-Timestamp Support

EchoLake can handle schemas with multiple timestamp fields. Both timestamps are transformed with the same delta, preserving the relationship:

```yaml
input:
  schema: raw
  timestamp_patterns:
    - field: _event_time
      format: iso8601
      is_base: true  # Use as base for delta calculation
    - field: _ingest_time
      format: iso8601
```

## OCSF Support

For OCSF format, the `time` field (Unix milliseconds) is transformed:

```yaml
input:
  schema: ocsf
```

The schema handler automatically detects OCSF timestamp fields including:
- `time` (primary)
- `start_time`
- `end_time`
- `create_time`
- `modify_time`

## Advanced: Custom Timestamp Patterns

For raw data or custom schemas:

```yaml
input:
  schema: null  # or 'raw'
  timestamp_patterns:
    - field: custom_timestamp
      format: iso8601
      is_base: true
    - field: metadata.event_time
      format: unix_ms
      is_base: false
```

Supported formats:
- `iso8601` - ISO 8601 format (e.g., 2024-01-01T10:00:00Z)
- `rfc3339` - RFC 3339 format
- `unix_s` - Unix seconds since epoch
- `unix_ms` - Unix milliseconds since epoch
- Custom strftime patterns (e.g., `%Y-%m-%d %H:%M:%S`)

## Troubleshooting

### All events have the same timestamp

**Problem:** With `prevent_future=True`, events are collapsed to single timestamp.

**Old Behavior (Bug):** Algorithm was setting new_base to "now", then all events after base were capped.

**Fixed Behavior:** Algorithm now calculates new_base as `now - (max_delta * factor)`, ensuring proper spacing.

**Verify Fix:**
```bash
echolake echo --input data/ --output out/ --delta-factor 2.0 --verbose
```

You should see properly spaced timestamps in the output.

### Events are in the future

**Problem:** Latest event timestamp is after current time.

**Solution:** Ensure `prevent_future=true` in configuration:

```yaml
echo:
  prevent_future: true
  ceiling_time: "now"
```

### Deltas don't match expected factor

**Problem:** Time deltas aren't scaled by `delta_factor`.

**Check:**
1. Verify original events have varying timestamps
2. Check if `prevent_future` is causing ceiling effects
3. Ensure timestamp extraction is working (use `--verbose`)

## Performance Considerations

- Timestamp manipulation is performed in-memory
- For very large datasets (millions of events), consider processing in batches
- The algorithm scales linearly with number of events: O(n)

## Comparison with Logstory

EchoLake's algorithm is inspired by and compatible with Logstory's approach:

1. ✅ Determine original base time (earliest or latest)
2. ✅ Designate new base time (target time)
3. ✅ Compute new timestamps as offset from new base
4. ✅ Apply delta factor for expansion/compression
5. ✅ Prevent future timestamps with intelligent base adjustment

The key improvement in EchoLake is the automatic calculation of `new_base` when `prevent_future=true`, ensuring the latest event lands at or before the ceiling time.
