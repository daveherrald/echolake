# Time Expression Support

EchoLake supports relative time expressions for flexible timestamp manipulation. This allows you to specify base times and target times using intuitive expressions.

## Supported Expressions

### Simple Keywords

- `now` - Current UTC time
- `earliest` - Earliest timestamp found in all input files
- `latest` - Latest timestamp found in all input files
- `auto` - Same as `earliest` (for backward compatibility)

### Time Units

- `s` - seconds
- `m` - minutes
- `h` - hours
- `d` - days
- `w` - weeks
- `mon` - months (30 days)
- `y` - years (365 days)

### Relative Expressions

Format: `<base><sign><number><unit>[<sign><number><unit>...]`

- **Base**: `now`, `earliest`, `latest`, or ISO8601 timestamp
- **Sign**: `+` (add) or `-` (subtract)
- **Number**: Integer value
- **Unit**: One of the time units above

## Examples

### Basic Expressions

```bash
# 2 hours ago
now-2h

# 1 day from now
now+1d

# 30 minutes before the earliest timestamp
earliest-30m

# 1 day after the latest timestamp
latest+1d
```

### Complex Expressions

Multiple offsets can be combined:

```bash
# 1 day, 12 hours, and 30 minutes ago
now-1d-12h-30m

# 1 day after earliest, minus 2 hours
earliest+1d-2h

# 2 weeks and 3 days ago
now-2w-3d
```

### ISO8601 Timestamps

You can also use absolute timestamps:

```bash
# Specific timestamp
2024-01-15T10:00:00Z

# With timezone offset
2024-01-15T10:00:00+05:00
```

## Configuration Options

### Base Time

Specifies the original reference timestamp for calculating deltas.

**CLI**: `--base-time`, `-b`

**Config file**:
```yaml
echo:
  base_time: latest-30m
```

**Examples**:
- `earliest` - Use the earliest timestamp from all files
- `latest` - Use the latest timestamp from all files
- `earliest+1d` - One day after the earliest timestamp
- `latest-2h` - Two hours before the latest timestamp

### Target Time

Specifies where to replay events (the new base time).

**CLI**: `--target-time`, `-t`

**Config file**:
```yaml
echo:
  target_time: now-2h
```

**Examples**:
- `now` - Current time (default)
- `now-2h` - Two hours ago
- `now-1d-12h` - 1.5 days ago
- `2024-01-15T10:00:00Z` - Specific timestamp

### Ceiling Time

Specifies the maximum allowed timestamp (for future prevention).

**CLI**: `--ceiling-time`

**Config file**:
```yaml
echo:
  ceiling_time: now
```

**Examples**:
- `now` - Current time (default)
- `now-1h` - One hour ago
- `now+1d` - One day from now

## Use Cases

### Replay events starting from latest timestamp

Use the latest timestamp as the reference point:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time latest \
  --target-time now-2h
```

This replays events so that the latest event occurred 2 hours ago.

### Replay events from a day after earliest

Start from a point 1 day after the earliest event:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time earliest+1d \
  --target-time now-1w
```

This calculates deltas from "earliest + 1 day" and replays them ending 1 week ago.

### Compress timeline and replay to the past

Compress events to 50% of original duration and replay to the past:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time earliest \
  --target-time now-1d-12h \
  --delta-factor 0.5
```

This compresses the timeline by 50% and replays events ending 1.5 days ago.

### Expand timeline with latest as reference

Use latest timestamp as base and expand timeline:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time latest-30m \
  --target-time now \
  --delta-factor 2.0
```

This uses "latest - 30 minutes" as the reference, doubles the time deltas, and replays ending now.

## Configuration File Example

```yaml
echo:
  delta_factor: 2.0
  base_time: latest-30m
  target_time: now-2h
  prevent_future: true
  ceiling_time: now

input:
  source:
    type: local
    path: ./logs
  format: jsonl
  schema: raw

output:
  destination:
    type: local
    path: ./replayed
  format: jsonl
```

## How It Works

1. **Parse Expression**: EchoLake parses the time expression and validates the syntax
2. **Read Events**: All input files are read and timestamps are extracted
3. **Resolve Base Time**:
   - For `earliest` or `latest`, the actual values are determined from the events
   - Offsets are applied to calculate the final base time
4. **Calculate Deltas**: Time deltas are calculated from the base time for each event
5. **Apply Transformation**:
   - Deltas are multiplied by `delta_factor`
   - New timestamps are calculated: `target_time + (original_delta * delta_factor)`
   - Future prevention is applied if enabled

## Validation

Time expressions are validated at configuration time:

```bash
# Validate configuration
echolake validate config.yaml

# This will check:
# - Expression syntax is correct
# - Time units are valid
# - Expression format matches the pattern
```

Invalid expressions will produce clear error messages:

```
Invalid time expression: now-1x.
Expected format: now|earliest|latest[+/-<number><unit>...] or ISO8601 timestamp
```

## Backward Compatibility

All existing configurations continue to work:

- `base_time: auto` → Uses earliest (same as before)
- `base_time: earliest` → Uses earliest (same as before)
- `target_time: now` → Uses current time (same as before)
- ISO8601 timestamps → Work as before

## Tips

1. **Use `latest` for recent data**: When replaying recent logs, `latest` provides a more intuitive reference point
2. **Combine with delta factor**: Use `earliest+1d` with `delta_factor: 2.0` to skip the first day and expand the timeline
3. **Test with verbose mode**: Use `--verbose` to see exactly how timestamps are being calculated
4. **Use ceiling time wisely**: Set `ceiling_time: now-1h` to ensure all events appear at least 1 hour old

## Troubleshooting

### Cannot resolve 'earliest' without event data

This error occurs when using `earliest` or `latest` in contexts where events haven't been read yet. This should not happen in normal usage, but if it does:

- Ensure your input files exist and contain valid data
- Check that timestamp patterns are correctly configured

### Invalid time expression

Check that:
- Time units are spelled correctly (s, m, h, d, w, mon, y)
- Base keyword is one of: now, earliest, latest
- Sign is `+` or `-`
- Numbers are integers

### Events in future

If you see "Events in Future" in the output:

- Enable `prevent_future: true` in config
- Set appropriate `ceiling_time` value
- Adjust `target_time` to be further in the past
