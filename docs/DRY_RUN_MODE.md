# Dry-Run Mode with Timeline Visualization

EchoLake's dry-run mode allows you to preview what a replay operation would do without actually writing any output files. This is perfect for:

- Testing time expression configurations
- Visualizing how events will be distributed
- Verifying timestamp transformations before committing to output
- Experimenting with delta factors and base times

## Usage

Add the `--dry-run` flag to any echo command:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time latest \
  --target-time now-2h \
  --dry-run
```

## What Dry-Run Does

1. **Reads all input files** - Processes files normally to extract events
2. **Calculates timestamp shifts** - Computes how timestamps would be transformed
3. **Generates statistics** - Tracks all the metrics a normal replay would
4. **Displays visualization** - Shows timeline and event distribution
5. **Skips writing** - Does NOT write any output files

## Visualization Output

### Timeline Display

The timeline shows both original and replayed timelines with markers for:

- **[EARLIEST]** - Earliest timestamp in the dataset
- **[LATEST]** - Latest timestamp in the dataset
- **[BASE]** - Base time used for calculations (if different from earliest/latest)
- **[EARLIEST/BASE]** or **[LATEST/BASE]** - Combined markers when they coincide

Example:

```
╭─────────────────────────── Original Timeline ───────────────────────────╮
│ ├──────────────────────────────────────────────────────────┤           │
│ │  [EARLIEST]                                  [LATEST/BASE]  │        │
│ │  2024-01-15 06:00                    14:45  │                        │
│ │  Time Span: 8.75 hours                              │                │
│ └──────────────────────────────────────────────────────────┘           │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Event Distribution Histogram

The replayed timeline includes a histogram showing event distribution:

```
│ │  Event Distribution:                                                 │
│ │  ████    ▄▄▄▄████                        ▄▄▄▄████                    │
│ │  12:55             17:18             20:57                           │
```

The histogram uses different bar heights to represent event density:
- `░` - Very few events
- `▂` - Low density
- `▄` - Medium density
- `█` - High density

### Transformation Summary

Shows the configuration and what would happen:

```
╭──────────────────────────────────────────────────────────────────╮
│ Transformation Configuration:                                    │
│   Base Time: latest → 2024-01-15 14:45:00                        │
│   Target Time: now-2h → 2026-01-28 21:40:48                      │
│   Delta Factor: 1.0x                                             │
│   Prevent Future: True                                           │
│   Ceiling Time: now                                              │
╰──────────────────────────────────────────────────────────────────╯
```

### Summary Statistics

```
╭────────────────────────── Dry Run Summary ──────────────────────────╮
│ What would happen:                                                  │
│   ✓ 9 events would be read from 2 file(s)                          │
│   ✓ All timestamps would be shifted                                │
│   ✓ Original span of 8.75h would become 8.75h                      │
│   ✓ 0 events would be in the future                                │
│   ✓ Output would be written to: test-dry-run-viz                   │
╰─────────────────────────────────────────────────────────────────────╯
```

## Use Cases

### 1. Testing Time Expressions

Before committing to a replay with complex time expressions, preview the results:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time earliest+1d+12h \
  --target-time now-1w-2d \
  --delta-factor 2.0 \
  --dry-run
```

This shows you exactly where events would land and how the timeline would be expanded.

### 2. Finding the Right Delta Factor

Experiment with different delta factors to find the right timeline compression/expansion:

```bash
# Try 2x expansion
echolake echo --input ./logs --output ./out --delta-factor 2.0 --dry-run

# Try 0.5x compression
echolake echo --input ./logs --output ./out --delta-factor 0.5 --dry-run
```

### 3. Validating Configuration Files

Test a configuration file before using it for real:

```bash
echolake echo --config my-config.yaml --dry-run
```

### 4. Understanding Event Distribution

See how events are distributed across time:

```bash
echolake echo \
  --input ./security-logs \
  --output ./test \
  --base-time latest \
  --target-time now \
  --dry-run
```

The histogram helps you understand:
- Are events clustered or evenly distributed?
- Where are the gaps in the timeline?
- How will delta expansion affect distribution?

## Combining with Verbose Mode

For maximum detail, combine dry-run with verbose:

```bash
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time latest-30m \
  --target-time now-2h \
  --delta-factor 1.5 \
  --dry-run \
  --verbose
```

This shows:
- Full configuration details
- Timeline visualization
- Event distribution
- Transformation summary

## Performance

Dry-run mode is nearly as fast as a full replay since it:
- Reads all files (same as normal)
- Parses all events (same as normal)
- Calculates all shifts (same as normal)

The only thing skipped is writing output, which is typically fast anyway.

## Tips

1. **Always dry-run first** - Especially with new configurations or time expressions
2. **Check the histogram** - It shows if events are where you expect them
3. **Verify "events in future"** - Should be 0 if `prevent_future: true`
4. **Compare spans** - Original vs replayed time span confirms delta factor
5. **Use with `--verbose`** - See full configuration being used

## Example Workflow

```bash
# 1. Dry-run to preview
echolake echo --config my-config.yaml --dry-run

# 2. Review the timeline and histogram
# 3. Adjust configuration if needed
# 4. Run for real

echolake echo --config my-config.yaml
```

## Troubleshooting

### "No events found to visualize"

This means no events were successfully read and parsed. Check:
- Input path is correct
- Input format matches your data
- Input schema is appropriate

### Histogram not showing

The histogram only appears in the replayed timeline, not the original. If you don't see it:
- Make sure you're looking at the replayed (green) timeline
- Ensure dry-run mode actually processed events

### Timeline markers overlapping

When BASE coincides with EARLIEST or LATEST, they're shown as combined markers:
- `[EARLIEST/BASE]` - Base time equals earliest
- `[LATEST/BASE]` - Base time equals latest

This is normal and helps declutter the display.

## Limitations

Dry-run mode:
- **Does NOT write files** - No output is created
- **Does NOT test output destination** - Cloud storage isn't validated
- **May use memory** - All events are held for histogram calculation

For very large datasets (millions of events), dry-run mode may use significant memory.
