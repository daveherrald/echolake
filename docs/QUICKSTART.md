# EchoLake Quick Start Guide

Get started with EchoLake in 5 minutes.

---

## Installation

```bash
pip install echolake
```

---

## Basic Usage

### 1. Simple Replay (No Profile)

Replay a single log file with new timestamps:

```bash
echolake echo \
  --input logs/attack.jsonl \
  --output replayed/ \
  --target-time "now-1h"
```

**What this does:**
- Takes `logs/attack.jsonl`
- Shifts all timestamps to end 1 hour ago
- Writes output to `replayed/` directory

### 2. Time Compression

Compress 7 days of logs into 1 hour:

```bash
echolake echo \
  --input logs/week-long-attack.jsonl \
  --output replayed/ \
  --delta-factor 0.006 \
  --target-time "now-1h"
```

**Math:** 7 days = 168 hours, so 1 / 168 ≈ 0.006

### 3. Dry Run (Preview First)

See what will happen without writing files:

```bash
echolake echo \
  --input logs/attack.jsonl \
  --output replayed/ \
  --target-time "now-1h" \
  --dry-run
```

**Output:**
```
Dry Run Summary
===============
Input: logs/attack.jsonl
Total events: 1,247
Original time range: 2024-01-01 10:00 → 2024-01-08 10:00 (7 days)
Replay time range: 2026-01-31 09:00 → 2026-01-31 10:00 (1 hour)
Output: replayed/
```

---

## Using Echo Profiles

Profiles make replays reusable and shareable.

### 1. Create Your First Profile

Create `profiles/my-attack.yaml`:

```yaml
profile:
  name: "my-attack"
  version: "1.0.0"
  description: "My first attack simulation"

datasets:
  - ref: "local:meta-datasets/attack-suite"

echo:
  delta_factor: 1.0
  target_time: "now-1h"

schema: "raw"
```

### 2. Create a Destination

Create `destinations/local-output.yaml`:

```yaml
destination:
  name: "local-output"
  description: "Local filesystem"

type: "local"

connection:
  path: "./output/"

format: "jsonl"
```

### 3. Run the Replay

```bash
echolake echo-profile my-attack --destination local-output
```

Done! Logs are now in `./output/`

---

## Common Use Cases

### Scenario 1: Testing Detection Rules

You have old logs from 2024 and want to test your current detection rules.

```bash
# Shift 2024 logs to today
echolake echo \
  --input 2024-attack-logs/ \
  --output current/ \
  --target-time "now-1h"

# Now your SIEM will process them as recent events
```

### Scenario 2: SOC Training

Run a week-long attack in 1 hour for training exercises.

Create `profiles/weekly-training.yaml`:
```yaml
profile:
  name: "weekly-training"
  version: "1.0.0"
  description: "7-day attack in 1 hour"

datasets:
  - ref: "local:training-data/apt-attack"

echo:
  delta_factor: 0.006  # 7 days → 1 hour
  target_time: "now-1h"
```

Run:
```bash
echolake echo-profile weekly-training --destination s3-archive
```

### Scenario 3: Multiple Attacks to Multiple Destinations

Send different scenarios to different teams simultaneously.

```bash
echolake echo-profile apt-scenario \
  --destination s3-archive \
  --destination chronicle-prod \
  --destination s3-archive
```

### Scenario 4: Scheduled Replays

Set up a weekly cron job:

```bash
# Run every Monday at 2 AM
0 2 * * 1 echolake echo-profile weekly-training --destination s3-archive
```

---

## Working with Datasets

Datasets are collections of related log files with metadata.

### Dataset Structure

```
my-dataset/
├── dataset.yaml        # Metadata
├── logs/
│   ├── auth.jsonl     # Bundled log files
│   └── network.jsonl
└── README.md          # Documentation
```

### Create a Simple Dataset

1. Create directory:
```bash
mkdir -p my-dataset/logs
```

2. Create `dataset.yaml`:
```yaml
metadata:
  name: "my-dataset"
  version: "1.0.0"
  description: "My security logs"

files:
  bundled:
    - path: "logs/auth.jsonl"
      description: "Authentication logs"
      format: "jsonl"
      event_count: 100
```

3. Add logs:
```bash
cp my-logs/*.jsonl my-dataset/logs/
```

4. Use in profile:
```yaml
datasets:
  - ref: "local:my-dataset"
```

---

## Setting Up Credentials

### For AWS S3

1. Use AWS credentials from `~/.aws/credentials`:
```yaml
# No credentials needed in credentials.yaml
# Will use default AWS profile
```

2. Create destination `destinations/s3-archive.yaml`:
```yaml
destination:
  name: "s3-archive"

type: "s3"

connection:
  bucket: "my-security-logs"
  prefix: "replays/2026-01/"
  region: "us-west-2"

format: "jsonl"
```

3. Replay:
```bash
echolake echo-profile my-attack --destination s3-archive
```

---

## Python API Quick Start

### Basic Replay

```python
from echolake import Config, EchoEngine

config = Config.from_file("echolake.yaml")
engine = EchoEngine(config)
engine.setup()
stats = engine.run()
print(f"Processed {stats.events_written} events")
```

### Using Profiles

```python
from echolake.profiles.models import EchoProfile, Destination
from echolake.profiles.executor import ProfileExecutor

profile = EchoProfile.from_file("my-profile.yaml")
destinations = [Destination.from_file("local-output.yaml")]
executor = ProfileExecutor(profile, destinations)
executor.execute()
```

---

## Next Steps

### Learn More

- **[FEATURES.md](FEATURES.md)** - Complete feature reference
- **[ECHO_PROFILES.md](ECHO_PROFILES.md)** - In-depth profile guide
- **[DATASET_FORMAT.md](DATASET_FORMAT.md)** - Dataset specification
- **[TIME_EXPRESSIONS.md](TIME_EXPRESSIONS.md)** - Time expression syntax

### Examples

Explore example profiles and destinations:
```bash
ls examples/profiles/
ls examples/destinations/
```

### Get Help

```bash
# Command help
echolake --help
echolake echo --help
echolake echo-profile --help

# List available profiles
echolake list-profiles

# List available destinations
echolake list-destinations
```

### Community

- **GitHub:** https://github.com/daveherrald/echolake
- **Issues:** https://github.com/daveherrald/echolake/issues
- **Discussions:** https://github.com/daveherrald/echolake/discussions

---

## Troubleshooting

### Issue: "Profile not found"

```
Error: Profile not found: my-attack
```

**Fix:** Ensure `profiles/my-attack.yaml` exists

### Issue: "Destination not found"

```
Error: Destination not found: s3-archive
```

**Fix:** Ensure `destinations/s3-archive.yaml` exists

### Issue: "No credentials found"

```
Error: No credentials found for destination: chronicle-prod
```

**Fix:** Create `~/.echolake/credentials.yaml` with:
```yaml
credentials:
  chronicle-prod:
    credentials_file: "${CHRONICLE_SA_FILE}"
```

And set the environment variable:
```bash
export CHRONICLE_SA_FILE="/secure/path/to/service-account.json"
```

### Issue: "Invalid time expression"

```
Error: Invalid time expression: now-1x
```

**Fix:** Use valid time expressions:
- `now` - Current time
- `now-1h` - 1 hour ago
- `now-1d` - 1 day ago
- `now-1w` - 1 week ago
- `2026-01-31T10:00:00Z` - Specific time (ISO8601)

See [TIME_EXPRESSIONS.md](TIME_EXPRESSIONS.md) for full syntax.

---

## Tips and Tricks

### 1. Always Dry Run First

```bash
echolake echo-profile my-attack --destination s3-archive --dry-run
```

Preview what will happen before actually sending data.

### 2. Use Local Destinations for Testing

```bash
# Test locally first
echolake echo-profile my-attack --destination local-output

# Then production
echolake echo-profile my-attack --destination s3-archive
```

### 3. Override Settings at Runtime

```bash
# Profile has delta_factor: 1.0
# Override to 0.5 at runtime
echolake echo-profile my-attack \
  --destination local-output \
  --delta-factor 0.5
```

### 4. Combine Multiple Datasets

```yaml
datasets:
  - ref: "local:baseline-traffic"
  - ref: "local:attack-phase-1"
  - ref: "local:attack-phase-2"
```

Datasets replay in order, maintaining relative timing.

### 5. Version Your Profiles

```yaml
profile:
  name: "my-attack"
  version: "1.2.0"  # Increment when changing
```

Track changes over time, especially when sharing with teams.

---

Happy replaying!
