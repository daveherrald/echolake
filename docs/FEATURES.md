# EchoLake Features Documentation

**Version:** 1.0.0
**Last Updated:** 2026-01-28

Complete reference for all EchoLake features, capabilities, and usage patterns.

## Table of Contents

1. [Overview](#overview)
2. [Core Features](#core-features)
3. [Echo Profiles](#echo-profiles)
4. [Command Reference](#command-reference)
5. [Timestamp Manipulation](#timestamp-manipulation)
6. [Dataset Management](#dataset-management)
7. [Input/Output Options](#inputoutput-options)
8. [Dry Run Mode](#dry-run-mode)
9. [Schema Support](#schema-support)
10. [Advanced Features](#advanced-features)
11. [Configuration Files](#configuration-files)
12. [Use Cases](#use-cases)

---

## Overview

EchoLake is a security log replay and timestamp manipulation tool designed for:
- Testing security detection rules with realistic timing
- Creating training datasets with current timestamps
- Simulating attack scenarios at different speeds
- Validating SIEM pipelines and data flows
- Supporting SOC training and purple team exercises

### Key Capabilities

✅ **Echo Profiles** - Reusable configurations with multiple datasets
✅ **Timestamp Manipulation** - Shift logs to any time period
✅ **Time Compression/Expansion** - Speed up or slow down events
✅ **Multiple Destinations** - Chronicle, S3, GCS, Azure, local
✅ **Multiple Input Sources** - Local files, S3, HTTP, datasets
✅ **Schema Transformation** - Raw, OCSF, and more
✅ **Dataset Management** - Package, share, and replay log collections
✅ **Credentials Management** - Secure storage separate from configs
✅ **Dry Run Mode** - Preview changes without writing output
✅ **Flexible Configuration** - CLI args, config files, or both
✅ **Dependency Resolution** - Recursive dataset dependencies
✅ **File Caching** - Automatic caching of remote files

---

## Core Features

### 1. Timestamp Manipulation

Modify log timestamps while preserving relative timing between events.

**Key Parameters:**
- **delta_factor** - Time compression/expansion multiplier
- **base_time** - Reference point for calculations
- **target_time** - Where to replay logs to
- **ceiling** - Prevent future timestamps

#### Time Compression

Compress 7 days of logs into 1 hour:

```bash
echolake echo \
  --input logs/week-long-attack.jsonl \
  --output replayed/ \
  --delta-factor 0.006 \
  --target-time "now-1h"
```

Calculation: 7 days = 168 hours → 168 / 1 = 0.006

#### Time Expansion

Slow down events 10x for detailed analysis:

```bash
echolake echo \
  --input logs/rapid-events.jsonl \
  --output slowed/ \
  --delta-factor 10.0
```

#### Time Shifting

Move logs from 2024 to today:

```bash
echolake echo \
  --input logs/2024-attack.jsonl \
  --output current/ \
  --target-time "now-1h"
```

**See:** [TIME_EXPRESSIONS.md](TIME_EXPRESSIONS.md) for full syntax

---

### 2. Multiple Input Sources

#### Local Files

```bash
# Single file
echolake echo --input /path/to/logs.jsonl --output out/

# Multiple files (use a directory or config file; --input takes a single value)
echolake echo --input /path/to/logs/ --output out/

# Directory (all .jsonl files)
echolake echo --input /path/to/logs/ --output out/
```

#### S3 Buckets

```bash
# Single S3 file
echolake echo \
  --input s3://my-bucket/logs/attack.jsonl \
  --output out/

# S3 prefix (all matching files)
echolake echo \
  --input s3://bucket/logs/ \
  --output out/
```

**Authentication:** Uses AWS credentials from environment or `~/.aws/credentials`

#### HTTP/HTTPS

> **Note:** HTTP/HTTPS sources are supported via dataset file references (in `dataset.yaml`), not directly via `--input`. To replay logs from an HTTP URL, create a dataset with a `references` entry pointing to the URL, then use `--dataset` to replay it.

```bash
# Use a dataset reference for HTTP sources
echolake echo \
  --dataset local:/path/to/dataset-with-http-refs \
  --output out/
```

#### Datasets

```bash
# Local dataset
echolake echo \
  --dataset local:/path/to/dataset \
  --output out/

# Preview dataset first
echolake preview-dataset local:/path/to/dataset --lines 10
```

---

### 3. Multiple Output Targets

#### Local Files

```bash
# Directory output
echolake echo --input logs.jsonl --output /path/to/output/

# Specific filename
echolake echo --input logs.jsonl --output /path/to/replayed.jsonl
```

#### S3 Buckets

```bash
echolake echo \
  --input logs.jsonl \
  --output s3://my-bucket/replayed/

# With prefix
echolake echo \
  --input logs.jsonl \
  --output s3://my-bucket/attacks/2025-01-15/
```

**Note:** Requires AWS write permissions on target bucket

#### Stdout

```bash
# Output to stdout
echolake echo --input logs.jsonl --output -

# Pipe to other tools
echolake echo --input logs.jsonl --output - | jq .

# Redirect to file
echolake echo --input logs.jsonl --output - > replayed.jsonl
```

---

### 4. Dry Run Mode

Preview changes without writing output files.

```bash
# Basic dry run
echolake echo \
  --input logs.jsonl \
  --output out/ \
  --dry-run

# Detailed dry run with timeline
echolake echo \
  --input logs.jsonl \
  --output out/ \
  --dry-run \
  --show-timeline
```

**Dry Run Output:**
```
=== DRY RUN MODE ===
No files will be written. This is a simulation.

Input Statistics:
  Files: 3
  Total events: 15,432
  Size: 12.4 MB
  Time span: 2024-06-15 10:00:00 UTC → 2024-06-22 18:30:00 UTC (7 days)

Replay Configuration:
  Delta factor: 0.006 (168.0x compression)
  Base time: 2024-06-15 10:00:00 UTC (earliest)
  Target time: 2025-01-28 20:00:00 UTC (now-1h)

Output Preview:
  Time span: 2025-01-28 20:00:00 UTC → 2025-01-28 21:00:00 UTC (1.0 hours)
  Ceiling applied: 0 events (0.0%)
  Files to write: 3
  Output format: jsonl

Would write to:
  - /path/to/output/file1.jsonl (5,123 events)
  - /path/to/output/file2.jsonl (8,234 events)
  - /path/to/output/file3.jsonl (2,075 events)
```

**See:** [DRY_RUN_MODE.md](DRY_RUN_MODE.md) for details

---

### 5. Schema Transformation

Transform logs between different schemas during replay.

#### Schema Types

**raw** - No transformation, preserve original format
```bash
echolake echo --input logs.jsonl --output out/ --input-schema raw
```

**lakehouse_bronze** - Transform to bronze layer schema
```bash
echolake echo --input logs.jsonl --output out/ --input-schema ocsf
```

**ocsf** - Transform to Open Cybersecurity Schema Framework
```bash
echolake echo --input logs.jsonl --output out/ --input-schema ocsf
```

#### Per-File Schema

Different schemas for different files (via config file):

```yaml
input:
  sources:
    - path: /logs/sysmon.jsonl
      schema: raw
    - path: /logs/network.jsonl
      schema: raw
```

---

### 6. Output Formats

#### JSONL (Default)

One JSON object per line - best for streaming and large files:

```bash
echolake echo --input logs.json --output out/ --output-format jsonl
```

#### JSON

Single JSON array:

```bash
echolake echo --input logs.jsonl --output out/ --output-format json
```

---

### 7. Timeline Ceiling

Prevent replayed logs from having future timestamps.

Future timestamp prevention is **on by default**. Use `--no-prevent-future` to disable it:

```bash
# Default behavior (future timestamps prevented, no flag needed)
echolake echo \
  --input logs.jsonl \
  --output out/

# Disable the ceiling to allow future timestamps
echolake echo \
  --input logs.jsonl \
  --output out/ \
  --no-prevent-future
```

**Default:** Enabled (prevents future timestamps)

**Example:**
```
Original:    2024-06-15 → 2024-06-22 (7 days)
Target:      now-1h
Ceiling:     now

Result:      2025-01-28 20:00 → 2025-01-28 21:00 (capped at now)
```

---

### 8. Dataset Preview

Preview log entries from datasets before replaying:

```bash
# Preview first 10 lines (default)
echolake preview-dataset local:/path/to/dataset

# Control number of lines
echolake preview-dataset local:/path/to/dataset --lines 5

# Preview meta-dataset (shows all dependencies)
echolake preview-dataset local:meta-datasets/ransomware-suite
```

**Output:**
```
Previewing dataset: local:meta-datasets/ransomware-suite

Found 7 file(s) in dataset

File 1/7:
https://media.githubusercontent.com/.../ransom-notes.log
Format: text
Description: Bulk ransom note creation
Downloading/caching...
Cached at: ~/.echolake/cache/datasets/file-refs/abc123_ransom-notes.log
Size: 145,234 bytes

Sample log entries:
   1: <Event xmlns='http://...'>...</Event>
   2: <Event xmlns='http://...'>...</Event>
  ... (10 of many lines shown)

File 2/7: ...
```

---

### 9. Configuration Files

Use YAML configuration files for complex scenarios.

#### Basic Config File

**echolake.yaml:**
```yaml
input:
  sources:
    - path: /logs/attack.jsonl

output:
  destination:
    type: local
    path: /replayed/
  format: jsonl

echo:
  delta_factor: 1.0
  base_time: "earliest"
  target_time: "now-1h"
```

**Usage:**
```bash
echolake echo --config echolake.yaml
```

#### Advanced Config File

```yaml
input:
  sources:
    - path: /logs/sysmon.jsonl
      schema: raw
    - path: /logs/cloudtrail.jsonl
      schema: raw
    - path: s3://bucket/network.jsonl
      schema: raw

output:
  destination:
    type: s3
    bucket: replayed-logs
    prefix: attacks/2025-01-28/
  format: jsonl

echo:
  delta_factor: 0.1        # 10x compression
  base_time: "earliest"
  target_time: "2025-01-28T15:00:00Z"
  prevent_future: true

schema: raw  # Default for files without explicit schema
```

#### Dataset Config File

```yaml
dataset:
  ref: "local:/datasets/ransomware-suite"
  version: "1.0.0"
  overrides:
    echo:
      delta_factor: 2.0    # Override dataset default

output:
  destination:
    type: local
    path: /replayed/
```

**Usage:**
```bash
echolake echo --config dataset-config.yaml
```

#### CLI Override

CLI arguments override config file values:

```bash
# Config says delta_factor: 1.0
# CLI overrides to 2.0
echolake echo --config config.yaml --delta-factor 2.0
```

**Priority:** CLI > Config File > Defaults

---

### 10. Cache Management

Automatic caching of remote files for faster repeated access.

#### Cache Location

**Default:** `~/.echolake/cache/datasets/file-refs/`

#### Cache Behavior

- Remote files (S3, HTTP) downloaded on first access
- Cached locally with checksum verification
- Reused on subsequent runs
- 88x speedup demonstrated on 1,866 datasets

#### Cache Statistics

```bash
# Check cache size
du -sh ~/.echolake/cache/

# Clear cache
rm -rf ~/.echolake/cache/
```

**Example Performance:**
- First run (1,866 datasets): 900 seconds, 7.2 GB downloaded
- Second run (cached): 10.2 seconds, 0 GB downloaded
- **Speedup: 88x**

---

## Echo Profiles

**NEW Feature:** Reusable replay configurations with separation of concerns.

Replay profiles enable you to create shareable, reusable configurations for replaying security logs. They separate **what to replay** (profiles), **where to send it** (destinations), and **how to authenticate** (credentials).

### Architecture

```
Echo Profile          Destination(s)         Credentials
(what & how)           (where)                (auth)
     │                      │                      │
     ├──────────────────────┼──────────────────────┤
     │                      │                      │
     └──────────────────────▼──────────────────────┘
                      Replay Engine
```

**Three Components:**

1. **Echo Profiles** (`profiles/*.yaml`) - ✅ Commit to git
   - Dataset references
   - Replay timing configuration
   - Schema settings
   - Multiple datasets support

2. **Destinations** (`destinations/*.yaml`) - ✅ Commit to git
   - Connection parameters (host, bucket, index, etc.)
   - Output format
   - No credentials!

3. **Credentials** (`~/.echolake/credentials.yaml`) - ❌ Never commit!
   - API tokens
   - Passwords
   - Service account files
   - Stored separately for security

### Quick Example

Create `profiles/weekly-training.yaml`:
```yaml
profile:
  name: "weekly-training"
  version: "1.0.0"
  description: "7-day APT attack compressed to 1 hour"

datasets:
  - ref: "local:meta-datasets/attack-suite"
  - ref: "local:datasets/lateral-movement"

echo:
  delta_factor: 0.006  # 7 days → 1 hour
  target_time: "now-1h"
```

Create `destinations/s3-archive.yaml`:
```yaml
destination:
  name: "s3-archive"

type: "s3"

connection:
  bucket: "security-datasets"
  prefix: "replays/2026-01/"
  region: "us-west-2"

format: "jsonl"
```

Run:
```bash
echolake echo-profile weekly-training --destination s3-archive
```

### Benefits

✅ **Reusable** - Define once, use repeatedly
✅ **Shareable** - Commit to git, share with team
✅ **Secure** - Credentials separate from config
✅ **Multi-destination** - Send to multiple targets simultaneously
✅ **Multi-dataset** - Combine multiple datasets in one profile
✅ **Schedulable** - Perfect for cron, Airflow, and more
✅ **Override-able** - Change settings at runtime

### Multiple Datasets

Profiles can include multiple datasets, replayed in order:

```yaml
profile:
  name: "multi-stage-attack"
  description: "Complete attack lifecycle"

datasets:
  # Stage 1: Initial access
  - ref: "local:meta-datasets/web-exploitation"
    description: "Initial compromise"

  # Stage 2: Persistence
  - ref: "local:datasets/registry-persistence"
    description: "Establish persistence"

  # Stage 3: Lateral movement
  - ref: "local:datasets/lateral-movement"
    description: "Spread across network"

  # Stage 4: Exfiltration
  - ref: "local:datasets/data-exfiltration"
    description: "Steal data"
```

### Per-Dataset Overrides

Each dataset can have its own replay configuration:

```yaml
datasets:
  # Slow down for analysis
  - ref: "local:datasets/reconnaissance"
    echo:
      delta_factor: 2.0      # 2x slower
      target_time: "now-4h"

  # Use global settings
  - ref: "local:datasets/exploitation"

  # Speed up
  - ref: "local:datasets/exfiltration"
    echo:
      delta_factor: 0.1      # 10x faster
      target_time: "now-30m"

# Global default
echo:
  delta_factor: 1.0
  target_time: "now-2h"
```

### Supported Destinations

| Type | Description |
|------|-------------|
| `chronicle` | Google Chronicle |
| `s3` | AWS S3 |
| `gcs` | Google Cloud Storage |
| `azure_blob` | Azure Blob Storage |
| `local` | Local filesystem |
| `stdout` | Standard output |
| `http` / `https` | Custom HTTP endpoints |
| *Custom* | Extensible for any destination |

### Multiple Destinations

Send to multiple destinations simultaneously:

```bash
echolake echo-profile my-profile \
  --destination chronicle-prod \
  --destination s3-archive
```

### Runtime Overrides

Override profile settings at runtime:

```bash
echolake echo-profile weekly-training \
  --destination s3-archive \
  --delta-factor 0.01 \
  --target-time "now-30m"
```

### CLI Commands

```bash
# List available profiles
echolake list-profiles
echolake list-profiles --tags apt,training

# List available destinations
echolake list-destinations
echolake list-destinations --type chronicle

# Replay with profile
echolake echo-profile PROFILE_NAME --destination DEST_NAME

# Dry run first
echolake echo-profile my-profile --destination my-dest --dry-run
```

### Python API

```python
from echolake.profiles.models import EchoProfile, Destination
from echolake.profiles.executor import ProfileExecutor

# Load profile and destination
profile = EchoProfile.from_file("profiles/weekly-training.yaml")
dest = Destination.from_file("destinations/s3-archive.yaml")

# Execute
executor = ProfileExecutor(profile, [dest])
executor.execute()
```

### Credentials Management

Store credentials separately in `~/.echolake/credentials.yaml`:

```yaml
credentials:
  s3-archive:
    # Uses AWS credentials from ~/.aws/credentials

  chronicle-prod:
    credentials_file: "/secure/service-account.json"
```

**Best Practices:**
- Use environment variables: `${VAR_NAME}`
- Use secret managers (AWS, Vault, etc.)
- Never commit credentials to git
- Rotate tokens regularly

### Notebook Integration

EchoLake's Python API works in any notebook environment (Jupyter, etc.).

### Scheduling

#### Cron
```bash
# Weekly on Monday at 2 AM
0 2 * * 1 echolake echo-profile weekly-training --destination s3-archive
```

#### Airflow
```python
from airflow import DAG
from airflow.operators.bash import BashOperator

replay_task = BashOperator(
    task_id='replay_training',
    bash_command='echolake echo-profile weekly-training --destination s3-archive'
)
```

### Example Profiles

**Example 1: Weekly APT Simulation**
```yaml
profile:
  name: "weekly-apt-simulation"
  version: "1.0.0"
  description: "7-day APT compressed to 1 hour"
  tags: [apt, simulation, training]

datasets:
  - ref: "local:meta-datasets/web-exploitation-cves"
  - ref: "local:meta-datasets/registry-persistence"
  - ref: "local:meta-datasets/credential-dumping-t1003"
  - ref: "local:meta-datasets/lateral-movement-suite"
  - ref: "local:meta-datasets/ransomware-suite"

echo:
  delta_factor: 0.006
  target_time: "now-1h"

schema: "raw"
```

**Example 2: Daily Baseline**
```yaml
profile:
  name: "daily-baseline-traffic"
  version: "1.0.0"
  description: "24 hours of normal activity"
  tags: [baseline, benign, ml-training]

datasets:
  - ref: "local:meta-datasets/normal-web-browsing"
  - ref: "local:meta-datasets/email-activity"
  - ref: "local:meta-datasets/file-access"
  - ref: "local:meta-datasets/network-communication"

echo:
  delta_factor: 1.0  # Real-time
  target_time: "now-24h"
```

### Security

**DO:**
- ✅ Commit profiles and destinations to git
- ✅ Store credentials in `~/.echolake/credentials.yaml` (gitignored)
- ✅ Use environment variables: `${VAR_NAME}`
- ✅ Use secret managers in production
- ✅ Rotate tokens regularly

**DON'T:**
- ❌ Commit credentials to git
- ❌ Hard-code secrets in profiles/destinations
- ❌ Share credentials in chat/email

**See:** [ECHO_PROFILES.md](ECHO_PROFILES.md) for complete documentation.

---

## Command Reference

### `echolake echo`

Echo logs with timestamp manipulation.

**Syntax:**
```bash
echolake echo [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--input PATH` | string | required | Input file or directory (single value) |
| `--output PATH` | string | required | Output destination |
| `--dataset PATH` | string | - | Dataset reference |
| `--config FILE` | string | - | Config file path |
| `--delta-factor N` | float | 1.0 | Time compression factor |
| `--base-time TIME` | string | "earliest" | Base time reference |
| `--target-time TIME` | string | "now-1h" | Target echo time |
| `--no-prevent-future` | flag | - | Disable future timestamp prevention (on by default) |
| `--input-schema TYPE` | string | "raw" | Input schema type |
| `--input-format TYPE` | string | auto | Input format |
| `--output-format TYPE` | string | "jsonl" | Output format |
| `--dry-run` | flag | false | Preview without writing |
| `--show-timeline` | flag | false | Show timeline in output |

**Examples:**

```bash
# Basic echo
echolake echo --input logs.jsonl --output out/

# Time compression (7 days → 1 hour)
echolake echo \
  --input week.jsonl \
  --output out/ \
  --delta-factor 0.006

# S3 to S3
echolake echo \
  --input s3://source/logs.jsonl \
  --output s3://dest/replayed/

# Directory of inputs
echolake echo \
  --input /path/to/logs/ \
  --output out/

# With config file
echolake echo --config config.yaml

# Dry run with timeline
echolake echo \
  --input logs.jsonl \
  --output out/ \
  --dry-run \
  --show-timeline
```

---

### `echolake preview-dataset`

Preview log entries from a dataset.

**Syntax:**
```bash
echolake preview-dataset DATASET_REF [OPTIONS]
```

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `DATASET_REF` | string | Dataset reference (local:, github:, etc.) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--lines N` | int | 10 | Number of lines to show per file |

**Examples:**

```bash
# Preview local dataset
echolake preview-dataset local:/path/to/dataset

# Show 5 lines per file
echolake preview-dataset local:dataset --lines 5

# Preview meta-dataset
echolake preview-dataset local:meta-datasets/ransomware-suite

# Preview from current directory
echolake preview-dataset local:.
```

**Output:**
```
Previewing dataset: local:/path/to/dataset

Found 3 file(s) in dataset

File 1/3:
/path/to/dataset/logs/auth.jsonl
Format: jsonl
Description: Authentication logs
Size: 1,234,567 bytes

Sample log entries:
   1: {"timestamp": "2025-01-15T10:00:00Z", "event": "login"}
   2: {"timestamp": "2025-01-15T10:05:00Z", "event": "logout"}
  ... (10 of 150 lines shown)

File 2/3: ...
```

---

### Dataset Commands

These commands are available for managing datasets:

```bash
# List available datasets
echolake list-datasets [--tags TAG] [--repository REPO]

# Search for datasets
echolake search-datasets QUERY [--search-in FIELD]

# Show dataset info
echolake info-dataset DATASET_REF

# Install (cache) a dataset
echolake install-dataset DATASET_REF [--version VERSION]

# Validate dataset manifest
echolake validate-dataset DATASET_PATH [--check-files]
```

---

## Timestamp Manipulation

### Delta Factor

Controls time compression/expansion.

**Formula:**
```
new_duration = original_duration × delta_factor
```

**Examples:**

| Original | Delta Factor | Result | Use Case |
|----------|-------------|---------|----------|
| 7 days | 0.006 | 1 hour | Training datasets |
| 1 hour | 2.0 | 2 hours | Slow down rapid events |
| 1 day | 0.042 | 1 hour | Compress daily logs |
| 10 min | 10.0 | 100 min | Expand for analysis |
| Any | 0.0 | All same time | Collapse timing |

**Calculate Delta Factor:**
```python
# Target: Compress 7 days to 1 hour
original_hours = 7 * 24  # 168 hours
target_hours = 1
delta_factor = target_hours / original_hours  # 0.006
```

### Base Time

Reference point for timestamp calculations.

**Options:**

| Value | Description |
|-------|-------------|
| `"earliest"` | Use earliest log timestamp (default) |
| `"latest"` | Use latest log timestamp |
| `"2025-01-15T10:00:00Z"` | Specific ISO8601 timestamp |
| `"2025-01-15"` | Date (assumes 00:00:00) |

**Example:**
```bash
# Use earliest timestamp as reference
echolake echo --input logs.jsonl --output out/ --base-time earliest

# Use specific time as reference
echolake echo --input logs.jsonl --output out/ --base-time "2024-06-15T10:00:00Z"
```

### Target Time

Where to replay the logs to (anchor point).

**Options:**

| Value | Description |
|-------|-------------|
| `"now"` | Current time |
| `"now-1h"` | 1 hour ago (default) |
| `"now-7d"` | 7 days ago |
| `"2025-01-28T15:00:00Z"` | Specific timestamp |

**Relative Time Syntax:**
- `now-1h`, `now-2h`, `now-24h` - Hours ago
- `now-1d`, `now-7d`, `now-30d` - Days ago
- `now-1w`, `now-4w` - Weeks ago

**Example:**
```bash
# Replay to 1 hour ago
echolake echo --input logs.jsonl --output out/ --target-time "now-1h"

# Replay to specific time
echolake echo --input logs.jsonl --output out/ --target-time "2025-01-28T15:00:00Z"
```

### Prevent Future

Ceiling to prevent future timestamps.

**Default:** Enabled

```bash
# Default behavior (future timestamps prevented, no flag needed)
echolake echo --input logs.jsonl --output out/

# Disabled - allow future timestamps
echolake echo --input logs.jsonl --output out/ --no-prevent-future
```

**Example:**
```
Current time: 2025-01-28 21:00:00 UTC

Default (future prevention on):
  Replayed range: 2025-01-28 20:00 → 2025-01-28 21:00 (capped)

With --no-prevent-future:
  Replayed range: 2025-01-28 20:00 → 2025-01-28 22:00 (uncapped)
```

**See:** [TIME_EXPRESSIONS.md](TIME_EXPRESSIONS.md) for complete reference

---

## Dataset Management

### Dataset Structure

```
my-dataset/
├── dataset.yaml          # Manifest
├── logs/                 # Bundled files (optional)
│   ├── file1.jsonl
│   └── file2.jsonl
└── README.md            # Documentation (optional)
```

### Dataset Types

#### 1. Simple Dataset (Bundled Files)

```yaml
metadata:
  name: "my-dataset"
  version: "1.0.0"
  description: "My security logs"

files:
  bundled:
    - path: "logs/sysmon.jsonl"
      format: "jsonl"
```

#### 2. Reference Dataset (External Files)

```yaml
metadata:
  name: "my-dataset"
  version: "1.0.0"
  description: "Logs on S3"

files:
  references:
    - uri: "s3://bucket/logs.jsonl"
      format: "jsonl"
      checksum: "sha256:abc..."
```

#### 3. Meta-Dataset (Dependencies)

```yaml
metadata:
  name: "attack-suite"
  version: "1.0.0"
  description: "Collection of related attacks"

files:
  bundled: []
  references: []

dependencies:
  - dataset: "local:/datasets/attack1"
    version: "*"
  - dataset: "local:/datasets/attack2"
    version: "*"
```

### Using Datasets

```bash
# Preview dataset
echolake preview-dataset local:/path/to/dataset

# Replay dataset
echolake echo --dataset local:/path/to/dataset --output out/

# Via config file
cat > config.yaml <<EOF
dataset:
  ref: "local:/path/to/dataset"
output:
  destination:
    type: local
    path: /output/
EOF

echolake echo --config config.yaml
```

**See:** [DATASET_FORMAT.md](DATASET_FORMAT.md) for complete specification

---

## Input/Output Options

### Input Sources

| Type | Example | Notes |
|------|---------|-------|
| Local file | `/path/to/file.jsonl` | Single file |
| Local directory | `/path/to/logs/` | All `.jsonl` files |
| S3 file | `s3://bucket/file.jsonl` | AWS credentials required |
| S3 prefix | `s3://bucket/logs/` | All matching files |
| HTTP/HTTPS | Via dataset references | Supported through dataset file refs, not directly via `--input` |
| Dataset | `local:/path/to/dataset` | Dataset manifest |

### Output Destinations

| Type | Example | Notes |
|------|---------|-------|
| Local directory | `/path/to/output/` | Creates directory if needed |
| Local file | `/path/to/output.jsonl` | Single file output |
| S3 bucket | `s3://bucket/output/` | AWS write permissions required |
| Stdout | `-` | Pipe to other tools |

### File Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| JSONL | `.jsonl` | Streaming, large files (default) |
| JSON | `.json` | Small files, exact structure |
| Text | `.txt`, `.log` | Plain text, CSV |
| XML | `.xml` | Windows Event Logs |

---

## Advanced Features

### 1. Multi-Pass Processing

EchoLake uses a two-pass algorithm for accurate timestamp manipulation:

**Pass 1: Analysis**
- Scan all input files
- Find earliest and latest timestamps
- Calculate time span and statistics

**Pass 2: Transformation**
- Apply delta factor and time shifts
- Transform timestamps
- Write output files

**Benefits:**
- Accurate time calculations
- Preserves relative timing
- Handles multiple files correctly

### 2. Dependency Resolution

Recursive resolution of dataset dependencies:

```
Meta-Dataset A
├── Dataset B
│   ├── Dataset D
│   └── Dataset E
└── Dataset C
    └── Dataset F
```

**Resolution order:**
1. Resolve Meta-Dataset A
2. Find dependencies B and C
3. Recursively resolve B → D, E
4. Recursively resolve C → F
5. Collect all files from D, E, F, B, C

### 3. File Caching

**Cache Structure:**
```
~/.echolake/
├── cache/
│   └── datasets/
│       └── file-refs/
│           ├── abc123_file1.jsonl
│           ├── def456_file2.jsonl
│           └── ...
└── config.yaml
```

**Cache Key:** SHA256 hash of file URI + filename

**Cache Validation:**
- Checksum verification (if provided)
- Size validation
- Automatic redownload on mismatch

### 4. Schema Transformation Pipeline

```
Input → Read → Parse → Transform → Format → Write → Output
         ↓                  ↓
      Detect schema   Apply transformations
```

**Transformations:**
- Timestamp field normalization
- Schema field mapping
- Data type conversions
- Enrichment (optional)

---

## Use Cases

### Use Case 1: SOC Training

**Scenario:** Create realistic attack scenarios for SOC analyst training

```bash
# Compress 7-day attack chain to 1 hour
echolake echo \
  --dataset local:meta-datasets/ransomware-suite \
  --output /training/2025-01-28/ \
  --delta-factor 0.006 \
  --target-time "now-2h"
```

**Result:** 7 days of ransomware activity compressed to 1 hour, ending 2 hours ago

### Use Case 2: SIEM Rule Testing

**Scenario:** Test detection rules with current timestamps

```bash
# Shift old logs to today for rule testing
echolake echo \
  --input /old-logs/2024-attack.jsonl \
  --output /test-logs/ \
  --target-time "now-30m"
```

**Result:** 2024 attack logs replayed with timestamps from 30 minutes ago

### Use Case 3: Pipeline Validation

**Scenario:** Validate data pipeline with controlled timing

```bash
# Slow down events 5x for detailed analysis
echolake echo \
  --input /rapid-events.jsonl \
  --output /slowed/ \
  --delta-factor 5.0 \
  --target-time "now-5m"
```

**Result:** Events spread out 5x, easier to trace through pipeline

### Use Case 4: Purple Team Exercise

**Scenario:** Simulate APT campaign over compressed timeframe

```bash
# Preview the attack chain first
echolake preview-dataset local:datasets/apt-attack-chain --lines 5

# Run dry run to validate
echolake echo \
  --dataset local:datasets/apt-attack-chain \
  --output /exercise/ \
  --delta-factor 0.01 \
  --dry-run \
  --show-timeline

# Execute the replay
echolake echo \
  --dataset local:datasets/apt-attack-chain \
  --output /exercise/ \
  --delta-factor 0.01 \
  --target-time "now-2h"
```

**Result:** Multi-week APT campaign compressed to a few hours for live exercise

### Use Case 5: Data Lake Population

**Scenario:** Populate data lake with historical attack patterns

```bash
echolake echo \
  --input s3://archive/attacks/2023/ \
  --output s3://datalake/security/attacks/ \
  --target-time "now-7d"
```

**Result:** Historical attacks placed 7 days ago in the data lake

### Use Case 6: Benchmark Creation

**Scenario:** Create reproducible benchmark datasets

```bash
# Configuration file for reproducibility
cat > benchmark.yaml <<EOF
input:
  sources:
    - path: s3://benchmarks/baseline.jsonl

output:
  destination:
    type: local
    path: /benchmarks/run-001/

echo:
  delta_factor: 1.0
  base_time: "2025-01-01T00:00:00Z"
  target_time: "2025-01-28T15:00:00Z"
  prevent_future: false
EOF

echolake echo --config benchmark.yaml
```

**Result:** Consistent, reproducible dataset for benchmarking

---

## Configuration Files

### Minimal Config

```yaml
input:
  sources:
    - path: /logs/file.jsonl

output:
  destination:
    type: local
    path: /output/
```

### Complete Config

```yaml
input:
  sources:
    - path: /logs/sysmon.jsonl
      schema: raw
    - path: /logs/cloudtrail.jsonl
      schema: "raw"
    - path: s3://bucket/network.jsonl

output:
  destination:
    type: s3
    bucket: replayed-logs
    prefix: attacks/2025-01-28/
  format: jsonl

echo:
  delta_factor: 0.1
  base_time: "earliest"
  target_time: "2025-01-28T15:00:00Z"
  prevent_future: true

schema: raw

# AWS credentials (optional, uses environment if not specified)
# aws:
#   access_key_id: AKIAIOSFODNN7EXAMPLE
#   secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
#   region: us-west-2
```

### Dataset Config

```yaml
dataset:
  ref: "local:/datasets/ransomware-suite"
  version: "1.0.0"
  overrides:
    echo:
      delta_factor: 2.0

output:
  destination:
    type: local
    path: /replayed/
```

---

## Performance Considerations

### File Caching

**First Run (no cache):**
- Downloads all remote files
- Verifies checksums
- Caches locally
- Time: ~900 seconds for 1,866 datasets (7.2 GB)

**Subsequent Runs (cached):**
- Uses local cache
- No network traffic
- Checksum validation only
- Time: ~10 seconds for 1,866 datasets
- **88x speedup**

### Optimization Tips

1. **Use JSONL format** - Streamable, memory-efficient
2. **Enable caching** - Automatic for remote files
3. **Use dry run first** - Validate before processing
4. **Batch inputs** - Use directory paths or datasets to process multiple files
5. **Parallel processing** - Future feature (coming soon)

---

## Troubleshooting

### Common Issues

**1. "File not found" error**
- Check file path is correct
- Verify file exists
- Use absolute paths when possible

**2. "Invalid timestamp" error**
- Check log format matches expected schema
- Verify timestamp field exists
- Use `--input-schema raw` to bypass validation

**3. S3 permission denied**
- Check AWS credentials configured
- Verify bucket permissions
- Test with AWS CLI: `aws s3 ls s3://bucket/`

**4. Out of memory**
- Use JSONL instead of JSON format
- Process files individually
- Reduce batch size

**5. Incorrect timing**
- Check `--delta-factor` calculation
- Verify `--base-time` and `--target-time`
- Use `--dry-run --show-timeline` to preview

---

## Related Documentation

- **[DATASET_FORMAT.md](DATASET_FORMAT.md)** - Dataset manifest specification
- **[TIME_EXPRESSIONS.md](TIME_EXPRESSIONS.md)** - Time expression syntax
- **[DRY_RUN_MODE.md](DRY_RUN_MODE.md)** - Dry run mode details
- **[TIMESTAMP_MANIPULATION.md](TIMESTAMP_MANIPULATION.md)** - Timestamp manipulation guide
- **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide
- **[README.md](../README.md)** - Project overview

---

## Feature Roadmap

### Implemented ✅
- ✅ Timestamp manipulation with delta factor
- ✅ Multiple input sources (local, S3, HTTP)
- ✅ Multiple output targets (local, S3, stdout)
- ✅ Dataset management and dependencies
- ✅ File reference caching
- ✅ Dry run mode
- ✅ Schema transformation (raw, bronze, ocsf)
- ✅ Configuration files
- ✅ Dataset preview command
- ✅ Timeline ceiling (prevent future)
- ✅ MITRE ATT&CK mapping (dataset metadata via `dataset.yaml` manifest)
- ✅ Dataset discovery commands (`list-datasets`, `search-datasets`, `info-dataset`, `install-dataset`, `validate-dataset`)

### Planned 🚧
- 🚧 GitHub dataset distribution
- 🚧 Dataset registry/catalog
- 🚧 Parallel processing
- 🚧 Progress indicators
- 🚧 Data validation and statistics
- 🚧 Web UI for dataset browsing
- 🚧 Dataset creation wizard
- 🚧 Advanced filtering
- 🚧 Custom transformations

---

**Version:** 1.0.0
**Last Updated:** 2026-01-28
