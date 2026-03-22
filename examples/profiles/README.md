# Replay Profiles and Destinations

**Feature:** Reusable replay configurations with separation of concerns

## Architecture

EchoLake separates replay configuration into three independent components:

### 1. **Replay Profiles** - WHAT and HOW to replay

Define which datasets to replay and how to manipulate timestamps.

**Location:** `profiles/*.yaml`
**Contains:** Dataset references, replay timing, schema
**Reusable across:** Multiple executions, destinations, environments

### 2. **Destinations** - WHERE to send data

Define output targets (Chronicle, S3, etc.) without credentials.

**Location:** `destinations/*.yaml`
**Contains:** Connection parameters, format settings
**Reusable across:** Multiple profiles, schedules

### 3. **Credentials** - Authentication secrets

Stored separately, never committed to git.

**Location:** `~/.echolake/credentials.yaml` (gitignored)
**Contains:** API tokens, service account files, passwords
**Security:** Environment variables, secret managers

---

## Replay Profile Format

```yaml
profile:
  name: "profile-name"
  version: "1.0.0"
  description: "What this profile does"
  tags: [tag1, tag2]

# Multiple datasets (executed in order)
datasets:
  - ref: "local:meta-datasets/attack-suite"
    version: "*"
    description: "Why this dataset is included"

  - ref: "local:datasets/another-dataset"
    version: ">=1.0.0"
    # Per-dataset echo override
    echo:
      delta_factor: 2.0
      target_time: "now-2h"

# Global replay configuration
echo:
  delta_factor: 1.0
  base_time: "earliest"
  target_time: "now-1h"
  prevent_future: true

schema: "raw"
```

---

## Destination Format

```yaml
destination:
  name: "destination-name"
  description: "What this destination is"
  tags: [tag1, tag2]

type: "chronicle"  # or s3, gcs, azure_blob, local, stdout, http

connection:
  project_id: "your-project-id"
  log_type: "WINDOWS_SYSMON"
  region: "us-central1"

format: "jsonl"
schema: "raw"
```

**Supported Types:**
- `chronicle` - Google Chronicle
- `s3` - AWS S3
- `gcs` - Google Cloud Storage
- `azure_blob` - Azure Blob Storage
- `local` - Local filesystem
- `stdout` - Standard output
- `http` / `https` - Custom HTTP endpoints
- Custom types supported (extensible)

---

## Credentials Format

**File:** `~/.echolake/credentials.yaml` (never commit!)

```yaml
credentials:
  chronicle-prod:
    credentials_file: "/path/to/service-account.json"

  s3-archive:
    # Uses AWS credentials from environment or ~/.aws/
```

**Environment variables:**
```bash
export CHRONICLE_SA_FILE="/path/to/sa.json"
```

---

## Usage Examples

### CLI: Single Destination

```bash
# List available profiles
echolake list-profiles

# List available destinations
echolake list-destinations

# Replay profile to destination
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive

# With runtime overrides
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --target-time "now-2h" \
  --delta-factor 0.01

# Dry run first
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --dry-run
```

### CLI: Multiple Destinations

```bash
# Send to multiple destinations simultaneously
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --destination chronicle-prod \
  --destination s3-archive
```

### Python API

```python
from echolake.profiles import EchoProfile, Destination
from echolake.profiles.executor import ProfileExecutor

# Load profile
profile = EchoProfile.from_file("profiles/weekly-apt-simulation.yaml")

# Load destination(s)
dest = Destination.from_file("destinations/s3-archive.yaml")

# Execute replay
executor = ProfileExecutor(profile, [dest])
executor.execute()
```

### Notebook Environment

EchoLake's Python API works in any notebook environment (Jupyter, etc.).

---

## Multiple Datasets

A single profile can include multiple datasets, replayed in order:

```yaml
profile:
  name: "multi-stage-attack"
  description: "Attack progression over time"

datasets:
  # Stage 1: Initial access
  - ref: "local:meta-datasets/web-exploitation-cves"
    description: "Initial compromise"

  # Stage 2: Persistence
  - ref: "local:datasets/registry-persistence"
    description: "Establish persistence"

  # Stage 3: Credential access
  - ref: "local:meta-datasets/credential-dumping-t1003"
    description: "Steal credentials"

  # Stage 4: Lateral movement
  - ref: "local:meta-datasets/lateral-movement-suite"
    description: "Spread across network"

  # Stage 5: Impact
  - ref: "local:meta-datasets/ransomware-suite"
    description: "Deploy ransomware"

# All datasets use this timing
echo:
  delta_factor: 0.006  # 7 days → 1 hour
  target_time: "now-1h"
```

**Per-dataset overrides:**

```yaml
datasets:
  # Slow down initial access for detailed analysis
  - ref: "local:datasets/initial-access"
    echo:
      delta_factor: 2.0        # 2x slower
      target_time: "now-4h"

  # Speed up lateral movement
  - ref: "local:datasets/lateral-movement"
    echo:
      delta_factor: 0.1        # 10x faster
      target_time: "now-1h"
```

---

## Available Examples

### Profiles

1. **`weekly-apt-simulation.yaml`** - 7-day APT attack compressed to 1 hour
   - 5 datasets covering full attack lifecycle
   - Highly compressed for training scenarios

2. **`daily-baseline-traffic.yaml`** - Normal user activity baseline
   - 5 datasets showing benign activity patterns
   - Real-time replay for ML training

3. **`multi-speed-attack.yaml`** - Variable speed attack simulation
   - Demonstrates per-dataset replay overrides
   - Different compression ratios per stage

### Destinations

1. **`chronicle-prod.yaml`** - Google Chronicle
2. **`s3-archive.yaml`** - AWS S3 bucket
3. **`local-output.yaml`** - Local filesystem

### Credentials

1. **`credentials.yaml.template`** - Template showing all options
   - Copy to `~/.echolake/credentials.yaml`
   - Fill in real values (never commit!)

---

## Best Practices

### 1. Version Control

**DO commit:**
- ✅ Replay profiles (`profiles/*.yaml`)
- ✅ Destination configs (`destinations/*.yaml`)

**DON'T commit:**
- ❌ Credentials (`credentials.yaml`)
- ❌ API tokens, passwords, keys

### 2. Credentials Management

**Recommended approaches:**

1. **Environment variables** (best for CI/CD)
   ```bash
   export CHRONICLE_SA_FILE="/path/to/sa.json"
   ```

2. **Credentials file** (best for local dev)
   ```yaml
   # ~/.echolake/credentials.yaml (gitignored)
   credentials:
     chronicle-prod:
       credentials_file: "/path/to/sa.json"
   ```

3. **Secret managers** (best for production)
   Retrieve secrets from your preferred secret manager and pass them
   via environment variables or the credentials YAML file.

### 3. Naming Conventions

**Profiles:**
- Use descriptive names: `weekly-apt-simulation`, `daily-baseline`
- Include timeframe: `weekly-`, `daily-`, `monthly-`
- Include purpose: `-simulation`, `-training`, `-testing`

**Destinations:**
- Include environment: `chronicle-prod`, `chronicle-dev`, `s3-staging`
- Use consistent naming across teams

### 4. Testing

Always dry run first:

```bash
echolake echo-profile my-profile \
  --destination my-destination \
  --dry-run
```

Test with local destination before production:

```bash
echolake echo-profile my-profile \
  --destination local-output
```

---

## Security Considerations

1. **Never commit credentials** - Use `.gitignore` patterns
2. **Use environment variables** - Reference `${VAR}` in credentials
3. **Rotate tokens regularly** - Especially for production
4. **Principle of least privilege** - Minimal permissions needed
5. **Audit access** - Log who replayed what and where

---

## Scheduling

### Cron

```bash
# Weekly APT simulation every Monday at 2 AM
0 2 * * 1 echolake echo-profile weekly-apt-simulation --destination s3-archive
```

### Airflow

```python
from airflow import DAG
from airflow.operators.bash import BashOperator

replay_task = BashOperator(
    task_id='replay_apt_simulation',
    bash_command='echolake echo-profile weekly-apt-simulation --destination s3-archive'
)
```

---

## Related Documentation

- [FEATURES.md](../../docs/FEATURES.md) - All EchoLake features
- [DATASET_FORMAT.md](../../docs/DATASET_FORMAT.md) - Dataset specification
- [TIME_EXPRESSIONS.md](../../docs/TIME_EXPRESSIONS.md) - Time expression syntax
