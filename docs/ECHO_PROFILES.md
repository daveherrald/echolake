# Echo Profiles and Destinations

**Feature:** Reusable echo configurations with separation of concerns

**Version:** 1.0.0
**Last Updated:** 2026-01-31

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Echo Profile Format](#echo-profile-format)
5. [Destination Format](#destination-format)
6. [Credentials Management](#credentials-management)
7. [Multiple Datasets](#multiple-datasets)
8. [CLI Reference](#cli-reference)
9. [Python API](#python-api)
10. [Examples](#examples)
11. [Best Practices](#best-practices)
12. [Security](#security)

---

## Overview

Replay profiles enable you to create reusable, shareable configurations for replaying security logs. They separate **what to replay** (profiles), **where to send it** (destinations), and **how to authenticate** (credentials).

### Why Use Echo Profiles?

**Without profiles:**
```bash
# Repeat this every time...
echolake echo \
  --input meta-datasets/attack-suite/ \
  --input datasets/lateral-movement/ \
  --input datasets/credential-dumping/ \
  --input datasets/data-exfiltration/ \
  --output s3://security-datasets/replayed/ \
  --delta-factor 0.006 \
  --target-time "now-1h" \
  --input-schema raw
```

**With profiles:**
```bash
# Simple, repeatable, shareable
echolake echo-profile weekly-apt-simulation --destination s3-archive
```

### Key Benefits

✅ **Reusable** - Define once, use many times
✅ **Shareable** - Commit profiles to git, share with team
✅ **Flexible** - Override settings at runtime
✅ **Secure** - Credentials separate from configuration
✅ **Multi-destination** - Send to multiple targets simultaneously
✅ **Multi-dataset** - Combine multiple datasets in one profile
✅ **Schedulable** - Perfect for cron, Airflow, and more

---

## Architecture

EchoLake separates replay configuration into three independent components:

### 1. Echo Profiles - WHAT and HOW to replay

Define which datasets to replay and how to manipulate timestamps.

**Location:** `profiles/*.yaml`
**Contains:** Dataset references, replay timing, schema
**Reusable across:** Multiple executions, destinations, environments
**Committed to git:** ✅ Yes

### 2. Destinations - WHERE to send data

Define output targets (Chronicle, S3, etc.) without credentials.

**Location:** `destinations/*.yaml`
**Contains:** Connection parameters, format settings
**Reusable across:** Multiple profiles, schedules
**Committed to git:** ✅ Yes

### 3. Credentials - Authentication secrets

Stored separately, never committed to git.

**Location:** `~/.echolake/credentials.yaml` (gitignored)
**Contains:** API tokens, service account files, passwords
**Security:** Environment variables, secret managers
**Committed to git:** ❌ Never!

### Diagram

```
┌─────────────────────┐
│  Echo Profile     │  What to replay & how
│  ✅ Commit to git   │  • Dataset references
└──────────┬──────────┘  • Timing configuration
           │             • Schema settings
           ├─────────────────────────┐
           │                         │
┌──────────▼──────────┐   ┌─────────▼──────────┐
│  Destination #1     │   │  Destination #2    │  Where to send
│  ✅ Commit to git   │   │  ✅ Commit to git  │  • Host/endpoint
└──────────┬──────────┘   └─────────┬──────────┘  • Connection params
           │                        │              • Format settings
           └────────┬───────────────┘
                    │
         ┌──────────▼──────────┐
         │  Credentials        │  How to authenticate
         │  ❌ NEVER commit!   │  • API tokens
         └─────────────────────┘  • Passwords
                                  • Service accounts
```

---

## Quick Start

### 1. Install EchoLake

```bash
pip install echolake
```

### 2. Create Your First Profile

Create `profiles/my-first-profile.yaml`:

```yaml
profile:
  name: "my-first-profile"
  version: "1.0.0"
  description: "My first echo profile"

datasets:
  - ref: "local:meta-datasets/attack-suite"
    description: "Sample attack data"

echo:
  delta_factor: 1.0
  target_time: "now-1h"

schema: "raw"
```

### 3. Create a Local Destination

Create `destinations/local-output.yaml`:

```yaml
destination:
  name: "local-output"
  description: "Local filesystem output"

type: "local"

connection:
  path: "./replayed-logs/"

format: "jsonl"
```

### 4. Run Your First Replay

```bash
echolake echo-profile my-first-profile --destination local-output
```

Done! Your logs are now in `./replayed-logs/`

---

## Echo Profile Format

### Complete Specification

```yaml
# Profile metadata (required)
profile:
  name: "profile-name"              # Required: unique identifier
  version: "1.0.0"                  # Required: semantic version
  description: "Human description"  # Optional but recommended
  author: "your-email@example.com"  # Optional
  tags: [tag1, tag2]                # Optional: for categorization

# Datasets to replay (required, at least one)
datasets:
  - ref: "local:meta-datasets/attack-suite"
    version: "*"                           # Optional: version constraint
    description: "Why this dataset"        # Optional but recommended

    # Optional: override schema for this dataset
    schema: "raw"

    # Optional: override replay config for this dataset
    echo:
      delta_factor: 2.0
      target_time: "now-2h"

  - ref: "local:datasets/another-dataset"
    version: ">=1.0.0"

# Global replay configuration (optional)
echo:
  delta_factor: 1.0           # Time compression (1.0 = real-time)
  base_time: "earliest"       # earliest, latest, or ISO8601
  target_time: "now-1h"       # When to replay to
  prevent_future: true        # Prevent timestamps in future

# Global schema (optional, default: raw)
schema: "raw"  # raw, ocsf, lakehouse_bronze

# Additional defaults (optional)
defaults:
  custom_field: "custom_value"
```

### Dataset References

Dataset references use a URI-like format:

```yaml
datasets:
  # Local directory
  - ref: "local:meta-datasets/attack-suite"

  # Local absolute path
  - ref: "local:/absolute/path/to/dataset"

  # Future: GitHub
  - ref: "github:org/repo/path/to/dataset"

  # Future: S3
  - ref: "s3://bucket/prefix/dataset"
```

### Version Constraints

Use semantic versioning constraints:

```yaml
datasets:
  - ref: "local:dataset"
    version: "*"           # Any version

  - ref: "local:dataset"
    version: "1.0.0"       # Exact version

  - ref: "local:dataset"
    version: ">=1.0.0"     # Minimum version

  - ref: "local:dataset"
    version: "~1.2.0"      # Compatible with 1.2.x
```

---

## Destination Format

### Complete Specification

```yaml
# Destination metadata (required)
destination:
  name: "destination-name"        # Required: unique identifier
  description: "Human description" # Optional but recommended
  tags: [tag1, tag2]              # Optional: for categorization

# Destination type (required)
type: "chronicle"  # See supported types below

# Connection parameters (required)
connection:
  # Generic fields
  host: "https://example.com"
  port: 8088
  path: "/services/collector"

  # Cloud storage fields
  bucket: "my-bucket"
  prefix: "logs/security/"
  region: "us-west-2"
  project_id: "my-project"

  # SIEM-specific fields
  index: "security"
  source: "echolake"
  sourcetype: "json"
  log_type: "WINDOWS_SYSMON"

  # Extensibility
  extra:
    custom_field: "custom_value"

# Output format (optional, default: jsonl)
format: "jsonl"  # jsonl, json, text

# Schema transformation (optional)
schema: "raw"
```

### Supported Destination Types

| Type | Description | Example Use Case |
|------|-------------|------------------|
| `chronicle` | Google Chronicle | Send to Chronicle SIEM |
| `s3` | AWS S3 | Archive to S3 bucket |
| `gcs` | Google Cloud Storage | Archive to GCS bucket |
| `azure_blob` | Azure Blob Storage | Archive to Azure |
| `local` | Local filesystem | Development, testing |
| `stdout` | Standard output | Debugging, piping |
| `http` / `https` | Custom HTTP endpoint | Custom APIs |
| `multi` | Multiple destinations | Fan-out to multiple targets |
| *Custom* | Extensible | Your custom destination |

### Example Destinations

#### Google Chronicle

```yaml
destination:
  name: "chronicle-prod"
  description: "Google Chronicle production"
  tags: [chronicle, production]

type: "chronicle"

connection:
  project_id: "security-prod-12345"
  log_type: "WINDOWS_SYSMON"
  region: "us-central1"

format: "jsonl"
```

#### AWS S3

```yaml
destination:
  name: "s3-archive"
  description: "S3 long-term archive"
  tags: [s3, archive]

type: "s3"

connection:
  bucket: "security-datasets"
  prefix: "replays/2026-01/"
  region: "us-west-2"

format: "jsonl"
```

#### Local Filesystem

```yaml
destination:
  name: "local-dev"
  description: "Local development output"
  tags: [local, development]

type: "local"

connection:
  path: "./replayed-logs/"

format: "jsonl"
```

---

## Credentials Management

Credentials are stored separately from profiles and destinations for security.

### File Location

Default: `~/.echolake/credentials.yaml`
Override: `ECHOLAKE_CREDENTIALS_FILE` environment variable

### Credentials Format

```yaml
credentials:
  # Destination name matches destination config
  chronicle-prod:
    credentials_file: "/secure/path/to/service-account.json"
    # OR environment variable:
    # credentials_file: "${CHRONICLE_SA_FILE}"

  s3-archive:
    # Option 1: Use AWS environment variables (recommended)
    # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY

    # Option 2: Explicit credentials (not recommended)
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE"
    aws_secret_access_key: "wJalr..."

    # Option 3: Use ~/.aws/credentials (best for local dev)
    # No credentials needed

  custom-api:
    api_key: "${CUSTOM_API_KEY}"
    # OR username/password:
    username: "${API_USERNAME}"
    password: "${API_PASSWORD}"
```

### Environment Variables

Create `.env` file (gitignored):

```bash
# Chronicle
export CHRONICLE_SA_FILE="/secure/service-account.json"

# Custom API
export CUSTOM_API_KEY="secret-api-key-here"
```

Load with:
```bash
source .env
echolake echo-profile my-profile --destination chronicle-prod
```

### Secret Managers

EchoLake does not ship its own secret-manager integrations. Credentials are loaded from YAML files (`~/.echolake/credentials.yaml`) or environment variables, as shown above. If you use a secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, etc.), retrieve the values in your own code or shell script and pass them via environment variables.

### Security Best Practices

1. **Never commit credentials to git**
   - Use `.gitignore` patterns
   - Store credentials separately

2. **Use environment variables**
   - Reference with `${VAR_NAME}` syntax
   - Load from `.env` files (gitignored)

3. **Use secret managers in production**
   - Platform-specific secret stores
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault

4. **Rotate tokens regularly**
   - Especially for production environments
   - Set expiration dates

5. **Principle of least privilege**
   - Grant minimum permissions needed
   - Use role-based access control

6. **Audit access**
   - Log who replayed what and where
   - Track credential usage

---

## Multiple Datasets

A single profile can include multiple datasets, replayed in order.

### Use Cases

- **Multi-stage attacks** - Initial access → Persistence → Lateral movement → Exfiltration
- **Baseline + anomaly** - Normal traffic followed by attack
- **Before/during/after** - Pre-attack baseline, attack, post-attack cleanup
- **Composite scenarios** - Combine multiple attack techniques

### Example: Multi-Stage Attack

```yaml
profile:
  name: "multi-stage-apt"
  version: "1.0.0"
  description: "Complete APT attack lifecycle"
  tags: [apt, multi-stage, training]

datasets:
  # Stage 1: Initial access (T1078 - Valid Accounts)
  - ref: "local:meta-datasets/web-exploitation-cves"
    description: "Initial compromise via web vulnerability"

  # Stage 2: Persistence (T1547 - Boot/Logon Autostart)
  - ref: "local:datasets/registry-persistence"
    description: "Establish registry-based persistence"

  # Stage 3: Credential access (T1003 - OS Credential Dumping)
  - ref: "local:meta-datasets/credential-dumping-t1003"
    description: "Steal credentials via LSASS dump"

  # Stage 4: Lateral movement (T1021 - Remote Services)
  - ref: "local:meta-datasets/lateral-movement-suite"
    description: "Spread across network via RDP/SMB"

  # Stage 5: Impact (T1486 - Data Encrypted for Impact)
  - ref: "local:meta-datasets/ransomware-suite"
    description: "Deploy ransomware payload"

# Compress 7 days into 1 hour
echo:
  delta_factor: 0.006  # 168 hours → 1 hour
  target_time: "now-1h"
  base_time: "earliest"

schema: "raw"
```

### Per-Dataset Overrides

Each dataset can override the global replay configuration:

```yaml
profile:
  name: "variable-speed-attack"
  version: "1.0.0"

datasets:
  # Slow down initial access for detailed analysis
  - ref: "local:datasets/initial-access"
    description: "Initial compromise (slowed 2x)"
    echo:
      delta_factor: 2.0        # 2x slower than global
      target_time: "now-4h"    # Start 4 hours ago

  # Use global settings for most stages
  - ref: "local:datasets/persistence"
  - ref: "local:datasets/lateral-movement"

  # Speed up final stage
  - ref: "local:datasets/exfiltration"
    description: "Data exfiltration (10x faster)"
    echo:
      delta_factor: 0.1        # 10x faster than global
      target_time: "now-30m"   # Finish 30 minutes ago

# Global default
echo:
  delta_factor: 1.0  # Real-time
  target_time: "now-2h"
```

### Configuration Merge Priority

When multiple configurations exist, they merge with this priority (highest to lowest):

1. **CLI arguments** - `--delta-factor`, `--target-time`, etc.
2. **Per-dataset overrides** - Dataset-level `echo:` section
3. **Global profile config** - Profile-level `echo:` section
4. **EchoLake defaults** - Built-in defaults

Example:
```bash
# Profile has: delta_factor: 1.0
# Dataset override: delta_factor: 2.0
# CLI argument: --delta-factor 3.0

# Result: delta_factor = 3.0 (CLI wins)
```

---

## CLI Reference

### List Profiles

```bash
# List all available profiles
echolake list-profiles

# List with filtering
echolake list-profiles --tags apt,simulation
echolake list-profiles --author "security-team@example.com"
```

### List Destinations

```bash
# List all available destinations
echolake list-destinations

# List with filtering
echolake list-destinations --type chronicle
echolake list-destinations --tags production
```

### Echo with Profile

```bash
# Basic echo
echolake echo-profile PROFILE_NAME --destination DEST_NAME

# Examples
echolake echo-profile weekly-apt-simulation --destination s3-archive
echolake echo-profile daily-baseline --destination local-output
```

### Multiple Destinations

Send to multiple destinations simultaneously:

```bash
echolake echo-profile weekly-apt-simulation \
  --destination chronicle-prod \
  --destination s3-archive
```

### Runtime Overrides

Override profile settings at runtime:

```bash
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --delta-factor 0.01 \
  --target-time "now-30m" \
  --input-schema ocsf
```

### Dry Run

Preview what will be replayed:

```bash
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --dry-run
```

Output:
```
Dry Run Summary
===============
Profile: weekly-apt-simulation v1.0.0
Datasets: 5
Total events: 1,247
Time range: 2026-01-24 10:00:00 UTC → 2026-01-31 10:00:00 UTC (7 days)
After echo: 2026-01-31 09:00:00 UTC → 2026-01-31 10:00:00 UTC (1 hour)
Destinations: s3-archive
```

### Configuration File

Use a config file instead of CLI args:

Create `echo-config.yaml`:
```yaml
profile: weekly-apt-simulation
destinations:
  - chronicle-prod
  - s3-archive
overrides:
  delta_factor: 0.01
  target_time: "now-30m"
```

Run:
```bash
echolake echo-profile --config echo-config.yaml
```

---

## Python API

### Basic Usage

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

### Multiple Destinations

```python
# Load multiple destinations
chronicle = Destination.from_file("destinations/chronicle-prod.yaml")
s3 = Destination.from_file("destinations/s3-archive.yaml")

# Send to all
executor = ProfileExecutor(profile, [chronicle, s3])
executor.execute()
```

### Credentials from Code

```python
# Set credentials programmatically
chronicle.set_credentials(credentials_file="/secure/path/to/service-account.json")

# Or from environment
import os
chronicle.set_credentials(credentials_file=os.getenv("CHRONICLE_SA_FILE"))
```

### Creating Profiles Programmatically

```python
import yaml
from echolake.profiles import (
    EchoProfile,
    EchoProfileMetadata,
    EchoConfig,
    DatasetReference
)

# Create profile
profile = EchoProfile(
    profile=EchoProfileMetadata(
        name="my-custom-profile",
        version="1.0.0",
        description="Programmatically created profile"
    ),
    datasets=[
        DatasetReference(ref="local:datasets/attack-1"),
        DatasetReference(ref="local:datasets/attack-2")
    ],
    echo=EchoConfig(
        delta_factor=0.01,
        target_time="now-1h"
    )
)

# Serialize to YAML file
with open("profiles/my-custom-profile.yaml", "w") as f:
    yaml.dump(profile.model_dump(), f, default_flow_style=False)
```

### Notebook Integration

EchoLake's Python API works in any notebook environment (Jupyter, etc.).

---

## Examples

### Example 1: Weekly APT Simulation

**File:** `profiles/weekly-apt-simulation.yaml`

```yaml
profile:
  name: "weekly-apt-simulation"
  version: "1.0.0"
  description: "7-day APT attack compressed to 1 hour for training"
  author: "security-team@example.com"
  tags: [apt, simulation, training]

datasets:
  - ref: "local:meta-datasets/web-exploitation-cves"
    description: "Initial access via web vulnerability"

  - ref: "local:meta-datasets/registry-persistence"
    description: "Registry-based persistence"

  - ref: "local:meta-datasets/credential-dumping-t1003"
    description: "LSASS credential dumping"

  - ref: "local:meta-datasets/lateral-movement-suite"
    description: "Lateral movement via RDP/SMB"

  - ref: "local:meta-datasets/ransomware-suite"
    description: "Ransomware deployment"

echo:
  delta_factor: 0.006  # 7 days (168h) → 1 hour
  base_time: "earliest"
  target_time: "now-1h"
  prevent_future: true

schema: "raw"
```

**Usage:**
```bash
echolake echo-profile weekly-apt-simulation --destination s3-archive
```

### Example 2: Daily Baseline Traffic

**File:** `profiles/daily-baseline-traffic.yaml`

```yaml
profile:
  name: "daily-baseline-traffic"
  version: "1.0.0"
  description: "24 hours of normal user activity for ML training"
  tags: [baseline, benign, ml-training]

datasets:
  - ref: "local:meta-datasets/normal-web-browsing"
    description: "Typical web browsing patterns"

  - ref: "local:meta-datasets/email-activity"
    description: "Normal email send/receive"

  - ref: "local:meta-datasets/file-access"
    description: "Standard file operations"

  - ref: "local:meta-datasets/network-communication"
    description: "Benign network traffic"

  - ref: "local:meta-datasets/authentication-events"
    description: "Normal login/logout activity"

echo:
  delta_factor: 1.0  # Real-time replay
  base_time: "earliest"
  target_time: "now-24h"

schema: "raw"
```

**Usage:**
```bash
echolake echo-profile daily-baseline-traffic --destination s3-archive
```

### Example 3: Multi-Speed Attack

**File:** `profiles/multi-speed-attack.yaml`

```yaml
profile:
  name: "multi-speed-attack"
  version: "1.0.0"
  description: "Attack with variable replay speeds per stage"
  tags: [variable-speed, training]

datasets:
  # Slow down reconnaissance for analysis
  - ref: "local:datasets/reconnaissance"
    description: "Initial reconnaissance (slowed 2x)"
    echo:
      delta_factor: 2.0
      target_time: "now-4h"

  # Normal speed for main attack
  - ref: "local:datasets/exploitation"
    description: "Exploitation phase"

  - ref: "local:datasets/persistence"
    description: "Persistence establishment"

  # Speed up exfiltration
  - ref: "local:datasets/exfiltration"
    description: "Data exfiltration (10x faster)"
    echo:
      delta_factor: 0.1
      target_time: "now-30m"

# Global default: real-time
echo:
  delta_factor: 1.0
  target_time: "now-2h"

schema: "raw"
```

**Usage:**
```bash
echolake echo-profile multi-speed-attack \
  --destination chronicle-prod \
  --destination s3-archive
```

---

## Best Practices

### 1. Version Control

**DO commit to git:**
- ✅ Replay profiles (`profiles/*.yaml`)
- ✅ Destination configs (`destinations/*.yaml`)
- ✅ Example credentials templates (`credentials.yaml.template`)

**DON'T commit to git:**
- ❌ Actual credentials (`credentials.yaml`)
- ❌ API tokens, passwords, keys
- ❌ Service account JSON files

### 2. Naming Conventions

**Profiles:**
- Use descriptive names: `weekly-apt-simulation`, `daily-baseline`
- Include timeframe: `weekly-`, `daily-`, `monthly-`
- Include purpose: `-simulation`, `-training`, `-testing`
- Use kebab-case: `multi-stage-attack`

**Destinations:**
- Include environment: `chronicle-prod`, `chronicle-dev`, `chronicle-staging`
- Be specific: `s3-archive-us-west-2`, `chronicle-soc-team`
- Use kebab-case: `local-dev-output`

**Credentials:**
- Match destination names exactly
- Use environment variable references: `${CHRONICLE_SA_FILE}`
- Never hard-code secrets

### 3. Testing Workflow

Always test before production:

```bash
# 1. Dry run to validate config
echolake echo-profile my-profile \
  --destination my-destination \
  --dry-run

# 2. Test with local destination
echolake echo-profile my-profile \
  --destination local-dev

# 3. Test with small delta-factor (fewer events)
echolake echo-profile my-profile \
  --destination staging \
  --delta-factor 0.001

# 4. Production deployment
echolake echo-profile my-profile \
  --destination production
```

### 4. Documentation

Document your profiles:

```yaml
profile:
  name: "profile-name"
  version: "1.0.0"
  description: "Clear description of what this profile does and why"
  author: "team-email@example.com"
  tags: [relevant, tags, here]

datasets:
  - ref: "local:dataset"
    description: "Why this dataset is included and what it represents"
```

### 5. Scheduling

#### Cron

```bash
# Weekly APT simulation every Monday at 2 AM
0 2 * * 1 cd /opt/echolake && echolake echo-profile weekly-apt-simulation --destination s3-archive

# Daily baseline every day at midnight
0 0 * * * cd /opt/echolake && echolake echo-profile daily-baseline --destination s3-archive
```

#### Airflow

```python
from airflow import DAG
from airflow.operators.bash import BashOperator
from datetime import datetime

dag = DAG(
    'echolake_replay',
    start_date=datetime(2026, 1, 1),
    schedule_interval='0 2 * * 1'  # Weekly on Monday 2 AM
)

replay_task = BashOperator(
    task_id='replay_apt_simulation',
    bash_command='echolake echo-profile weekly-apt-simulation --destination s3-archive',
    dag=dag
)
```

### 6. Monitoring and Alerts

Track replay execution:

```python
from echolake.profiles import EchoProfile, Destination
from echolake.profiles.executor import ProfileExecutor
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("echolake")

try:
    profile = EchoProfile.from_file("profiles/weekly-apt.yaml")
    dest = Destination.from_file("destinations/s3-archive.yaml")

    executor = ProfileExecutor(profile, [dest])
    executor.execute()

    logger.info("Success: replay completed")

except Exception as e:
    logger.error(f"Replay failed: {str(e)}")
    # Send alert (email, Slack, PagerDuty, etc.)
    raise
```

---

## Security

### Threat Model

**Risks:**
- Credential exposure in git repositories
- Unauthorized access to destination systems
- Log data exposure in transit
- Log injection attacks

**Mitigations:**
- Separate credentials from configuration
- Use secret managers
- Encrypt data in transit (HTTPS, TLS)
- Validate and sanitize inputs

### Credential Security

#### DO:
- ✅ Use environment variables
- ✅ Use secret managers (AWS, Vault, etc.)
- ✅ Store credentials in `~/.echolake/credentials.yaml` (gitignored)
- ✅ Rotate tokens regularly
- ✅ Use least-privilege permissions
- ✅ Audit credential usage

#### DON'T:
- ❌ Commit credentials to git
- ❌ Hard-code secrets in profiles/destinations
- ❌ Share credentials in chat/email
- ❌ Use overly permissive tokens
- ❌ Store credentials in plaintext outside secure locations

### Network Security

Use HTTPS/TLS for all remote destinations:

```yaml
# ✅ Good
connection:
  host: "https://siem.example.com:443"

# ❌ Bad
connection:
  host: "http://siem.example.com:443"
```

### Audit Logging

Log all replay executions:

```python
from echolake.profiles.executor import ProfileExecutor
import logging
import os

logger = logging.getLogger("echolake.audit")

logger.info(f"Starting echo: {profile.profile.name} v{profile.profile.version}")
logger.info(f"User: {os.getenv('USER')}")
logger.info(f"Destinations: {[d.destination.name for d in destinations]}")

executor = ProfileExecutor(profile, destinations)
executor.execute()

logger.info("Echo completed")
```

### Input Validation

EchoLake validates all inputs:
- Profile and destination YAML structure
- Dataset references and versions
- Timestamp expressions
- Connection parameters

Malformed configurations are rejected with clear error messages.

---

## Troubleshooting

### Profile not found

```
Error: Profile not found: weekly-apt-simulation
```

**Solution:**
- Check profile name spelling
- Ensure profile file exists in `profiles/` directory
- Use `echolake list-profiles` to see available profiles

### Destination not found

```
Error: Destination not found: s3-archive
```

**Solution:**
- Check destination name spelling
- Ensure destination file exists in `destinations/` directory
- Use `echolake list-destinations` to see available destinations

### Credentials not found

```
Error: No credentials found for destination: chronicle-prod
```

**Solution:**
- Create `~/.echolake/credentials.yaml`
- Add credentials for the destination
- Set environment variables if using `${VAR}` references
- Use `echolake validate-credentials` to check

### Dataset not found

```
Error: Dataset not found: local:meta-datasets/attack-suite
```

**Solution:**
- Check dataset path
- Ensure dataset directory exists
- Verify dataset.yaml exists in directory
- Use absolute path: `local:/absolute/path/to/dataset`

### Version constraint not satisfied

```
Error: No version of dataset satisfies constraint: >=2.0.0
```

**Solution:**
- Check dataset version in dataset.yaml
- Update version constraint in profile
- Use `*` for any version

---

## Related Documentation

- [DATASET_FORMAT.md](DATASET_FORMAT.md) - Dataset specification
- [FEATURES.md](FEATURES.md) - All EchoLake features
- [TIME_EXPRESSIONS.md](TIME_EXPRESSIONS.md) - Time expression syntax
- [DRY_RUN_MODE.md](DRY_RUN_MODE.md) - Dry run mode details

---

## Changelog

### Version 1.0.0 (2026-01-31)
- Initial release
- Replay profiles with multiple datasets
- Destination configurations
- Credentials management
- CLI and Python API
- Notebook integration support
