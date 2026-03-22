# EchoLake Examples

This directory contains example configurations to help you get started with EchoLake.

---

## Quick Start

### 1. First Time? Start Here!

```bash
# Use the getting-started profile with local output
echolake echo-profile getting-started --destination local-output
```

This will replay sample logs to `./output/` directory on your local machine.

### 2. Try a More Complex Scenario

```bash
# Simulate a weekly APT attack (dry run first)
echolake echo-profile weekly-apt-simulation \
  --destination local-output \
  --dry-run

# Run it for real
echolake echo-profile weekly-apt-simulation \
  --destination local-output
```

---

## Directory Structure

```
examples/
├── profiles/              # Replay profile configurations
│   ├── getting-started.yaml
│   ├── weekly-apt-simulation.yaml
│   ├── daily-baseline-traffic.yaml
│   ├── multi-speed-attack.yaml
│   ├── ransomware-incident.yaml
│   ├── insider-threat-slow.yaml
│   └── cloud-breach-aws.yaml
│
├── destinations/          # Output destination configurations
│   ├── azure-archive.yaml
│   ├── chronicle-prod.yaml
│   ├── gcs-archive.yaml
│   ├── local-output.yaml
│   ├── s3-archive.yaml
│   └── stdout-debug.yaml
│
└── credentials/           # Credential templates (DO NOT commit real credentials!)
    └── credentials.yaml.template
```

---

## Available Profiles

### 🎓 Getting Started

**File:** `profiles/getting-started.yaml`

Simple example for first-time users.

- **Duration:** Original timing preserved
- **Time range:** Ends 1 hour ago
- **Datasets:** 1
- **Use case:** Learning EchoLake basics

```bash
echolake echo-profile getting-started --destination local-output
```

---

### 🎯 Weekly APT Simulation

**File:** `profiles/weekly-apt-simulation.yaml`

7-day APT attack compressed to 1 hour for training scenarios.

- **Duration:** 7 days → 1 hour (168x compression)
- **Time range:** Ends 1 hour ago
- **Datasets:** 5 (initial access → ransomware)
- **Use case:** SOC training, detection rule testing

```bash
echolake echo-profile weekly-apt-simulation --destination s3-archive
```

**MITRE ATT&CK Coverage:**
- T1190 - Exploit Public-Facing Application
- T1547 - Boot or Logon Autostart Execution
- T1003 - OS Credential Dumping
- T1021 - Remote Services
- T1486 - Data Encrypted for Impact

---

### 📊 Daily Baseline Traffic

**File:** `profiles/daily-baseline-traffic.yaml`

24 hours of normal user activity for ML training and baseline establishment.

- **Duration:** 24 hours (real-time)
- **Time range:** Starts 24 hours ago
- **Datasets:** 5 (normal user behaviors)
- **Use case:** UEBA baseline, ML training, anomaly detection tuning

```bash
echolake echo-profile daily-baseline-traffic --destination s3-archive
```

---

### ⚡ Multi-Speed Attack

**File:** `profiles/multi-speed-attack.yaml`

Attack simulation with variable replay speeds per stage.

- **Duration:** Variable per stage
- **Time range:** Ends 30 minutes ago
- **Datasets:** 4 with different speeds
- **Use case:** Demonstrating per-dataset timing control

```bash
echolake echo-profile multi-speed-attack --destination local-output
```

**Timing:**
- Reconnaissance: 2x slower (detailed analysis)
- Exploitation: Real-time
- Persistence: Real-time
- Exfiltration: 10x faster (rapid completion)

---

### 🔒 Ransomware Incident

**File:** `profiles/ransomware-incident.yaml`

Complete ransomware attack lifecycle from phishing to encryption.

- **Duration:** 3 days → 30 minutes (144x compression)
- **Time range:** Ends 30 minutes ago
- **Datasets:** 9 (phishing → encryption)
- **Use case:** Incident response training, ransomware detection testing

```bash
echolake echo-profile ransomware-incident --destination s3-archive
```

**Attack Stages:**
1. Phishing (T1566)
2. Malicious macro execution (T1204)
3. Registry persistence (T1547)
4. Privilege escalation (T1068)
5. Disable antivirus (T1562)
6. Credential dumping (T1003)
7. File discovery (T1083)
8. Lateral movement (T1021)
9. File encryption (T1486)

---

### 👤 Insider Threat (Slow Burn)

**File:** `profiles/insider-threat-slow.yaml`

30-day insider threat scenario with gradual behavioral anomalies.

- **Duration:** 30 days (real-time)
- **Time range:** Starts 30 days ago
- **Datasets:** 6 (escalating suspicious behavior)
- **Use case:** UEBA testing, behavioral analytics validation

```bash
echolake echo-profile insider-threat-slow --destination chronicle-prod
```

**Timeline:**
- Days 1-5: Normal baseline
- Days 6-10: Increased file access
- Days 11-15: Accessing sensitive files
- Days 16-20: Data staging
- Days 21-25: Large transfers
- Days 26-30: Cover tracks

---

### ☁️ AWS Cloud Breach

**File:** `profiles/cloud-breach-aws.yaml`

AWS-focused cloud breach with IAM abuse and S3 exfiltration.

- **Duration:** 5 days → 45 minutes (160x compression)
- **Time range:** Ends 45 minutes ago
- **Datasets:** 10 (credential compromise → crypto mining)
- **Use case:** Cloud security testing, AWS detection rule validation

```bash
echolake echo-profile cloud-breach-aws --destination s3-archive
```

**Attack Stages:**
1. Compromised IAM credentials
2. AWS reconnaissance
3. IAM persistence (backdoor user)
4. Privilege escalation
5. Disable CloudTrail
6. Steal secrets (Secrets Manager)
7. S3 bucket enumeration
8. Download sensitive data
9. Exfiltrate to external S3
10. Deploy crypto miners

---

## Available Destinations

### 💾 Local Output

**File:** `destinations/local-output.yaml`

Write replayed logs to local filesystem.

```yaml
type: "local"
connection:
  path: "./output/"
format: "jsonl"
```

**Use case:** Development, testing, local analysis

```bash
echolake echo-profile getting-started --destination local-output
```

---

### 🛡️ Google Chronicle

**File:** `destinations/chronicle-prod.yaml`

Send logs to Google Chronicle SIEM.

```yaml
type: "chronicle"
connection:
  project_id: "your-project-id"
  log_type: "WINDOWS_SYSMON"
  region: "us-central1"
format: "jsonl"
```

**Prerequisites:**
- Service account JSON file
- Chronicle API enabled

```bash
echolake echo-profile ransomware-incident --destination chronicle-prod
```

---

### 📦 AWS S3 Archive

**File:** `destinations/s3-archive.yaml`

Archive replayed logs to AWS S3.

```yaml
type: "s3"
connection:
  bucket: "security-datasets"
  prefix: "replays/2026-01/"
  region: "us-west-2"
format: "jsonl"
```

**Prerequisites:**
- AWS credentials (from ~/.aws/credentials or environment)
- S3 bucket created with appropriate permissions

```bash
echolake echo-profile daily-baseline-traffic --destination s3-archive
```

---

## Credentials Setup

### Step 1: Copy Template

```bash
mkdir -p ~/.echolake
cp examples/credentials/credentials.yaml.template ~/.echolake/credentials.yaml
```

### Step 2: Edit Credentials

Edit `~/.echolake/credentials.yaml`:

```yaml
credentials:
  chronicle-prod:
    credentials_file: "/path/to/service-account.json"

  s3-archive:
    # Uses AWS credentials from ~/.aws/credentials
```

### Step 3: Set Environment Variables

Create `.env` file:

```bash
export CHRONICLE_SA_FILE="/path/to/service-account.json"
```

Load it:

```bash
source .env
```

### Step 4: Test

```bash
echolake echo-profile getting-started --destination local-output --dry-run
```

---

## Common Workflows

### Workflow 1: Local Testing

```bash
# 1. Dry run to preview
echolake echo-profile getting-started \
  --destination local-output \
  --dry-run

# 2. Run for real
echolake echo-profile getting-started \
  --destination local-output

# 3. Check output
ls -lh ./output/
```

### Workflow 2: SIEM Testing

```bash
# 1. Test with local destination first
echolake echo-profile weekly-apt-simulation \
  --destination local-output

# 2. Dry run to production
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --dry-run

# 3. Send to production
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive
```

### Workflow 3: Multi-Destination

```bash
# Send to multiple destinations simultaneously
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --destination chronicle-prod \
  --destination s3-archive
```

### Workflow 4: Runtime Overrides

```bash
# Override profile settings at runtime
echolake echo-profile weekly-apt-simulation \
  --destination s3-archive \
  --delta-factor 0.01 \
  --target-time "now-2h" \
  --input-schema ocsf
```

---

## Creating Custom Profiles

### Example: Custom Attack Scenario

Create `profiles/my-custom-attack.yaml`:

```yaml
profile:
  name: "my-custom-attack"
  version: "1.0.0"
  description: "My custom attack scenario"
  tags: [custom, attack]

datasets:
  - ref: "local:my-datasets/initial-access"
    description: "How attacker got in"

  - ref: "local:my-datasets/lateral-movement"
    description: "How they moved around"

  - ref: "local:my-datasets/exfiltration"
    description: "What they stole"

echo:
  delta_factor: 0.1  # 10x faster
  target_time: "now-1h"

schema: "raw"
```

Run it:

```bash
echolake echo-profile my-custom-attack --destination local-output
```

---

## Best Practices

### 1. Always Dry Run First

```bash
echolake echo-profile PROFILE --destination DEST --dry-run
```

Preview what will happen before sending data.

### 2. Test Locally Before Production

```bash
# Local first
echolake echo-profile my-profile --destination local-output

# Then production
echolake echo-profile my-profile --destination chronicle-prod
```

### 3. Use Version Control

```bash
# Commit profiles and destinations
git add profiles/ destinations/
git commit -m "Add new attack profiles"

# NEVER commit credentials
# .gitignore already excludes them
```

### 4. Document Your Profiles

Add clear descriptions and comments:

```yaml
profile:
  name: "my-profile"
  description: "Clear description of what this does and why"
  tags: [helpful, tags, here]

datasets:
  - ref: "local:dataset"
    description: "Why this dataset is included"
```

---

## Scheduling

### Cron

```bash
# Weekly on Monday at 2 AM
0 2 * * 1 cd /opt/echolake && echolake echo-profile weekly-apt-simulation --destination chronicle-prod
```

---

## Troubleshooting

### "Profile not found"

```
Error: Profile not found: my-profile
```

**Fix:** Ensure `profiles/my-profile.yaml` exists

### "Destination not found"

```
Error: Destination not found: my-destination
```

**Fix:** Ensure `destinations/my-destination.yaml` exists

### "No credentials found"

```
Error: No credentials found for destination: my-destination
```

**Fix:** Set up `~/.echolake/credentials.yaml` (see Credentials Setup above)

---

## Documentation

- **[QUICKSTART.md](../docs/QUICKSTART.md)** - Quick start guide
- **[FEATURES.md](../docs/FEATURES.md)** - All features
- **[ECHO_PROFILES.md](../docs/ECHO_PROFILES.md)** - In-depth profiles guide
- **[DATASET_FORMAT.md](../docs/DATASET_FORMAT.md)** - Dataset specification
- **[TIME_EXPRESSIONS.md](../docs/TIME_EXPRESSIONS.md)** - Time syntax

---

## Getting Help

```bash
# Command help
echolake --help
echolake echo-profile --help

# List available
echolake list-profiles
echolake list-destinations
```

**Community:**
- GitHub Issues: https://github.com/daveherrald/echolake/issues
- Discussions: https://github.com/daveherrald/echolake/discussions
