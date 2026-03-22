# EchoLake Dataset Format Specification

**Version:** 1.0.0
**Last Updated:** 2026-01-28

This document provides comprehensive documentation for the EchoLake dataset manifest format (`dataset.yaml`).

## Table of Contents

1. [Overview](#overview)
2. [File Structure](#file-structure)
3. [Complete Specification](#complete-specification)
4. [Field Reference](#field-reference)
5. [Examples](#examples)
6. [Validation Rules](#validation-rules)
7. [Best Practices](#best-practices)
8. [Common Patterns](#common-patterns)
9. [Troubleshooting](#troubleshooting)

---

## Overview

### What is a Dataset?

A dataset in EchoLake is a packaged collection of security logs with metadata, designed for replay and testing. Each dataset is defined by a `dataset.yaml` manifest file that describes:

- **Metadata** - Name, version, description, MITRE ATT&CK mapping
- **Files** - Bundled log files and/or external file references
- **Dependencies** - Other datasets this one depends on
- **Defaults** - Default replay configuration

### Dataset Types

**Simple Dataset:** Contains only bundled files (logs included in the dataset directory)
```
my-dataset/
├── dataset.yaml
└── logs/
    └── auth.jsonl
```

**Reference Dataset:** Contains only external file references (logs hosted elsewhere)
```
my-dataset/
└── dataset.yaml  # References S3/HTTP files
```

**Hybrid Dataset:** Contains both bundled files and external references
```
my-dataset/
├── dataset.yaml
└── logs/
    └── local.jsonl  # Plus references to external files
```

**Meta-Dataset:** Contains only dependencies (bundles other datasets together)
```
meta-dataset/
└── dataset.yaml  # Lists 5-10 related datasets
```

---

## File Structure

### Required File

**`dataset.yaml`** - The manifest file (must be named exactly this)

### Optional Files

**`logs/`** - Directory containing bundled log files (if using bundled files)
**`README.md`** - Human-readable documentation
**`docs/`** - Additional documentation

### Example Directory Layout

```
mitre-attack-t1078/
├── dataset.yaml              # Required: manifest
├── README.md                 # Optional: documentation
├── logs/                     # Optional: bundled files
│   ├── auth.jsonl
│   ├── network.jsonl
│   └── dns.jsonl
└── docs/                     # Optional: extra docs
    └── scenario.md
```

---

## Complete Specification

### Full Schema

```yaml
metadata:
  # === REQUIRED FIELDS ===
  name: string                # Dataset identifier (lowercase, hyphens)
  version: string             # Semantic version (e.g., "1.0.0", "2.1.3")
  description: string         # Human-readable description

  # === OPTIONAL FIELDS ===
  author: string              # Author email or identifier
  created: string             # Creation date (ISO8601 or YYYY-MM-DD)
  updated: string             # Last update date (ISO8601 or YYYY-MM-DD)
  license: string             # License (e.g., "MIT", "Apache-2.0", "Proprietary")
  tags: [string]              # Searchable tags

  # === MITRE ATT&CK MAPPING (OPTIONAL) ===
  mitre_attack:
    techniques:
      - id: string            # Technique ID (e.g., "T1078", "T1003.001")
        name: string          # Technique name
        tactics: [string]     # Associated tactics
    tactics: [string]         # Overall tactics covered

# === FILES SECTION ===
files:
  bundled: [BundledFile]      # Files included in dataset directory
  references: [FileReference]  # External file references (S3, HTTP, etc.)

# === ENVIRONMENT (OPTIONAL) ===
# Describes the collection environment: host, security controls, audit config.
# See COLLECTION_ENVIRONMENT.md for the full specification.
environment:
  host: Host                    # Host identity (hostname, OS, architecture)
  collection: Collection        # How data was collected
  execution: Execution          # Test execution context (for generated data)
  windows: WindowsEnvironment   # Windows-specific controls
  linux: LinuxEnvironment       # Linux-specific controls
  macos: MacOSEnvironment       # macOS-specific controls
  cloud: CloudEnvironment       # Cloud provider controls
  network: NetworkEnvironment   # Network capture context
  container: ContainerEnvironment  # Container runtime context

# === PROVENANCE (OPTIONAL) ===
# Build and verification metadata for datasets produced by automated pipelines.
provenance:
  build:
    host:                         # Build-time host details (ephemeral)
      vmid: integer               # VM identifier
      ip: string                  # IP address at build time
    timestamps:
      start_epoch: integer        # Unix epoch when collection started
      end_epoch: integer          # Unix epoch when collection ended
    tool: string                  # Build tool or pipeline identifier
    notes: string                 # Free-text build notes
  verification:                   # Pipeline integrity checks
    source_counts:                # Event counts at the source
      <channel>: integer          # e.g., sysmon: 24, security: 21
    dest_counts:                  # Event counts at the destination
      <channel>: integer
    table: string                 # Destination table/index used for verification
    host_filter: string           # Host filter applied during verification

# === DEPENDENCIES (OPTIONAL) ===
dependencies:
  - dataset: string           # Dataset reference
    version: string           # Version constraint (semver)
    description: string       # Why this dependency is needed

# === DEFAULTS (OPTIONAL) ===
defaults:
  echo:                     # Default echo configuration
    delta_factor: float       # Time compression factor (default: 1.0)
    base_time: string         # Base time reference (default: "earliest")
    target_time: string       # Target time (default: "now-1h")
  schema: string              # Default schema type
```

---

## Field Reference

### metadata

The `metadata` section contains descriptive information about the dataset.

#### metadata.name (required)

**Type:** `string`
**Format:** Lowercase letters, numbers, hyphens only
**Example:** `"aws-console-login-failed-mfa"`

The unique identifier for this dataset. Should be descriptive and follow kebab-case naming.

**Valid:**
- `"mitre-attack-t1078"`
- `"ransomware-ryuk-detection"`
- `"aws-cloudtrail-suspicious-activity"`

**Invalid:**
- `"My Dataset"` (spaces, capitals)
- `"dataset_name"` (underscores)
- `"dataset/name"` (slashes)

---

#### metadata.version (required)

**Type:** `string`
**Format:** Semantic version (MAJOR.MINOR.PATCH)
**Example:** `"1.0.0"`, `"2.1.3"`, `"15.0.0"`

Must follow semantic versioning:
- **MAJOR** - Incompatible changes
- **MINOR** - Backward-compatible additions
- **PATCH** - Backward-compatible fixes

```yaml
version: "1.0.0"    # Initial release
version: "1.1.0"    # Added new logs (backward compatible)
version: "2.0.0"    # Changed schema (breaking change)
```

---

#### metadata.description (required)

**Type:** `string`
**Length:** 50-500 characters recommended
**Example:**

```yaml
description: "Detection logs for AWS console login failures during MFA challenge, indicating potential credential stuffing or brute force attacks against multi-factor authentication"
```

Should clearly explain:
- What logs are included
- What security scenario is covered
- What detection or attack is being demonstrated

---

#### metadata.author (optional)

**Type:** `string`
**Format:** Email or identifier
**Example:** `"security-team@company.com"`, `"john.doe@example.com"`

Contact information for the dataset maintainer.

---

#### metadata.created (optional)

**Type:** `string`
**Format:** ISO8601 or YYYY-MM-DD
**Example:** `"2025-01-15"`, `"2025-01-15T10:30:00Z"`

Date when the dataset was first created.

---

#### metadata.updated (optional)

**Type:** `string`
**Format:** ISO8601 or YYYY-MM-DD
**Example:** `"2025-01-20"`, `"2025-01-20T14:45:00Z"`

Date of last update. Should be updated when dataset content changes.

---

#### metadata.license (optional)

**Type:** `string`
**Example:** `"MIT"`, `"Apache-2.0"`, `"Proprietary"`, `"CC-BY-4.0"`

License under which the dataset is distributed. Common values:
- `"MIT"` - MIT License (permissive)
- `"Apache-2.0"` - Apache License 2.0
- `"Proprietary"` - Private/internal use
- `"CC-BY-4.0"` - Creative Commons Attribution 4.0

---

#### metadata.tags (optional)

**Type:** `array[string]`
**Example:**

```yaml
tags:
  - authentication
  - aws
  - mfa-bypass
  - credential-access
  - cloudtrail
```

Searchable keywords for discovery. Use consistent, lowercase tags. Common categories:
- **Platform:** `aws`, `azure`, `gcp`, `windows`, `linux`, `macos`
- **Tactic:** `initial-access`, `persistence`, `privilege-escalation`, `defense-evasion`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `exfiltration`, `impact`
- **Type:** `malware`, `ransomware`, `apt`, `insider-threat`
- **Source:** `sysmon`, `cloudtrail`, `zeek`, `suricata`, `osquery`

---

#### metadata.mitre_attack (optional)

**Type:** `object`

Maps the dataset to MITRE ATT&CK framework for categorization and discovery.

**Structure:**

```yaml
mitre_attack:
  techniques:
    - id: "T1078"
      name: "Valid Accounts"
      tactics: ["persistence", "privilege-escalation", "defense-evasion", "initial-access"]

    - id: "T1078.004"
      name: "Cloud Accounts"
      tactics: ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]

  tactics:
    - "initial-access"
    - "persistence"
```

**techniques:**
- **id** - MITRE ATT&CK technique ID (must start with "T")
- **name** - Technique name (human-readable)
- **tactics** - Tactics this technique belongs to (for this specific dataset)

**tactics:**
Overall list of tactics covered by the dataset.

**Valid MITRE ATT&CK Tactics:**
- `initial-access`
- `execution`
- `persistence`
- `privilege-escalation`
- `defense-evasion`
- `credential-access`
- `discovery`
- `lateral-movement`
- `collection`
- `command-and-control`
- `exfiltration`
- `impact`

**Example IDs:**
- `"T1078"` - Main technique
- `"T1078.004"` - Sub-technique (Cloud Accounts)
- `"T1003.001"` - Sub-technique (LSASS Memory)

---

### files

The `files` section defines what log files are included in or referenced by the dataset.

#### files.bundled

**Type:** `array[BundledFile]`

Files included directly in the dataset directory (relative paths).

**BundledFile Schema:**

```yaml
bundled:
  - path: string              # Required: relative path from dataset root
    description: string       # Optional: what this file contains
    format: string            # Optional: file format (default: "jsonl")
    schema: string            # Optional: schema type
    event_count: integer      # Optional: expected number of events

    # Log source classification (optional)
    log_source:               # Optional: vendor-neutral classification
      vendor: string          # Vendor name (e.g., Microsoft, AWS)
      product: string         # Product name (e.g., Windows, CloudTrail)
      category: string        # Log category (e.g., Sysmon, Security)
      subcategory: string     # Optional subcategory
      event_ids: [int|str]    # Optional event IDs

    # Platform-specific metadata (optional, fully extensible)
    platforms:                # Optional: platform-specific metadata
      <platform_name>:        # Any platform name (elastic, chronicle, etc.)
        <key>: <value>        # Any structure (no validation)
```

**Example:**

```yaml
files:
  bundled:
    - path: "logs/sysmon.jsonl"
      description: "Windows Sysmon logs showing LSASS memory access"
      format: "jsonl"
      schema: "raw"
      event_count: 1250

      log_source:
        vendor: "Microsoft"
        product: "Windows"
        category: "Sysmon"
        subcategory: "Process Creation"
        event_ids: [1, 10]

      platforms:
        chronicle:
          logtype: "WINDOWS_SYSMON"
        elastic:
          index: "winlogbeat-sysmon"

    - path: "logs/security.xml"
      description: "Windows Security Event Log (XML format)"
      format: "xml"
      schema: "raw"
      event_count: 3400

      log_source:
        vendor: "Microsoft"
        product: "Windows"
        category: "Security"
        event_ids: [4624, 4625, 4672]

      platforms:
        elastic:
          index: "winlogbeat-security"
```

**Field Details:**

**path** (required)
- Must be relative (no absolute paths)
- Cannot contain `..` (no directory traversal)
- Case-sensitive on Linux/macOS
- Examples: `"logs/file.jsonl"`, `"data/network/zeek.log"`

**format** (optional, default: "jsonl")
- Valid values: `"jsonl"`, `"json"`, `"text"`, `"xml"`
- Use `"jsonl"` for newline-delimited JSON (most common)
- Use `"json"` for single JSON array/object
- Use `"text"` for plain text or CSV
- Use `"xml"` for XML format logs

**schema** (optional)
- Valid values: `"raw"`, `"ocsf"`, `"lakehouse_bronze"`
- `"raw"` - No transformation, original format
- `"ocsf"` - Open Cybersecurity Schema Framework
- `"lakehouse_bronze"` - Bronze layer schema

**event_count** (optional)
- Expected number of events/records in the file
- Used for validation and statistics
- Not enforced strictly (just informational)

**log_source** (optional)
- Vendor-neutral log source classification
- All subfields are optional
- Provides portable classification across platforms
- Fields:
  - `vendor` - Vendor name (e.g., "Microsoft", "AWS", "Cisco")
  - `product` - Product name (e.g., "Windows", "CloudTrail", "ASA")
  - `category` - Log category (e.g., "Sysmon", "Security", "Network")
  - `subcategory` - Optional finer classification
  - `event_ids` - Optional array of event IDs (integers or strings)
- **See:** [LOG_SOURCE_METADATA.md](LOG_SOURCE_METADATA.md) for complete guide

**platforms** (optional)
- Platform-specific metadata for SIEM ingestion
- Fully extensible - any platform name and structure allowed
- No validation - future-proof for new platforms
- Common platforms: chronicle, elastic, sentinel, qradar, sumo_logic
- Each platform can have any structure (no restrictions)
- **See:** [LOG_SOURCE_METADATA.md](LOG_SOURCE_METADATA.md) for platform examples

---

#### files.references

**Type:** `array[FileReference]`

References to external files hosted on S3, HTTP, GCS, etc.

**FileReference Schema:**

```yaml
references:
  - uri: string               # Required: URI to external file
    description: string       # Optional: what this file contains
    format: string            # Optional: file format (default: "jsonl")
    schema: string            # Optional: schema type
    checksum: string          # Optional but recommended: integrity check

    # Log source classification (optional)
    log_source:               # Optional: vendor-neutral classification
      vendor: string          # Vendor name (e.g., Microsoft, AWS)
      product: string         # Product name (e.g., Windows, CloudTrail)
      category: string        # Log category (e.g., Sysmon, Security)
      subcategory: string     # Optional subcategory
      event_ids: [int|str]    # Optional event IDs

    # Platform-specific metadata (optional, fully extensible)
    platforms:                # Optional: platform-specific metadata
      <platform_name>:        # Any platform name (elastic, chronicle, etc.)
        <key>: <value>        # Any structure (no validation)
```

**Example:**

```yaml
files:
  references:
    - uri: "s3://security-datasets/aws/cloudtrail-mfa-failures.jsonl"
      description: "AWS CloudTrail logs with MFA challenge failures"
      format: "jsonl"
      schema: "raw"
      checksum: "sha256:a1b2c3d4e5f6..."

      log_source:
        vendor: "AWS"
        product: "CloudTrail"
        category: "Management Events"

      platforms:
        chronicle:
          logtype: "AWS_CLOUDTRAIL"
        elastic:
          data_stream:
            dataset: "aws.cloudtrail"

    - uri: "https://example.com/datasets/network-traffic.jsonl"
      description: "Baseline network traffic (Zeek)"
      format: "jsonl"
      checksum: "sha256:f6e5d4c3b2a1..."

      log_source:
        vendor: "Zeek"
        product: "Zeek"
        category: "Network"
        subcategory: "Connection Logs"

      platforms:
        chronicle:
          logtype: "ZEEK_CONN"

    - uri: "gs://gcp-datasets/dns-queries.jsonl"
      description: "DNS query logs"
      format: "jsonl"
```

**Field Details:**

**uri** (required)
- Must start with supported scheme: `s3://`, `gs://`, `http://`, `https://`, `azure://`
- Full URI to downloadable file
- Will be downloaded and cached locally on first use

**format** (optional, default: "jsonl")
- Same as bundled files: `"jsonl"`, `"json"`, `"text"`, `"xml"`

**schema** (optional)
- Same as bundled files: `"raw"`, `"ocsf"`, `"lakehouse_bronze"`

**checksum** (optional but recommended)
- Format: `"algorithm:hexvalue"`
- Valid algorithms: `"sha256"`, `"sha512"`, `"md5"`
- Examples:
  - `"sha256:a1b2c3d4e5f6789..."`
  - `"md5:1234567890abcdef"`
- Used to verify file integrity after download
- Prevents corrupted or tampered files

**log_source** (optional)
- Same as bundled files - vendor-neutral log source classification
- All subfields optional: vendor, product, category, subcategory, event_ids
- **See:** [LOG_SOURCE_METADATA.md](LOG_SOURCE_METADATA.md)

**platforms** (optional)
- Same as bundled files - platform-specific metadata
- Fully extensible, no validation
- **See:** [LOG_SOURCE_METADATA.md](LOG_SOURCE_METADATA.md)

---

### dependencies

**Type:** `array[DatasetDependency]`

Other datasets that this dataset depends on. Used for meta-datasets (datasets of datasets).

**DatasetDependency Schema:**

```yaml
dependencies:
  - dataset: string           # Required: dataset reference
    version: string           # Optional: version constraint (default: "*")
    description: string       # Optional: why this is needed
```

**Example:**

```yaml
dependencies:
  - dataset: "local:./datasets/access-lsass-memory"
    version: "*"
    description: "LSASS memory dumping detection"

  - dataset: "github:echolake/datasets/common/baseline-network"
    version: ">=1.0.0"
    description: "Baseline network traffic for comparison"

  - dataset: "common/dns-baseline"
    version: "^1.2.0"
    description: "Normal DNS query patterns"
```

**Field Details:**

**dataset** (required)

Dataset reference in one of these formats:

1. **Local absolute path:**
   ```yaml
   dataset: "local:/path/to/my-dataset"
   ```

2. **Local relative path:**
   ```yaml
   dataset: "local:../other-dataset"
   ```

3. **GitHub repository:**
   ```yaml
   dataset: "github:org/repo/path/to/dataset"
   dataset: "github:echolake/datasets/mitre-attack/t1078"
   ```

4. **Short name (from configured registries):**
   ```yaml
   dataset: "common/baseline-network"
   dataset: "mitre-attack/t1078"
   ```

**version** (optional, default: "*")

Semantic version constraint:

- `"*"` - Any version (default)
- `"1.0.0"` - Exact version
- `">=1.0.0"` - Version 1.0.0 or higher
- `"^1.2.0"` - Compatible with 1.2.0 (>=1.2.0, <2.0.0)
- `"~1.2.3"` - Approximately 1.2.3 (>=1.2.3, <1.3.0)
- `">1.0.0 <2.0.0"` - Range

**description** (optional)

Human-readable explanation of why this dependency is needed.

---

### provenance

**Type:** `object` (optional)

Build and verification metadata for datasets produced by automated pipelines. Records ephemeral build-time details (VM identifiers, IPs, epoch timestamps) and pipeline integrity checks (event counts at source vs. destination).

This section is optional. It is most useful for datasets generated by automated tooling where reproducibility and pipeline verification matter.

**Schema:**

```yaml
provenance:
  build:
    host:
      vmid: integer               # VM or instance identifier
      ip: string                  # IP address at build time
    timestamps:
      start_epoch: integer        # Unix epoch when collection started
      end_epoch: integer          # Unix epoch when collection ended
    tool: string                  # Build tool or pipeline identifier
    notes: string                 # Free-text build notes
  verification:
    source_counts:
      <channel>: integer          # Event counts at the collection source
    dest_counts:
      <channel>: integer          # Event counts at the destination/storage
    table: string                 # Destination table or index
    host_filter: string           # Host filter applied during verification
```

**Example:**

```yaml
provenance:
  build:
    timestamps:
      start_epoch: 1773439154
      end_epoch: 1773439160
    tool: "art-pipeline v2"
  verification:
    source_counts:
      sysmon: 24
      security: 21
      powershell: 2452
    dest_counts:
      sysmon: 24
      security: 21
      powershell: 2452
```

**Field Details:**

**build.host** (optional) — Ephemeral host identity at build time (VM ID, IP). These may differ from `environment.host` which describes the logical host identity.

**build.timestamps** (optional) — Unix epoch boundaries for the collection window. These define the exact time range queried to extract the dataset from the pipeline.

**build.tool** (optional) — Identifier for the build tool or pipeline that produced the dataset (e.g., `"art-pipeline v2"`, `"echolake-build"`).

**build.notes** (optional) — Free-text notes about the build (e.g., `"re-executed after Sysmon recovery"`).

**verification.source_counts / dest_counts** (optional) — Event counts by channel at the collection source and destination. When these match, the pipeline delivered all events without loss.

**verification.table** (optional) — The table, index, or bucket used as the verification destination.

**verification.host_filter** (optional) — The host filter applied when querying the destination for verification.

---

### defaults

**Type:** `object`

Default configuration for replaying this dataset.

**Schema:**

```yaml
defaults:
  echo:
    delta_factor: float       # Time compression/expansion (default: 1.0)
    base_time: string         # Base time reference (default: "earliest")
    target_time: string       # Target time (default: "now-1h")
  schema: string              # Default schema for files without explicit schema
```

**Example:**

```yaml
defaults:
  echo:
    delta_factor: 1.0         # Real-time (no compression)
    base_time: "earliest"     # Use earliest log timestamp as base
    target_time: "now-1h"     # Echo to 1 hour ago
  schema: "raw"               # Default to raw schema
```

**Field Details:**

**echo.delta_factor** (optional, default: 1.0)
- Time compression/expansion factor
- `1.0` - Real-time (1 minute of logs = 1 minute of echo)
- `2.0` - 2x faster (1 minute of logs = 30 seconds of echo)
- `0.5` - 2x slower (1 minute of logs = 2 minutes of echo)
- `0.0` - All events at same time (collapse time)

**echo.base_time** (optional, default: "earliest")
- Reference point for time manipulation
- `"earliest"` - Use earliest timestamp in logs
- `"latest"` - Use latest timestamp in logs
- ISO8601 timestamp: `"2025-01-15T10:00:00Z"`

**echo.target_time** (optional, default: "now-1h")
- Where to echo the logs to
- `"now"` - Current time
- `"now-1h"` - 1 hour ago
- `"now-7d"` - 7 days ago
- ISO8601 timestamp: `"2025-01-20T15:30:00Z"`

**schema** (optional)
- Default schema for files that don't specify one
- Valid values: `"raw"`, `"ocsf"`, `"lakehouse_bronze"`

---

## Examples

### Example 1: Simple Dataset (Bundled Files Only)

**Use case:** Small dataset with log files included in the directory

```yaml
metadata:
  name: "windows-lsass-access-detection"
  version: "1.0.0"
  description: "Windows Sysmon logs detecting LSASS memory access for credential dumping"
  author: "security@company.com"
  created: "2025-01-15"
  license: "MIT"
  tags:
    - windows
    - sysmon
    - credential-access
    - lsass

  mitre_attack:
    techniques:
      - id: "T1003.001"
        name: "LSASS Memory"
        tactics: ["credential-access"]
    tactics:
      - "credential-access"

files:
  bundled:
    - path: "logs/sysmon.jsonl"
      description: "Sysmon Event ID 10 showing LSASS process access"
      format: "jsonl"
      schema: "raw"
      event_count: 150

defaults:
  echo:
    delta_factor: 1.0
    base_time: "earliest"
    target_time: "now-1h"
  schema: "raw"
```

---

### Example 2: Reference Dataset (External Files)

**Use case:** Large datasets hosted on S3/HTTP

```yaml
metadata:
  name: "aws-cloudtrail-suspicious-activity"
  version: "2.1.0"
  description: "AWS CloudTrail logs showing suspicious IAM and resource access patterns"
  author: "cloud-security@company.com"
  created: "2024-06-10"
  updated: "2025-01-15"
  license: "Proprietary"
  tags:
    - aws
    - cloudtrail
    - iam
    - privilege-escalation

  mitre_attack:
    techniques:
      - id: "T1078.004"
        name: "Cloud Accounts"
        tactics: ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]
    tactics:
      - "initial-access"
      - "privilege-escalation"

files:
  references:
    - uri: "s3://security-datasets/aws/cloudtrail-2025-01.jsonl"
      description: "CloudTrail logs from January 2025"
      format: "jsonl"
      schema: "raw"
      checksum: "sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234"

    - uri: "s3://security-datasets/aws/iam-policy-changes.jsonl"
      description: "IAM policy modification events"
      format: "jsonl"
      checksum: "sha256:f6e5d4c3b2a1098765432109876543210987654321098765432109876543"

defaults:
  echo:
    delta_factor: 1.0
    base_time: "earliest"
    target_time: "now-2h"
  schema: "raw"
```

---

### Example 3: Hybrid Dataset (Bundled + References)

**Use case:** Mix of local files and external references

```yaml
metadata:
  name: "multi-stage-attack-scenario"
  version: "1.0.0"
  description: "Complete attack chain from initial access through exfiltration"
  author: "red-team@company.com"
  tags:
    - attack-chain
    - multi-stage
    - windows
    - network

files:
  bundled:
    - path: "logs/initial-access.jsonl"
      description: "Phishing and initial compromise"
      format: "jsonl"
      event_count: 45

    - path: "logs/persistence.jsonl"
      description: "Registry persistence mechanisms"
      format: "jsonl"
      event_count: 20

  references:
    - uri: "s3://datasets/network/lateral-movement.jsonl"
      description: "Network traffic showing lateral movement"
      format: "jsonl"
      checksum: "sha256:abc123..."

    - uri: "https://datasets.example.com/exfiltration.jsonl"
      description: "Data exfiltration to external IPs"
      format: "jsonl"

defaults:
  echo:
    delta_factor: 0.1
    base_time: "earliest"
    target_time: "now-1h"
  schema: "raw"
```

---

### Example 4: Meta-Dataset (Dependencies Only)

**Use case:** Bundle related datasets together

```yaml
metadata:
  name: "ransomware-detection-suite"
  version: "1.0.0"
  description: "Complete ransomware detection suite covering encryption, ransom notes, and impact"
  author: "EchoLake Meta-Datasets"
  created: "2026-01-28"
  tags:
    - ransomware
    - impact
    - meta-dataset

  mitre_attack:
    techniques:
      - id: "T1486"
        name: "Data Encrypted for Impact"
        tactics: ["impact"]
      - id: "T1490"
        name: "Inhibit System Recovery"
        tactics: ["impact"]
    tactics:
      - "impact"

files:
  bundled: []
  references: []

dependencies:
  - dataset: "local:/datasets/ransomware-notes-bulk-creation"
    version: "*"
    description: "Bulk ransom note creation detection"

  - dataset: "local:/datasets/file-encryption-ransomware-extensions"
    version: "*"
    description: "File encryption with ransomware extensions"

  - dataset: "local:/datasets/shadow-copy-deletion"
    version: "*"
    description: "Volume shadow copy deletion to prevent recovery"

  - dataset: "local:/datasets/backup-deletion"
    version: "*"
    description: "Backup file and service deletion"

defaults:
  echo:
    delta_factor: 1.0
    base_time: "earliest"
    target_time: "now-1h"
  schema: "raw"
```

---

### Example 5: Minimal Dataset

**Use case:** Bare minimum required fields

```yaml
metadata:
  name: "test-dataset"
  version: "1.0.0"
  description: "Simple test dataset"

files:
  bundled:
    - path: "logs/test.jsonl"
```

---

## Validation Rules

### Automatic Validation

All datasets are validated when loaded using Pydantic models. Common validation errors:

#### Name Validation
- ✅ `"my-dataset"` - lowercase, hyphens
- ❌ `"My Dataset"` - spaces, capitals
- ❌ `"my_dataset"` - underscores
- ❌ `""` - empty string

#### Version Validation
- ✅ `"1.0.0"` - valid semver
- ✅ `"15.2.3"` - valid semver
- ❌ `"1.0"` - missing patch version
- ❌ `"v1.0.0"` - 'v' prefix not allowed
- ❌ `"latest"` - not a version number

#### Path Validation (bundled files)
- ✅ `"logs/file.jsonl"` - relative path
- ✅ `"data/subfolder/log.json"` - nested path
- ❌ `"/absolute/path"` - absolute paths not allowed
- ❌ `"../escape"` - directory traversal not allowed

#### URI Validation (references)
- ✅ `"s3://bucket/file.jsonl"`
- ✅ `"https://example.com/data.json"`
- ✅ `"gs://gcp-bucket/logs.jsonl"`
- ❌ `"file:///local/path"` - file:// not supported
- ❌ `"/path/to/file"` - must have scheme

#### Format Validation
- ✅ `"jsonl"`, `"json"`, `"text"`, `"xml"`
- ❌ `"csv"` - not supported (use "text")
- ❌ `"parquet"` - not supported

#### Checksum Validation
- ✅ `"sha256:a1b2c3..."` - algorithm:value format
- ✅ `"md5:1234567890abcdef"`
- ❌ `"a1b2c3"` - missing algorithm
- ❌ `"sha1:..."` - sha1 not in allowed list

#### MITRE Technique ID Validation
- ✅ `"T1078"` - starts with T
- ✅ `"T1003.001"` - sub-technique
- ❌ `"1078"` - missing T prefix
- ❌ `"TA0001"` - tactics not techniques

---

## Best Practices

### 1. Naming Conventions

**Use descriptive, kebab-case names:**
```yaml
# Good
name: "aws-cloudtrail-mfa-bypass-attempt"
name: "windows-sysmon-lsass-credential-dump"
name: "lateral-movement-rdp-detection"

# Bad
name: "dataset1"
name: "My Dataset"
name: "aws_logs"
```

### 2. Version Management

**Follow semantic versioning strictly:**

- **1.0.0 → 1.0.1** - Fixed typos in description
- **1.0.1 → 1.1.0** - Added new log files
- **1.1.0 → 2.0.0** - Changed schema or file format

**Update the `updated` field when changing content:**
```yaml
version: "1.1.0"
updated: "2025-01-20"  # Updated when version changed
```

### 3. File Organization

**Keep bundled files in a `logs/` subdirectory:**
```yaml
files:
  bundled:
    - path: "logs/sysmon.jsonl"    # Not just "sysmon.jsonl"
    - path: "logs/security.jsonl"
```

**Use consistent file naming:**
```yaml
# Good - descriptive names
- path: "logs/cloudtrail-iam-events.jsonl"
- path: "logs/sysmon-process-creation.jsonl"

# Bad - vague names
- path: "logs/data.jsonl"
- path: "logs/log1.jsonl"
```

### 4. MITRE ATT&CK Mapping

**Always include MITRE mapping for security datasets:**
```yaml
mitre_attack:
  techniques:
    - id: "T1003.001"
      name: "LSASS Memory"        # Include readable name
      tactics: ["credential-access"]  # Be specific
  tactics:
    - "credential-access"
```

**Use specific sub-techniques when possible:**
- ✅ `"T1003.001"` - LSASS Memory (specific)
- ❌ `"T1003"` - OS Credential Dumping (too broad)

### 5. Checksums for References

**Always include checksums for external files:**
```yaml
references:
  - uri: "s3://bucket/large-dataset.jsonl"
    checksum: "sha256:abc123..."  # Prevents corruption/tampering
```

**Generate checksums:**
```bash
# macOS/Linux
shasum -a 256 file.jsonl

# Output: sha256:a1b2c3d4e5f6...
```

### 6. Meaningful Descriptions

**Write clear, specific descriptions:**

```yaml
# Good - explains what and why
description: "AWS CloudTrail logs showing console login failures during MFA challenge, indicating credential stuffing or brute force attacks against multi-factor authentication"

# Bad - too vague
description: "Login logs"
```

### 7. Tagging Strategy

**Use consistent, hierarchical tags:**

```yaml
tags:
  # Platform
  - windows
  - aws

  # Data source
  - sysmon
  - cloudtrail

  # MITRE tactic
  - credential-access
  - initial-access

  # Specific technique/threat
  - lsass
  - mimikatz
  - mfa-bypass
```

### 8. Dependencies

**Use absolute paths for local dependencies:**
```yaml
# Good - explicit and portable
dependencies:
  - dataset: "local:/path/to/datasets/baseline"

# Bad - ambiguous
dependencies:
  - dataset: "../baseline"
```

**Add descriptions explaining why dependencies are needed:**
```yaml
dependencies:
  - dataset: "common/baseline-network"
    version: ">=1.0.0"
    description: "Baseline network traffic for comparison with malicious activity"
```

---

## Common Patterns

### Pattern 1: Detection Content Dataset

```yaml
metadata:
  name: "windows-mimikatz-binary-execution"
  version: "15.0.0"
  description: "Detects execution of Mimikatz credential dumping tool"
  author: "security-team@example.com"
  tags:
    - ttp
    - detection-content
    - mimikatz

  mitre_attack:
    techniques:
      - id: "T1003.001"
        name: "LSASS Memory"
        tactics: ["credential-access"]
    tactics:
      - "credential-access"

files:
  bundled:
    - path: "logs/sysmon-mimikatz.jsonl"
      description: "Sysmon logs showing Mimikatz execution"
      format: "jsonl"
      schema: "raw"

defaults:
  echo:
    delta_factor: 1.0
    base_time: "earliest"
    target_time: "now-1h"
  schema: "raw"
```

### Pattern 2: Multi-File Detection Scenario

```yaml
metadata:
  name: "lateral-movement-rdp-smb"
  version: "1.0.0"
  description: "RDP and SMB lateral movement across network"
  tags:
    - lateral-movement
    - rdp
    - smb

files:
  bundled:
    - path: "logs/windows-security.jsonl"
      description: "Windows Security Event Log (Event ID 4624, 4625)"
      format: "jsonl"

    - path: "logs/sysmon-network.jsonl"
      description: "Sysmon Event ID 3 (Network Connection)"
      format: "jsonl"

    - path: "logs/zeek-conn.jsonl"
      description: "Zeek connection logs showing RDP/SMB traffic"
      format: "jsonl"
```

### Pattern 3: Time-Compressed Scenario

```yaml
metadata:
  name: "apt-attack-chain-compressed"
  version: "1.0.0"
  description: "7-day APT attack compressed to 1 hour for testing"

files:
  bundled:
    - path: "logs/attack-day1-7.jsonl"

defaults:
  echo:
    delta_factor: 0.006  # 7 days → 1 hour (168 hours / 1 hour)
    base_time: "earliest"
    target_time: "now-1h"
```

### Pattern 4: Cloud Security Dataset

```yaml
metadata:
  name: "aws-iam-privilege-escalation"
  version: "1.0.0"
  description: "AWS IAM privilege escalation via policy manipulation"
  tags:
    - aws
    - iam
    - privilege-escalation
    - cloudtrail

files:
  references:
    - uri: "s3://security-datasets/aws/cloudtrail-iam-policy-changes.jsonl"
      format: "jsonl"
      checksum: "sha256:..."

defaults:
  echo:
    delta_factor: 1.0
    base_time: "earliest"
    target_time: "now-2h"
  schema: "raw"
```

---

## Troubleshooting

### Error: "Manifest file not found"

**Problem:** `dataset.yaml` doesn't exist or is misnamed

**Solutions:**
- Ensure file is named exactly `dataset.yaml` (lowercase)
- Check file is in the correct directory
- Verify path is correct

### Error: "Invalid semantic version"

**Problem:** Version field doesn't follow semver format

**Solutions:**
```yaml
# Wrong
version: "1.0"
version: "v1.0.0"
version: "latest"

# Right
version: "1.0.0"
version: "2.1.3"
```

### Error: "Path cannot contain '..'"

**Problem:** Bundled file path tries to escape dataset directory

**Solutions:**
```yaml
# Wrong
path: "../../logs/file.jsonl"

# Right
path: "logs/file.jsonl"
```

### Error: "URI must start with one of..."

**Problem:** File reference URI missing or invalid scheme

**Solutions:**
```yaml
# Wrong
uri: "/local/path/file.jsonl"
uri: "file:///path/file.jsonl"

# Right
uri: "s3://bucket/file.jsonl"
uri: "https://example.com/file.jsonl"
```

### Error: "Checksum must be in format 'algorithm:value'"

**Problem:** Checksum format is incorrect

**Solutions:**
```yaml
# Wrong
checksum: "a1b2c3d4..."
checksum: "sha256-a1b2c3"

# Right
checksum: "sha256:a1b2c3d4e5f6..."
checksum: "md5:1234567890abcdef"
```

### Error: "Technique ID must start with 'T'"

**Problem:** MITRE technique ID format is wrong

**Solutions:**
```yaml
# Wrong
techniques:
  - id: "1078"
  - id: "TA0001"

# Right
techniques:
  - id: "T1078"
  - id: "T1003.001"
```

### Warning: "File not found"

**Problem:** Bundled file path in manifest doesn't exist

**Solutions:**
- Check file actually exists at specified path
- Verify path is relative to dataset root directory
- Check for typos in filename or path

---

## File Format Specifications

### JSONL Format (Recommended)

**JSONL** (JSON Lines) - One JSON object per line:

```jsonl
{"timestamp": "2025-01-15T10:30:00Z", "event": "login", "user": "alice"}
{"timestamp": "2025-01-15T10:31:00Z", "event": "file_access", "user": "bob"}
```

**Advantages:**
- Streamable (can process line-by-line)
- Easy to append
- Memory-efficient for large files

### JSON Format

**JSON** - Single array or object:

```json
[
  {"timestamp": "2025-01-15T10:30:00Z", "event": "login"},
  {"timestamp": "2025-01-15T10:31:00Z", "event": "logout"}
]
```

**Use when:**
- Small files (<10MB)
- Need to maintain exact JSON structure

### Text Format

**TEXT** - Plain text, CSV, or other formats:

```
2025-01-15 10:30:00 User alice logged in
2025-01-15 10:31:00 User bob accessed file
```

**Use for:**
- CSV files
- Plain text logs
- Custom formats

### XML Format

**XML** - XML structured logs:

```xml
<Event>
  <System>
    <EventID>4624</EventID>
    <TimeCreated>2025-01-15T10:30:00Z</TimeCreated>
  </System>
</Event>
```

**Use for:**
- Windows Event Logs (XML format)
- XML-based log formats

---

## Schema Types

### raw

**No transformation** - Keep original log format exactly as-is

Use when:
- Logs are already in correct format
- Don't need schema validation
- Maximum flexibility

### lakehouse_bronze

**Bronze Layer Schema** - Standardized bronze layer format

Use when:
- Need consistent schema with dual timestamps
- Following medallion architecture

### ocsf

**Open Cybersecurity Schema Framework** - Industry standard schema

Use when:
- Need vendor-neutral format
- Sharing with other tools
- Following OCSF standards

---

## Related Documentation

- [Time Expressions](TIME_EXPRESSIONS.md) - Time expression syntax for replay
- [Dry Run Mode](DRY_RUN_MODE.md) - Testing datasets without writing
- [Timestamp Manipulation](TIMESTAMP_MANIPULATION.md) - How time shifting works

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-28 | Initial comprehensive documentation |

---

**Questions or Issues?**

- Check the [EchoLake README](../README.md)
- Review [example datasets](../tests/fixtures/)
