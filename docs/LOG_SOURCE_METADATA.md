# Log Source and Platform Metadata

**Version:** 1.0.0
**Last Updated:** 2026-01-28

Complete guide to classifying log sources and specifying platform-specific metadata in EchoLake datasets.

## Table of Contents

1. [Overview](#overview)
2. [Log Source Classification](#log-source-classification)
3. [Platform Metadata](#platform-metadata)
4. [Common Platforms](#common-platforms)
5. [Examples](#examples)
6. [Best Practices](#best-practices)
7. [Extensibility](#extensibility)

---

## Overview

### The Problem

Different SIEM platforms require different metadata to correctly ingest and classify logs:

- **Chronicle** needs `logtype`
- **Elastic** needs `index` and `data_stream`
- **Sentinel** needs `table`
- **QRadar** needs `log_source_type`
- **Sumo Logic** needs `source_category`

### The Solution

EchoLake datasets support **two-tier metadata**:

1. **log_source** - Vendor-neutral classification (portable across platforms)
2. **platforms** - Platform-specific metadata (extensible, no validation)

**Both are optional** - use what you need.

---

## Log Source Classification

### Purpose

Provide vendor-neutral classification that works across all platforms.

### Schema

```yaml
log_source:
  vendor: string          # Vendor name (optional)
  product: string         # Product name (optional)
  category: string        # Log category (optional)
  subcategory: string     # Subcategory (optional)
  event_ids: [int|str]   # Event IDs (optional)
```

**All fields are optional** - use what makes sense for your logs.

### Field Descriptions

#### vendor

The organization or company that produces the product.

**Examples:**
- `"Microsoft"`
- `"AWS"`
- `"Cisco"`
- `"Palo Alto"`
- `"Zeek"`
- `"CrowdStrike"`

**Use cases:**
- Search by vendor: "Show me all Microsoft logs"
- Filter by vendor: "Exclude AWS logs"
- Vendor-specific processing rules

---

#### product

The specific product or service generating the logs.

**Examples:**
- `"Windows"` (Microsoft)
- `"CloudTrail"` (AWS)
- `"ASA"` (Cisco)
- `"NGFW"` (Palo Alto)
- `"Falcon"` (CrowdStrike)

**Use cases:**
- Product-specific detection rules
- License tracking
- Product documentation links

---

#### category

The type or category of logs within the product.

**Examples:**

**Windows:**
- `"Security"`
- `"Sysmon"`
- `"PowerShell"`
- `"Application"`

**AWS:**
- `"CloudTrail"`
- `"VPC Flow Logs"`
- `"GuardDuty"`
- `"Config"`

**Network:**
- `"Firewall"`
- `"IDS"`
- `"DNS"`
- `"Proxy"`

---

#### subcategory

Optional finer classification within a category.

**Examples:**

**Sysmon:**
- `"Process Creation"` (Event ID 1)
- `"Network Connection"` (Event ID 3)
- `"File Creation"` (Event ID 11)

**CloudTrail:**
- `"IAM"`
- `"S3"`
- `"EC2"`

**Firewall:**
- `"Allow"`
- `"Deny"`
- `"Threat"`

---

#### event_ids

List of event IDs or log types covered by this file.

**Type:** Array of integers or strings

**Examples:**

**Windows Security:**
```yaml
event_ids: [4624, 4625, 4672]  # Successful login, failed login, special privileges
```

**Sysmon:**
```yaml
event_ids: [1, 3, 11]  # Process creation, network connection, file creation
```

**CloudTrail:**
```yaml
event_ids: ["PutUserPolicy", "AttachUserPolicy", "CreateAccessKey"]
```

**Use cases:**
- Documentation: "This file contains events 4624, 4625, 4672"
- Validation: Check expected events are present
- Filtering: "Only process Event ID 1"

---

## Platform Metadata

### Purpose

Provide platform-specific metadata for SIEM ingestion and classification.

### Schema

```yaml
platforms:
  <platform_name>:       # Any platform name (fully extensible)
    <key>: <value>       # Any structure (no validation)
```

**Key points:**
- ✅ **Fully extensible** - Any platform name allowed
- ✅ **No validation** - Any structure allowed
- ✅ **Optional** - Include only platforms you use
- ✅ **Future-proof** - New platforms work without code changes

### Examples

```yaml
platforms:
  elastic:
    data_stream:
      type: "logs"
      dataset: "aws.cloudtrail"
      namespace: "production"

  chronicle:
    logtype: "AWS_CLOUDTRAIL"

  custom_platform:
    whatever: "fields"
    you: "need"
```

---

## Common Platforms

### Google Chronicle

**Common fields:**
```yaml
platforms:
  chronicle:
    logtype: string       # Required: Log type classification
    namespace: string     # Optional: Namespace/environment
    log_type: string      # Alias for logtype (some use this)
```

**Common logtypes:**
- `"WINDOWS_SYSMON"` - Windows Sysmon
- `"WINDOWS_EVENTLOG"` - Windows Event Log
- `"AWS_CLOUDTRAIL"` - AWS CloudTrail
- `"ZEEK_CONN"` - Zeek connection logs
- `"PALO_ALTO_TRAFFIC"` - Palo Alto traffic

**Example:**
```yaml
platforms:
  chronicle:
    logtype: "WINDOWS_SYSMON"
    namespace: "production"
```

---

### Elastic Stack

**Common fields:**
```yaml
platforms:
  elastic:
    index: string              # Legacy: Index name
    data_stream:               # Modern: Data stream
      type: string             # Usually "logs"
      dataset: string          # Log type (e.g., "windows.sysmon")
      namespace: string        # Environment (e.g., "production")
```

**Common indices:**
- `"winlogbeat-sysmon"` - Windows Sysmon
- `"filebeat-aws"` - AWS logs
- `"packetbeat-flows"` - Network flows

**Example:**
```yaml
platforms:
  elastic:
    index: "winlogbeat-sysmon"
    data_stream:
      type: "logs"
      dataset: "windows.sysmon"
      namespace: "production"
```

---

### Microsoft Sentinel

**Common fields:**
```yaml
platforms:
  sentinel:
    table: string          # Required: Destination table
    workspace_id: string   # Optional: Workspace identifier
```

**Common tables:**
- `"SecurityEvent"` - Windows Security
- `"Sysmon"` - Sysmon events
- `"AWSCloudTrail"` - AWS CloudTrail
- `"CommonSecurityLog"` - CEF logs

**Example:**
```yaml
platforms:
  sentinel:
    table: "Sysmon"
    workspace_id: "production"
```

---

### IBM QRadar

**Common fields:**
```yaml
platforms:
  qradar:
    log_source_type: string        # Required: Log source type
    log_source_identifier: string  # Optional: Source identifier
```

**Common log source types:**
- `"Microsoft Windows Security Event Log"`
- `"Microsoft Windows Security Event Log - Sysmon"`
- `"Amazon AWS CloudTrail"`
- `"Palo Alto Networks Firewall"`

**Example:**
```yaml
platforms:
  qradar:
    log_source_type: "Microsoft Windows Security Event Log - Sysmon"
    log_source_identifier: "Sysmon-DC01"
```

---

### Sumo Logic

**Common fields:**
```yaml
platforms:
  sumo_logic:
    source_category: string   # Required: Source category
    source_name: string       # Optional: Source name
    source_host: string       # Optional: Source host
```

**Example:**
```yaml
platforms:
  sumo_logic:
    source_category: "windows/sysmon"
    source_name: "sysmon-process-creation"
    source_host: "DC01"
```

---

## Examples

### Example 1: Windows Sysmon (All Major Platforms)

```yaml
files:
  bundled:
    - path: "logs/sysmon.jsonl"
      format: "jsonl"

      log_source:
        vendor: "Microsoft"
        product: "Windows"
        category: "Sysmon"
        subcategory: "Process Creation"
        event_ids: [1]

      platforms:
        chronicle:
          logtype: "WINDOWS_SYSMON"

        elastic:
          data_stream:
            type: "logs"
            dataset: "windows.sysmon"
            namespace: "default"

        sentinel:
          table: "Sysmon"

        qradar:
          log_source_type: "Microsoft Windows Security Event Log - Sysmon"

        sumo_logic:
          source_category: "windows/sysmon"
```

---

### Example 2: AWS CloudTrail

```yaml
files:
  references:
    - uri: "s3://bucket/cloudtrail.jsonl"
      format: "jsonl"

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
            namespace: "production"
```

---

### Example 3: Zeek Network Logs

```yaml
files:
  bundled:
    - path: "logs/zeek-conn.jsonl"
      format: "jsonl"

      log_source:
        vendor: "Zeek"
        product: "Zeek"
        category: "Network"
        subcategory: "Connection Logs"

      platforms:
        chronicle:
          logtype: "ZEEK_CONN"

        elastic:
          data_stream:
            dataset: "zeek.connection"
```

---

### Example 4: Only Log Source (No Platform Metadata)

```yaml
files:
  bundled:
    - path: "logs/custom-app.jsonl"
      format: "jsonl"

      # Only vendor-neutral classification
      log_source:
        vendor: "MyCompany"
        product: "CustomApp"
        category: "Audit"
```

---

### Example 5: Only Platform Metadata (No Log Source)

```yaml
files:
  bundled:
    - path: "logs/app.jsonl"
      format: "jsonl"

      # Only Elastic metadata
      platforms:
        elastic:
          index: "application-logs"
          data_stream:
            type: "logs"
            dataset: "custom.app"
            namespace: "default"
```

---

### Example 6: Custom/Proprietary Platform

```yaml
files:
  bundled:
    - path: "logs/security.jsonl"
      format: "jsonl"

      log_source:
        vendor: "Microsoft"
        product: "Windows"
        category: "Security"

      platforms:
        # Standard platforms
        elastic:
          index: "winlogbeat-security"

        # Custom internal platform
        internal_siem:
          data_type: "windows_security"
          pipeline: "security_events"
          retention_days: 365
          compliance_tags: ["PCI", "HIPAA"]
```

---

## Best Practices

### 1. Use Both Log Source and Platform Metadata

**Recommendation:** Provide both for maximum portability and platform-specific optimization.

```yaml
# Good - portable AND platform-specific
log_source:
  vendor: "Microsoft"
  product: "Windows"
  category: "Sysmon"

platforms:
  elastic:
    index: "winlogbeat-sysmon"
  chronicle:
    logtype: "WINDOWS_SYSMON"
```

```yaml
# Also OK - just log source (portable only)
log_source:
  vendor: "Microsoft"
  product: "Windows"
  category: "Sysmon"
```

```yaml
# Also OK - just platforms (platform-specific only)
platforms:
  elastic:
    index: "winlogbeat-sysmon"
```

---

### 2. Be Consistent with Naming

**Use consistent vendor/product names across datasets:**

```yaml
# Good - consistent
log_source:
  vendor: "Microsoft"   # Always "Microsoft"
  product: "Windows"    # Always "Windows"
  category: "Sysmon"    # Always "Sysmon"
```

```yaml
# Bad - inconsistent
log_source:
  vendor: "MS"          # Sometimes "MS", sometimes "Microsoft"
  product: "Win"        # Sometimes "Win", sometimes "Windows"
  category: "sysmon"    # Sometimes lowercase, sometimes capitalized
```

**Recommendation:** Create a standard naming guide for your organization.

---

### 3. Include Event IDs When Relevant

**For logs with specific event IDs:**

```yaml
# Good - documents which events are included
log_source:
  vendor: "Microsoft"
  product: "Windows"
  category: "Security"
  event_ids: [4624, 4625, 4672]  # Login success, failure, special privileges
```

**For logs without event IDs:**

```yaml
# OK - omit event_ids
log_source:
  vendor: "AWS"
  product: "CloudTrail"
  category: "Management Events"
  # No event_ids field
```

---

### 4. Document Platform-Specific Fields

**Add comments explaining non-obvious fields:**

```yaml
platforms:
  elastic:
    data_stream:
      type: "logs"                    # Always "logs" for log data
      dataset: "windows.sysmon"       # Product.category format
      namespace: "production"         # Environment identifier
```

---

### 5. Include Only Platforms You Use

**Don't add platforms "just in case":**

```yaml
# Good - only platforms you actually use
platforms:
  elastic:
    data_stream:
      dataset: "aws.cloudtrail"
  chronicle:
    logtype: "AWS_CLOUDTRAIL"
```

```yaml
# Bad - adding every platform "just in case"
platforms:
  chronicle: {...}
  elastic: {...}
  sentinel: {...}
  qradar: {...}
  # ... unnecessary platforms
```

**Exception:** If creating shareable datasets, include common platforms.

---

## Extensibility

### Fully Extensible Design

**No validation** = **Any platform works**

The `platforms` field accepts **any structure** with **no validation**. This means:

✅ New platforms work immediately (no code changes)
✅ Custom/proprietary platforms supported
✅ Platform-specific features (nested objects, arrays, etc.)
✅ Future-proof (platforms evolve without breaking changes)

### Adding New Platforms

**Example: New hypothetical platform "SecOps AI"**

```yaml
platforms:
  # Existing platforms
  elastic:
    data_stream:
      dataset: "aws.cloudtrail"

  # New platform (works immediately, no code changes needed)
  secops_ai:
    data_category: "cloud_audit"
    risk_score: 8
    auto_correlate: true
    ml_model: "threat_detection_v2"
    tags: ["privilege-escalation", "iam"]
```

### Nested Structures

**Example: Complex platform metadata**

```yaml
platforms:
  custom_platform:
    ingestion:
      pipeline: "security_events"
      batch_size: 1000
      compression: "gzip"

    enrichment:
      geoip: true
      threat_intel: true
      user_context: true

    retention:
      hot_tier_days: 30
      warm_tier_days: 90
      cold_tier_days: 365

    compliance:
      frameworks: ["PCI-DSS", "HIPAA", "SOC2"]
      data_classification: "confidential"
```

### Platform-Specific Arrays

**Example: Multiple indices or tables**

```yaml
platforms:
  elastic:
    data_stream:
      dataset: "aws.cloudtrail"
    # Send to multiple indices
    indices: ["aws_primary", "aws_backup", "compliance_audit"]

  custom_siem:
    # Array of processing rules
    rules:
      - name: "enrich_user_data"
        enabled: true
      - name: "correlate_threats"
        enabled: true
```

---

## Migration Guide

### Migrating from Description-Embedded Metadata

**Old format (description-embedded metadata):**
```yaml
files:
  references:
    - uri: "https://..."
      description: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational - XmlWinEventLog"
```

**New format:**
```yaml
files:
  references:
    - uri: "https://..."
      description: "Sysmon process creation events"  # Actual human description

      log_source:
        vendor: "Microsoft"
        product: "Windows"
        category: "Sysmon"

      platforms:
        elastic:
          index: "winlogbeat-sysmon"
```

**Benefits:**
- ✅ Structured and parseable
- ✅ Human-readable description separate from metadata
- ✅ Multi-platform support
- ✅ Vendor-neutral classification

---

## Related Documentation

- **[DATASET_FORMAT.md](DATASET_FORMAT.md)** - Complete dataset specification
- **[FEATURES.md](FEATURES.md)** - All EchoLake features
- **[Examples](../examples/datasets/)** - Real-world examples

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-28 | Initial documentation for log source and platform metadata |

---

**Questions or Feedback?**

- Review [example datasets](../examples/datasets/)
- Check [dataset format spec](DATASET_FORMAT.md)
- See [EchoLake features](FEATURES.md)
