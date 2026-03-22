# Dataset Examples

This directory contains example dataset manifests demonstrating various features and use cases.

## Available Examples

### sysmon-example
**File:** `sysmon-example/dataset.yaml`

Complete example showing Windows Sysmon logs with:
- Full log source classification (vendor, product, category, subcategory, event_ids)
- Platform metadata for all major SIEMs (Chronicle, Elastic, Sentinel, QRadar, Sumo Logic)
- Bundled file with full metadata

**Use case:** Single-source Windows endpoint detection

---

### aws-cloudtrail-example
**File:** `aws-cloudtrail-example/dataset.yaml`

AWS CloudTrail example showing:
- Cloud log source classification
- File references (S3) with checksums
- Platform metadata for cloud-focused SIEMs
- Custom/proprietary platform example

**Use case:** Cloud security monitoring and IAM privilege escalation detection

---

### multi-source-attack
**File:** `multi-source-attack/dataset.yaml`

Complex multi-source detection scenario showing:
- Multiple log sources (Windows Security, Sysmon, Zeek, Firewall)
- Mix of bundled files and references
- Different platform metadata per file
- Lateral movement detection across multiple data sources

**Use case:** Correlated detection across endpoints and network

---

## Features Demonstrated

### Log Source Classification
```yaml
log_source:
  vendor: "Microsoft"
  product: "Windows"
  category: "Sysmon"
  subcategory: "Process Creation"
  event_ids: [1]
```

### Platform Metadata
```yaml
platforms:
  chronicle:
    logtype: "WINDOWS_SYSMON"
  elastic:
    index: "winlogbeat-sysmon"
  sentinel:
    table: "Sysmon"
```

### Extensibility
```yaml
platforms:
  custom_siem:
    data_type: "cloud_audit"
    category: "iam_changes"
    severity: "high"
```

## Documentation

**Complete guides:**
- [LOG_SOURCE_METADATA.md](../../docs/LOG_SOURCE_METADATA.md) - Log source and platform metadata
- [DATASET_FORMAT.md](../../docs/DATASET_FORMAT.md) - Complete dataset specification
- [FEATURES.md](../../docs/FEATURES.md) - All EchoLake features

## Using These Examples

### Preview an example
```bash
echolake preview-dataset local:examples/datasets/sysmon-example
```

### Replay an example
```bash
echolake echo \
  --dataset local:examples/datasets/sysmon-example \
  --output /tmp/replayed/
```

### Use as template
Copy an example and modify it for your use case:
```bash
cp -r examples/datasets/sysmon-example my-dataset/
# Edit my-dataset/dataset.yaml
echolake preview-dataset local:my-dataset
```
