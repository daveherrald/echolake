# Collection Environment Metadata

**Version:** 1.0.0
**Last Updated:** 2026-03-14

Specification for describing the environment that produced dataset telemetry. This metadata helps consumers understand what security controls were active, what audit policies were in place, and therefore what telemetry to expect — and what might be absent.

## Table of Contents

1. [Overview](#overview)
2. [Schema](#schema)
3. [Platform Specifications](#platform-specifications)
4. [Examples](#examples)
5. [Best Practices](#best-practices)
6. [Extensibility](#extensibility)

---

## Overview

### The Problem

A dataset containing Windows Sysmon events is only interpretable if you know the Sysmon configuration. A dataset showing a "blocked" credential dump only makes sense if you know Defender was active. A dataset missing DNS logs might mean DNS wasn't collected — or it might mean the technique didn't generate DNS traffic.

Without environment context, consumers of a dataset must guess at what the collection infrastructure looked like. This leads to incorrect assumptions — especially for AI agents processing datasets programmatically.

### The Solution

The `environment` section in `dataset.yaml` provides structured metadata about the collection environment. It is:

- **Platform-agnostic at the top level** — works for Windows, Linux, macOS, cloud, network, containers
- **Platform-specific where it matters** — each platform type has its own structured fields
- **Optional but recommended** — every field is optional, include what's relevant
- **Descriptive, not prescriptive** — describes what WAS configured, not what SHOULD be

---

## Schema

The `environment` section is a new top-level key in `dataset.yaml`, alongside `metadata`, `files`, `dependencies`, and `defaults`.

```yaml
environment:
  # === HOST IDENTITY ===
  host:
    hostname: string            # Source host name
    os: string                  # OS name and edition
    os_version: string          # OS version string
    architecture: string        # CPU architecture (x86_64, arm64, etc.)
    domain: string              # Domain/realm membership (if applicable)
    platform: string            # Virtualization/cloud platform (optional)

  # === COLLECTION CONTEXT ===
  collection:
    method: string              # How data was collected (e.g., "agent", "syslog", "api", "packet-capture")
    collector: string           # Collection agent/tool (e.g., "Cribl Edge", "Filebeat", "Fluentd")
    channels: [string]          # Log channels/sources collected
    notes: string               # Free-text collection notes

  # === EXECUTION CONTEXT (for generated/simulated data) ===
  execution:
    user: string                # User context tests ran under
    method: string              # How tests were executed
    tool: string                # Test framework (e.g., "Atomic Red Team", "Caldera", "manual")
    tool_version: string        # Test framework version
    isolation: string           # Test isolation approach (e.g., "per-test cleanup", "snapshot restore")
    notes: string               # Free-text execution notes

  # === SECURITY CONTROLS ===
  # Platform-specific. Use the appropriate key for your platform.
  # Multiple platforms can be specified if the dataset spans environments.

  windows: WindowsEnvironment   # Windows-specific controls
  linux: LinuxEnvironment       # Linux-specific controls
  macos: MacOSEnvironment       # macOS-specific controls
  cloud: CloudEnvironment       # Cloud provider controls
  network: NetworkEnvironment   # Network device/capture context
  container: ContainerEnvironment  # Container runtime context
```

**All fields are optional.** Include what is relevant and known.

---

## Platform Specifications

### WindowsEnvironment

```yaml
windows:
  # === SYSMON ===
  sysmon:
    installed: bool             # Whether Sysmon is present
    version: string             # Sysmon version (e.g., "15.15")
    config_source: string       # Config origin (e.g., "sysmon-modular", "SwiftOnSecurity", "custom")
    config_hash: string         # SHA256 of config file
    hashing_algorithms: [string]  # e.g., ["SHA1", "MD5", "SHA256", "IMPHASH"]
    network_connect: bool       # EID 3 enabled
    image_load: bool            # EID 7 enabled
    dns_query: bool             # EID 22 enabled
    process_create_mode: string # "include", "exclude", or "all"
    notes: string               # Free-text (e.g., "filtered config — not all processes captured")

  # === AUDIT POLICY ===
  audit_policy:
    process_creation: string         # "success", "failure", "success_and_failure", "none"
    process_termination: string
    command_line_logging: bool        # Whether 4688 includes command line
    logon: string
    logoff: string
    special_logon: string
    object_access: string
    registry: string
    file_system: string
    account_management: string
    policy_change: string
    privilege_use: string
    token_right_adjusted: string
    kerberos: string
    credential_validation: string
    notes: string

  # === POWERSHELL LOGGING ===
  powershell:
    script_block_logging: bool       # EID 4104
    script_block_invocation: bool    # EID 4105/4106
    module_logging: bool             # EID 4103
    module_logging_scope: string     # e.g., "*" (all), or specific modules
    transcription: bool
    constrained_language_mode: bool
    notes: string

  # === ENDPOINT PROTECTION ===
  endpoint_protection:
    product: string              # e.g., "Windows Defender", "CrowdStrike Falcon", "SentinelOne"
    version: string
    real_time_protection: bool
    behavior_monitoring: bool
    amsi_enabled: bool           # Antimalware Scan Interface
    tamper_protection: bool
    cloud_protection: bool
    signature_version: string
    notes: string

  # === ADDITIONAL LOGGING ===
  etw_providers: [string]        # Additional ETW providers enabled
  wef_enabled: bool              # Windows Event Forwarding
  notes: string                  # General Windows notes
```

### LinuxEnvironment

```yaml
linux:
  # === AUDIT FRAMEWORK ===
  auditd:
    installed: bool
    version: string
    rule_count: int              # Number of active audit rules
    rule_source: string          # e.g., "laurel", "STIG", "custom"
    key_rules: [string]          # Notable rule descriptions
    notes: string

  # === SECURITY MODULES ===
  security_module:
    type: string                 # "selinux", "apparmor", "none"
    mode: string                 # "enforcing", "permissive", "disabled"
    policy: string               # e.g., "targeted", "mls"

  # === ENDPOINT PROTECTION ===
  endpoint_protection:
    product: string              # e.g., "CrowdStrike Falcon", "Wazuh", "OSSEC"
    version: string
    notes: string

  # === SYSLOG ===
  syslog:
    daemon: string               # "rsyslog", "syslog-ng", "journald"
    facilities_collected: [string]  # e.g., ["auth", "authpriv", "kern", "daemon"]
    notes: string

  # === ADDITIONAL MONITORING ===
  ebpf_monitoring: string        # e.g., "Falco", "Tracee", "none"
  shell_logging: bool            # bash/zsh command history to syslog
  notes: string
```

### MacOSEnvironment

```yaml
macos:
  # === ENDPOINT SECURITY ===
  endpoint_security_framework: bool  # ESF enabled
  endpoint_protection:
    product: string
    version: string
    notes: string

  # === UNIFIED LOGGING ===
  unified_logging:
    subsystems_collected: [string]
    predicates: [string]         # Log stream filter predicates
    notes: string

  # === ADDITIONAL ===
  gatekeeper: bool
  sip_enabled: bool              # System Integrity Protection
  notes: string
```

### CloudEnvironment

```yaml
cloud:
  provider: string               # "aws", "azure", "gcp", "oci"
  account_id: string             # Account/subscription/project ID (sanitize if needed)
  region: string                 # Primary region

  # === LOGGING CONFIGURATION ===
  logging:
    # AWS
    cloudtrail: bool
    cloudtrail_management_events: bool
    cloudtrail_data_events: bool
    vpc_flow_logs: bool
    guardduty: bool
    config_enabled: bool

    # Azure
    activity_log: bool
    diagnostic_settings: [string]
    defender_for_cloud: bool
    sentinel_enabled: bool

    # GCP
    cloud_audit_logs: bool
    data_access_logs: bool
    vpc_flow_logs: bool
    scc_enabled: bool            # Security Command Center

    notes: string

  notes: string
```

### NetworkEnvironment

```yaml
network:
  capture_type: string           # "pcap", "netflow", "zeek", "firewall_log", "ids_alert"
  capture_point: string          # e.g., "span port", "tap", "inline", "endpoint agent"
  sensor: string                 # e.g., "Zeek 6.0", "Suricata 7.0", "tcpdump"
  bpf_filter: string             # Capture filter if applicable
  protocols_monitored: [string]  # e.g., ["http", "dns", "tls", "smb"]
  encryption_visibility: string  # "none", "tls_inspection", "decrypted"
  notes: string
```

### ContainerEnvironment

```yaml
container:
  runtime: string                # "docker", "containerd", "cri-o"
  orchestrator: string           # "kubernetes", "ecs", "nomad", "standalone"
  orchestrator_version: string
  monitoring:
    product: string              # e.g., "Falco", "Sysdig", "Aqua"
    audit_logging: bool          # K8s audit log enabled
    runtime_protection: bool
    notes: string
  notes: string
```

---

## Examples

### Example 1: Windows ART Dataset

```yaml
environment:
  host:
    hostname: LAB-WS02
    os: Windows 11 Enterprise Evaluation
    os_version: "10.0.22631"
    architecture: x86_64
    domain: lab.local
    platform: QEMU/KVM

  execution:
    user: NT AUTHORITY\SYSTEM
    method: QEMU guest agent
    tool: Atomic Red Team
    tool_version: "329 techniques"
    isolation: per-test cleanup

  collection:
    collector: Cribl Edge
    channels:
      - Microsoft-Windows-Sysmon/Operational
      - Security
      - Microsoft-Windows-PowerShell/Operational

  windows:
    sysmon:
      installed: true
      version: "15.15"
      config_source: sysmon-modular (Olaf Hartong)
      config_hash: "SHA256=4516404F..."
      hashing_algorithms: [SHA1, MD5, SHA256, IMPHASH]
      network_connect: true
      image_load: true
      dns_query: true
      process_create_mode: include
      notes: >
        Filtered config — ProcessCreate uses include rules matching known-suspicious
        patterns. Not all process creations are captured in Sysmon. Security 4688
        with command-line auditing provides complementary full coverage.

    audit_policy:
      process_creation: success
      process_termination: success
      command_line_logging: true
      logon: success_and_failure
      special_logon: success_and_failure
      object_access: none
      account_management: none
      policy_change: none
      privilege_use: none
      token_right_adjusted: success
      kerberos: success_and_failure
      credential_validation: success_and_failure

    powershell:
      script_block_logging: true
      script_block_invocation: true
      module_logging: true
      module_logging_scope: "*"
      transcription: true

    endpoint_protection:
      product: Windows Defender
      version: "4.18.26010.5"
      real_time_protection: true
      behavior_monitoring: true
      amsi_enabled: true
      signature_version: "1.445.536.0"
      notes: >
        Fully active during all test executions. Many techniques are blocked
        before completion, producing attempt telemetry (process creation,
        command lines) but not success telemetry (LSASS access, file dumps).
```

### Example 2: Linux Auditd Dataset

```yaml
environment:
  host:
    hostname: web-prod-03
    os: Ubuntu 22.04 LTS
    os_version: "5.15.0-91-generic"
    architecture: x86_64

  collection:
    method: agent
    collector: Filebeat 8.12
    channels: [/var/log/audit/audit.log, /var/log/auth.log]

  linux:
    auditd:
      installed: true
      version: "3.0.7"
      rule_count: 47
      rule_source: "STIG + custom"
      key_rules:
        - "execve syscall logging for all users"
        - "file access on /etc/shadow, /etc/passwd"
        - "module load/unload"
        - "privilege escalation (setuid/setgid)"

    security_module:
      type: apparmor
      mode: enforcing

    endpoint_protection:
      product: CrowdStrike Falcon
      version: "7.10"
```

### Example 3: AWS CloudTrail Dataset

```yaml
environment:
  host:
    os: N/A
    platform: AWS

  collection:
    method: api
    collector: CloudTrail → S3 → Athena

  cloud:
    provider: aws
    region: us-east-1
    logging:
      cloudtrail: true
      cloudtrail_management_events: true
      cloudtrail_data_events: false
      vpc_flow_logs: true
      guardduty: true
      notes: >
        Data events (S3 object-level, Lambda invocations) not enabled.
        Techniques involving S3 data exfiltration will show bucket-level
        API calls but not individual GetObject/PutObject events.
```

### Example 4: Network Capture (Zeek)

```yaml
environment:
  collection:
    method: packet-capture
    collector: Zeek 6.0.4
    channels: [conn.log, dns.log, http.log, ssl.log, files.log]

  network:
    capture_type: zeek
    capture_point: span port (core switch)
    sensor: "Zeek 6.0.4 with JA4+ package"
    protocols_monitored: [http, dns, tls, smb, ssh, ftp, smtp]
    encryption_visibility: none
    notes: >
      No TLS inspection. Encrypted payloads are not visible — only
      connection metadata, JA4 fingerprints, and certificate information.
      HTTP/2 traffic over TLS appears only as connection logs.
```

---

## Best Practices

### Include What Matters

Not every field needs to be filled. Focus on the controls that directly affect what telemetry is present or absent:

- If your dataset has Sysmon data, describe the Sysmon config
- If techniques were blocked, describe the endpoint protection
- If certain log categories are missing, describe the audit policy
- If the dataset is from a cloud environment, describe which logging services were active

### Be Honest About Gaps

The `notes` fields exist for a reason. If you know the Sysmon config filters out certain process creations, say so. If Defender was active and blocked techniques, say so. If audit policy doesn't cover object access, say so. This is more valuable than a perfect-looking configuration that doesn't explain the data's limitations.

### Sanitize Sensitive Data

- Replace real hostnames with descriptive names if needed
- Redact account IDs or subscription IDs for public datasets
- Don't include API keys, tokens, or credentials
- Config hashes are fine to include — they identify the config without revealing its contents

### Use Notes for Context

The structured fields capture the "what." Use `notes` for the "so what" — the implications for the data. For example:

```yaml
# Good: explains impact on the data
notes: >
  ProcessCreate uses include-mode filtering. Only processes matching
  known-suspicious patterns generate Sysmon EID 1. Security 4688
  provides complementary full coverage.

# Less useful: just restates the field
notes: "Sysmon is installed and running"
```

---

## Extensibility

### Adding New Platforms

The platform keys (`windows`, `linux`, `macos`, `cloud`, `network`, `container`) are not a closed set. New platforms can be added as needed:

```yaml
environment:
  # Standard platforms
  windows: { ... }

  # Custom/new platform
  iot:
    device_type: "smart thermostat"
    firmware_version: "2.4.1"
    protocol: "MQTT"
    logging:
      local_syslog: true
      cloud_telemetry: true
```

### Adding New Fields to Existing Platforms

All platform specifications are open for extension. Add fields as needed — consumers should ignore fields they don't recognize:

```yaml
windows:
  sysmon:
    installed: true
    version: "15.15"
    # Custom field — not in the base spec
    custom_rules_count: 12
```

### Referencing External Configuration

For large configurations (e.g., full Sysmon XML), reference an external file rather than inlining:

```yaml
windows:
  sysmon:
    installed: true
    version: "15.15"
    config_source: sysmon-modular
    config_file: config/sysmonconfig.xml   # Relative to dataset root
    config_hash: "SHA256=4516404F..."
```
