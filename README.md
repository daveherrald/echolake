# EchoLake - Security Data Replay Tool

EchoLake is a Python-based tool for replaying security logs and events into SIEMs and security data lakes. It intelligently manipulates timestamps while preserving event deltas, supports multiple input/output formats, and provides both CLI and Python library interfaces.

## Features

- **Intelligent Timestamp Manipulation**: Preserve, expand, or compress time deltas between events
- **Flexible Time Expressions**: Relative time expressions (`now-2h`, `earliest+1d`, `latest-30m`)
- **Dry-Run Mode with Visualization**: Preview timeline and event distribution before writing output
- **Multiple Input Sources**: Local filesystem, AWS S3, Google Cloud Storage, Azure Blob Storage
- **Multiple Formats**: JSON, JSONL, plain text (XML support planned)
- **Schema Support**: Multiple output schemas including OCSF
- **Cloud Output**: Write to S3, GCS, or Azure Blob Storage
- **Dual Interface**: CLI tool and Python library (Config + EchoEngine)

## Installation

```bash
pip install echolake
```

For development:

```bash
git clone https://github.com/daveherrald/echolake.git
cd echolake
pip install -e ".[dev]"
```

## Quick Start

### CLI Usage

```bash
# Basic replay with config file
echolake echo --config echolake.yaml

# Replay with inline options
echolake echo \
  --input s3://my-bucket/logs/ \
  --output gcs://output-bucket/replayed/ \
  --delta-factor 2.0 \
  --input-format jsonl \
  --input-schema raw

# Replay with time expressions
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time latest \
  --target-time now-2h \
  --delta-factor 1.5

# Dry-run to preview (no output written)
echolake echo \
  --input ./logs \
  --output ./replayed \
  --base-time latest \
  --target-time now-2h \
  --dry-run

# Validate configuration
echolake validate echolake.yaml
```

### Python Library Usage

```python
from echolake import Config, EchoEngine

# Load from config file
config = Config.from_file("echolake.yaml")
engine = EchoEngine(config)
engine.setup()
stats = engine.run()
print(f"Processed {stats.events_written} events")
```

## Configuration

EchoLake supports configuration via:
1. CLI arguments (highest priority)
2. Environment variables
3. YAML config files
4. Defaults (lowest priority)

Example `echolake.yaml`:

```yaml
echo:
  delta_factor: 1.0  # 1.0 = preserve, >1.0 = expand, <1.0 = compress
  base_time: latest-30m  # earliest, latest, now-2h, earliest+1d, or ISO8601
  target_time: now-2h  # now, now-1d, or ISO8601 timestamp
  prevent_future: true
  ceiling_time: now  # Maximum allowed timestamp

input:
  source:
    type: gcs
    bucket: my-security-logs
    prefix: zeek-logs/
    pattern: "*.log"
  format: jsonl
  schema: raw

output:
  destination:
    type: s3
    bucket: replay-output
    path_template: "replayed/{year}/{month}/{day}/{filename}"
  format: jsonl
  compression: gzip
  batch_size: 1000
```

## Timestamp Manipulation

EchoLake provides several timestamp manipulation strategies:

- **Delta Preservation**: Maintain exact time differences between events (delta_factor=1.0)
- **Delta Expansion**: Spread events out over longer time (delta_factor>1.0)
- **Delta Compression**: Compress timeline (delta_factor<1.0)
- **Future Prevention**: Never generate timestamps beyond current time
- **Dual Timestamp Support**: Handle multiple timestamp fields per event

### Time Expressions

EchoLake supports Relative time expressions for flexible timestamp control:

```bash
# Use latest timestamp as base, target 2 hours ago
--base-time latest --target-time now-2h

# Start from 1 day after earliest, compress timeline by 50%
--base-time earliest+1d --target-time now-1w --delta-factor 0.5

# Complex expression: 30 minutes before latest, target 1.5 days ago
--base-time latest-30m --target-time now-1d-12h
```

**Supported time units**: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `mon` (months), `y` (years)

**Base keywords**: `now`, `earliest`, `latest`, or ISO8601 timestamp

See [docs/TIME_EXPRESSIONS.md](docs/TIME_EXPRESSIONS.md) for complete documentation.

## Supported Schemas

EchoLake supports multiple output schemas:

- **raw** - No transformation, preserve original format (default)
- **ocsf** - Open Cybersecurity Schema Framework with tagging
- **lakehouse_bronze** - Bronze layer schema with dual timestamp support

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=echolake --cov-report=html

# Format code
black src/ tests/

# Lint code
ruff check src/ tests/

# Type check
mypy src/
```

## Roadmap

### Current (MVP)
- ✅ Core replay engine
- ✅ Cloud bucket outputs (S3, GCS, Azure)
- ✅ JSONL format support
- ✅ Schema support (raw, OCSF, bronze)
- ✅ CLI interface
- ✅ Python library interface (Config + EchoEngine)
- ✅ Relative time expressions

### Future Phases
- API outputs (Chronicle, custom HTTP)
- XML format support
- Extraction from Delta tables
- Custom schema definitions
- Multi-threaded processing
- Resume capability

## Contributing

Contributions are welcome! Please see our contributing guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/daveherrald/echolake/issues)
- Examples: [examples/](examples/)
