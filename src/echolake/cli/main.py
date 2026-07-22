"""CLI interface for EchoLake."""

import sys
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ..core.config import Config
from ..core.echo import EchoEngine
from .. import __version__
from .visualization import (
    print_timeline,
    print_transformation_summary,
    calculate_event_buckets,
)

app = typer.Typer(
    name="echolake",
    help="EchoLake - Security Data Echo Tool",
    add_completion=False,
)
console = Console()


@app.command()
def echo(
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file (YAML)",
        exists=True,
    ),
    dataset: Optional[str] = typer.Option(
        None,
        "--dataset",
        "-l",
        help="Dataset reference (github:org/repo/path, local:/path, etc.)",
    ),
    input_source: Optional[str] = typer.Option(
        None,
        "--input",
        "-i",
        help="Input source (path, bucket URI, etc.)",
    ),
    input_format: Optional[str] = typer.Option(
        None,
        "--input-format",
        help="Input format (auto, json, jsonl, text, xml). Default: auto (detects per line)",
    ),
    input_schema: Optional[str] = typer.Option(
        None,
        "--input-schema",
        help="Input schema (lakehouse_bronze, ocsf, raw)",
    ),
    output_dest: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output destination (path, bucket URI, etc.)",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output-format",
        help="Output format (json, jsonl, text)",
    ),
    delta_factor: Optional[float] = typer.Option(
        None,
        "--delta-factor",
        "-d",
        help="Time delta multiplication factor",
    ),
    base_time: Optional[str] = typer.Option(
        None,
        "--base-time",
        "-b",
        help="Original base time (earliest, latest, earliest+1d, latest-2h, or ISO8601)",
    ),
    target_time: Optional[str] = typer.Option(
        None,
        "--target-time",
        "-t",
        help="Target time for echo (now, now-2h, now+1d, or ISO8601)",
    ),
    ceiling_time: Optional[str] = typer.Option(
        None,
        "--ceiling-time",
        help="Maximum timestamp (now, now-1h, or ISO8601)",
    ),
    no_prevent_future: bool = typer.Option(
        False,
        "--no-prevent-future",
        help="Allow timestamps in the future (disables future prevention)",
    ),
    no_shift: bool = typer.Option(
        False,
        "--no-shift",
        help="Passthrough: emit events with their original timestamps and skip the Phase 1 scan (no _time or _raw changes)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Dry run mode (don't write output)",
    ),
    show_timeline: bool = typer.Option(
        False,
        "--show-timeline",
        help="Show timeline visualization in output",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose output",
    ),
    max_memory: Optional[int] = typer.Option(
        None,
        "--max-memory",
        help="Maximum memory to use in MB (default: 70%% of available)",
    ),
    max_file_size: Optional[int] = typer.Option(
        None,
        "--max-file-size",
        help="Skip files larger than this (MB, decompressed estimate)",
    ),
    skip_memory_check: bool = typer.Option(
        False,
        "--skip-memory-check",
        help="Skip memory safety checks (not recommended)",
    ),
    path_template: Optional[str] = typer.Option(
        None,
        "--path-template",
        help="Path template for output files. Variables: {filename}, {sourcetype}, {year}, {month}, {day}, {hour}, {minute}",
    ),
    compression: Optional[str] = typer.Option(
        None,
        "--compression",
        help="Output compression (gzip, bzip2)",
    ),
    workers: int = typer.Option(
        1,
        "--workers",
        "-w",
        help="Number of concurrent file processing workers (default: 1)",
        min=1,
        max=32,
    ),
    hec_workers: Optional[int] = typer.Option(
        None,
        "--hec-workers",
        help="Concurrent HEC POST workers for the splunk_hec output (default: 1)",
        min=1,
        max=64,
    ),
):
    """
    Echo security logs with timestamp manipulation.

    Examples:

        # Using config file
        echolake echo --config echolake.yaml

        # Using dataset
        echolake echo --dataset github:echolake/datasets/mitre-attack/t1078 --output ./echoed

        # Using CLI arguments
        echolake echo --input ./logs --output ./echoed --delta-factor 2.0

        # Echo from S3 to GCS
        echolake echo --input s3://my-bucket/logs --output gcs://my-bucket/echoed
    """
    try:
        # Load configuration
        if config:
            cfg = Config.from_file(config)
        else:
            cfg = Config()

        # Add dataset if specified
        if dataset:
            from ..core.config import DatasetConfig

            # Just set the dataset reference - let EchoEngine handle resolution
            # (including downloading file references, merging defaults, etc.)
            cfg.dataset = DatasetConfig(ref=dataset)
            console.print(f"[cyan]Loading dataset: {dataset}[/cyan]")

        # Override with CLI arguments
        if input_source:
            # Parse input source
            source_type, source_path = _parse_source(input_source)
            if not cfg.input:
                from ..core.config import InputConfig, InputSourceConfig
                cfg.input = InputConfig(
                    source=InputSourceConfig(type=source_type, path=source_path),
                    format=input_format or "jsonl",
                    schema_type=input_schema,
                )
            else:
                cfg.input.source.type = source_type
                cfg.input.source.path = source_path

        if input_format and cfg.input:
            cfg.input.format = input_format

        if input_schema and cfg.input:
            cfg.input.schema_type = input_schema

        if output_dest:
            # Parse output destination
            dest_type, dest_path = _parse_source(output_dest)
            if not cfg.output:
                from ..core.config import OutputConfig, OutputDestinationConfig
                if dest_type in ('s3', 'gcs', 'azure'):
                    bucket, prefix = _split_cloud_path(dest_path)
                    cfg.output = OutputConfig(
                        destination=OutputDestinationConfig(
                            type=dest_type,
                            bucket=bucket,
                            path_template=prefix.rstrip('/') + "/{filename}",
                        ),
                        format=output_format or "jsonl",
                    )
                else:
                    cfg.output = OutputConfig(
                        destination=OutputDestinationConfig(type=dest_type, path=dest_path),
                        format=output_format or "jsonl",
                    )
            else:
                cfg.output.destination.type = dest_type
                if dest_type in ('s3', 'gcs', 'azure'):
                    bucket, prefix = _split_cloud_path(dest_path)
                    cfg.output.destination.bucket = bucket
                    cfg.output.destination.path_template = prefix.rstrip('/') + "/{filename}"
                else:
                    cfg.output.destination.path = dest_path

        if output_format and cfg.output:
            cfg.output.format = output_format

        if delta_factor is not None:
            cfg.echo.delta_factor = delta_factor

        if base_time:
            cfg.echo.base_time = base_time

        if target_time:
            cfg.echo.target_time = target_time

        if ceiling_time:
            cfg.echo.ceiling_time = ceiling_time

        if no_prevent_future:
            cfg.echo.prevent_future = False

        if no_shift:
            cfg.echo.no_shift = True

        if path_template and cfg.output:
            # If the output URL included a prefix (e.g. s3://bucket/prefix),
            # prepend it to the user-provided path template.
            if cfg.output.destination.bucket:
                existing = cfg.output.destination.path_template or ""
                # Extract the prefix portion (everything before the default {filename})
                prefix_part = existing.rsplit("/{filename}", 1)[0] if "/{filename}" in existing else ""
                if prefix_part:
                    cfg.output.destination.path_template = prefix_part.rstrip('/') + '/' + path_template.lstrip('/')
                else:
                    cfg.output.destination.path_template = path_template
            else:
                cfg.output.destination.path_template = path_template

        if compression and cfg.output:
            cfg.output.compression = compression

        if hec_workers and cfg.output and cfg.output.destination:
            cfg.output.destination.hec_max_workers = hec_workers

        # Note: Don't validate cfg.input/output here - if dataset is specified,
        # EchoEngine will resolve it and create input config automatically

        # Show configuration if verbose (only if already configured)
        if verbose and cfg.input and cfg.output:
            console.print("\n[bold]Configuration:[/bold]")
            console.print(f"  Input: {cfg.input.source.type}://{cfg.input.source.path or cfg.input.source.bucket}")
            console.print(f"  Output: {cfg.output.destination.type}://{cfg.output.destination.path or cfg.output.destination.bucket}")
            console.print(f"  Format: {cfg.input.format} -> {cfg.output.format}")
            console.print(f"  Schema: {cfg.input.schema_type or 'raw'}")
            console.print(f"  Delta Factor: {cfg.echo.delta_factor}")
            console.print(f"  Base Time: {cfg.echo.base_time}")
            console.print(f"  Target Time: {cfg.echo.target_time}")
            console.print(f"  Ceiling Time: {cfg.echo.ceiling_time}\n")

        # Memory safety checks
        if not skip_memory_check:
            from ..core.memory_guard import MemoryGuard
            from ..inputs.sources import get_source

            # Get list of files that will be processed
            try:
                source = get_source(cfg.input.source.type, **{
                    'path': cfg.input.source.path,
                    'bucket': cfg.input.source.bucket,
                    'prefix': cfg.input.source.prefix,
                    'pattern': cfg.input.source.pattern or '*',
                })
                file_paths = [Path(f) for f in source.list_files()]
                source.close()

                if file_paths:
                    # Filter out files larger than max_file_size (if specified)
                    if max_file_size:
                        filtered_files = []
                        skipped_files = []
                        max_bytes = max_file_size * 1024 * 1024

                        for file_path in file_paths:
                            estimated_size = MemoryGuard._estimate_decompressed_size(file_path)
                            if estimated_size > max_bytes:
                                skipped_files.append((file_path.name, estimated_size // (1024 * 1024)))
                            else:
                                filtered_files.append(file_path)

                        if skipped_files:
                            console.print(f"\n[yellow]Skipping {len(skipped_files)} large files (>{max_file_size} MB decompressed):[/yellow]")
                            for name, size_mb in skipped_files[:5]:
                                console.print(f"  - {name} (~{size_mb} MB)")
                            if len(skipped_files) > 5:
                                console.print(f"  ... and {len(skipped_files) - 5} more")
                            console.print()

                        file_paths = filtered_files

                        # Apply file filter to config so EchoEngine only processes these files
                        cfg.input.source.include_files = [str(fp) for fp in filtered_files]

                    # Run memory check on remaining files (streaming mode - checks largest file only)
                        if file_paths:
                            guard = MemoryGuard(max_memory_mb=max_memory)
                            is_safe, message, estimated_mb, limit_mb = guard.check_files(file_paths, streaming=True)

                            if not is_safe:
                                console.print(f"\n[red]❌ {message}[/red]\n")
                                raise typer.Exit(1)
                            elif estimated_mb > limit_mb * 0.5:
                                console.print(f"\n[yellow]⚠️  {message}[/yellow]\n")

            except KeyboardInterrupt:
                console.print("\n[yellow]⚠️  Memory check interrupted[/yellow]")
                raise typer.Exit(130)
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]Warning: Could not perform memory check: {e}[/yellow]")

        # Run echo (with or without dry-run)
        if dry_run:
            console.print("[yellow]Dry run mode - analyzing without writing output[/yellow]\n")

        console.print("[bold]Starting echo...[/bold]")
        engine = EchoEngine(cfg, dry_run=dry_run, workers=workers)
        stats = engine.run()

        # Show results
        if dry_run:
            # Enhanced dry-run output with optional timeline visualization
            _print_dry_run_results(stats, cfg, engine, show_timeline=show_timeline)
        else:
            # Normal stats output
            _print_stats(stats, show_timeline=show_timeline)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@app.command()
def validate(
    config: Path = typer.Argument(
        ...,
        help="Path to configuration file (YAML)",
        exists=True,
    ),
):
    """
    Validate configuration file.

    Example:
        echolake validate echolake.yaml
    """
    try:
        cfg = Config.from_file(config)
        console.print(f"[green]✓[/green] Configuration is valid: {config}")

        # Show summary
        if cfg.input:
            console.print(f"\n[bold]Input:[/bold]")
            console.print(f"  Source: {cfg.input.source.type}")
            console.print(f"  Format: {cfg.input.format}")
            console.print(f"  Schema: {cfg.input.schema_type or 'raw'}")

        if cfg.output:
            console.print(f"\n[bold]Output:[/bold]")
            console.print(f"  Destination: {cfg.output.destination.type}")
            console.print(f"  Format: {cfg.output.format}")
            console.print(f"  Compression: {cfg.output.compression or 'none'}")

        console.print(f"\n[bold]Echo:[/bold]")
        console.print(f"  Delta Factor: {cfg.echo.delta_factor}")
        console.print(f"  Base Time: {cfg.echo.base_time}")
        console.print(f"  Target Time: {cfg.echo.target_time}")
        console.print(f"  Ceiling Time: {cfg.echo.ceiling_time}")
        console.print(f"  Prevent Future: {cfg.echo.prevent_future}")

    except Exception as e:
        console.print(f"[red]✗[/red] Configuration is invalid: {e}")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    console.print(f"EchoLake version {__version__}")


@app.command(name="validate-dataset")
def validate_set(
    path: Path = typer.Argument(
        ...,
        help="Path to dataset directory or dataset.yaml file",
        exists=True,
    ),
    check_files: bool = typer.Option(
        False,
        "--check-files",
        help="Verify that bundled files exist",
    ),
):
    """
    Validate a dataset manifest.

    Examples:
        echolake validate-dataset ./my-dataset/
        echolake validate-dataset ./my-dataset/dataset.yaml --check-files
    """
    try:
        from ..datasets.models import DatasetManifest

        # Determine manifest path
        if path.is_dir():
            manifest_path = path / "dataset.yaml"
        else:
            manifest_path = path

        if not manifest_path.exists():
            console.print(f"[red]Error: Manifest file not found: {manifest_path}[/red]")
            raise typer.Exit(1)

        # Load and validate manifest
        manifest = DatasetManifest.from_file(manifest_path)
        console.print(f"[green]✓[/green] Manifest is valid: {manifest_path}")

        # Show basic info
        console.print(f"\n[bold]Dataset: {manifest.metadata.name}[/bold]")
        console.print(f"Version: {manifest.metadata.version}")
        console.print(f"Description: {manifest.metadata.description}")

        # Check files if requested
        if check_files:
            base_path = manifest_path.parent if manifest_path.name == "dataset.yaml" else manifest_path.parent.parent
            missing = manifest.validate_files_exist(base_path)
            if missing:
                console.print(f"\n[red]Missing files:[/red]")
                for f in missing:
                    console.print(f"  - {f}")
                raise typer.Exit(1)
            else:
                console.print(f"\n[green]✓[/green] All bundled files exist ({len(manifest.files.bundled)} files)")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="info-dataset")
def info_set(
    path: Path = typer.Argument(
        ...,
        help="Path to dataset directory or dataset.yaml file",
        exists=True,
    ),
):
    """
    Show detailed information about a dataset.

    Examples:
        echolake info-dataset ./my-dataset/
        echolake info-dataset ./my-dataset/dataset.yaml
    """
    try:
        from ..datasets.models import DatasetManifest

        # Determine manifest path
        if path.is_dir():
            manifest_path = path / "dataset.yaml"
        else:
            manifest_path = path

        if not manifest_path.exists():
            console.print(f"[red]Error: Manifest file not found: {manifest_path}[/red]")
            raise typer.Exit(1)

        # Load manifest
        manifest = DatasetManifest.from_file(manifest_path)

        # Print metadata
        console.print(f"\n[bold cyan]{manifest.metadata.name}[/bold cyan] v{manifest.metadata.version}")
        console.print(f"{manifest.metadata.description}\n")

        # Metadata table
        meta_table = Table(title="Metadata", show_header=False)
        meta_table.add_column("Field", style="cyan")
        meta_table.add_column("Value")

        if manifest.metadata.author:
            meta_table.add_row("Author", manifest.metadata.author)
        if manifest.metadata.created:
            meta_table.add_row("Created", manifest.metadata.created)
        if manifest.metadata.updated:
            meta_table.add_row("Updated", manifest.metadata.updated)
        if manifest.metadata.license:
            meta_table.add_row("License", manifest.metadata.license)
        if manifest.metadata.tags:
            meta_table.add_row("Tags", ", ".join(manifest.metadata.tags))

        console.print(meta_table)

        # MITRE ATT&CK info
        if manifest.metadata.mitre_attack:
            console.print()
            mitre_table = Table(title="MITRE ATT&CK")
            mitre_table.add_column("Technique ID", style="yellow")
            mitre_table.add_column("Name", style="white")
            mitre_table.add_column("Tactics", style="cyan")

            for tech in manifest.metadata.mitre_attack.techniques:
                mitre_table.add_row(
                    tech.id,
                    tech.name,
                    ", ".join(tech.tactics) if tech.tactics else ""
                )

            console.print(mitre_table)

        # Files
        if manifest.files.bundled:
            console.print()
            files_table = Table(title="Bundled Files")
            files_table.add_column("Path", style="green")
            files_table.add_column("Format", style="yellow")
            files_table.add_column("Schema", style="cyan")
            files_table.add_column("Events", style="magenta", justify="right")

            for f in manifest.files.bundled:
                files_table.add_row(
                    f.path,
                    f.format,
                    f.schema_type or "-",
                    str(f.event_count) if f.event_count else "-"
                )

            console.print(files_table)

        # File references
        if manifest.files.references:
            console.print()
            refs_table = Table(title="File References")
            refs_table.add_column("URI", style="blue")
            refs_table.add_column("Format", style="yellow")
            refs_table.add_column("Checksum", style="green")

            for ref in manifest.files.references:
                checksum = ref.checksum[:20] + "..." if ref.checksum and len(ref.checksum) > 23 else (ref.checksum or "-")
                refs_table.add_row(
                    ref.uri,
                    ref.format,
                    checksum
                )

            console.print(refs_table)

        # Dependencies
        if manifest.dependencies:
            console.print()
            deps_table = Table(title="Dependencies")
            deps_table.add_column("Dataset", style="cyan")
            deps_table.add_column("Version", style="yellow")
            deps_table.add_column("Description")

            for dep in manifest.dependencies:
                deps_table.add_row(
                    dep.dataset,
                    dep.version,
                    dep.description or ""
                )

            console.print(deps_table)

        # Defaults
        if manifest.defaults:
            console.print()
            console.print("[bold]Defaults:[/bold]")
            if manifest.defaults.echo:
                console.print(f"  Echo: {manifest.defaults.echo}")
            elif manifest.defaults.replay:
                console.print(f"  Echo: {manifest.defaults.replay}")
            if manifest.defaults.schema_type:
                console.print(f"  Schema: {manifest.defaults.schema_type}")

        console.print()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="preview-dataset")
def preview_dataset(
    dataset_ref: str = typer.Argument(
        ...,
        help="Dataset reference (local:/path, github:org/repo/path, etc.)",
    ),
    lines: int = typer.Option(
        10,
        "--lines",
        "-n",
        help="Number of lines to show from each file (default: 10)",
    ),
):
    """
    Preview sample log entries from a dataset.

    Shows the first N lines from each file in the dataset, including
    both bundled files and external file references.

    Examples:
        echolake preview-dataset local:my-datasets/ransomware-notes-bulk-creation
        echolake preview-dataset local:./my-dataset --lines 20
        echolake preview-dataset github:org/repo/dataset-name
    """
    try:
        from ..datasets.resolver import DatasetResolver
        from ..datasets.cache import DatasetCache

        console.print(f"\n[bold cyan]Previewing dataset:[/bold cyan] {dataset_ref}\n")

        # Resolve dataset
        resolver = DatasetResolver()
        resolved = resolver.resolve(dataset_ref)

        # Get all files
        bundled_files = resolved.get_all_bundled_files()
        file_references = resolved.get_all_file_references()

        total_files = len(bundled_files) + len(file_references)
        if total_files == 0:
            console.print("[yellow]No files found in dataset[/yellow]")
            return

        console.print(f"Found {total_files} file(s) in dataset\n")

        # Cache for downloading file references
        cache = DatasetCache()

        file_count = 0

        # Preview bundled files
        for bundled_file in bundled_files:
            file_count += 1
            file_path = bundled_file

            console.print(f"[bold green]File {file_count}/{total_files}:[/bold green] {file_path.name}")
            console.print(f"[dim]Location:[/dim] {file_path}")
            console.print(f"[dim]Size:[/dim] {file_path.stat().st_size:,} bytes")
            console.print()

            # Read and display first N lines
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    console.print("[bold]Sample log entries:[/bold]")
                    for i, line in enumerate(f, 1):
                        if i > lines:
                            break
                        # Truncate very long lines
                        if len(line) > 200:
                            line = line[:200] + "..."
                        console.print(f"  {i:2d}: {line.rstrip()}")

                    if i >= lines:
                        console.print(f"[dim]  ... ({lines} of many lines shown)[/dim]")
                    else:
                        console.print(f"[dim]  ... (all {i} lines shown)[/dim]")
            except Exception as e:
                console.print(f"[red]  Error reading file: {e}[/red]")

            console.print()

        # Preview file references (download and cache first)
        for file_ref in file_references:
            file_count += 1

            console.print(f"[bold green]File {file_count}/{total_files}:[/bold green] {file_ref.uri}")
            console.print(f"[dim]Format:[/dim] {file_ref.format}")
            if file_ref.description:
                console.print(f"[dim]Description:[/dim] {file_ref.description}")

            # Download/cache the file
            try:
                console.print("[dim]Downloading/caching...[/dim]")
                cached_path = cache.download_file_reference(
                    uri=file_ref.uri,
                    checksum=file_ref.checksum,
                    timeout=120,
                )
                console.print(f"[dim]Cached at:[/dim] {cached_path}")
                console.print(f"[dim]Size:[/dim] {cached_path.stat().st_size:,} bytes")
                console.print()

                # Read and display first N lines
                with open(cached_path, 'r', errors='ignore') as f:
                    console.print("[bold]Sample log entries:[/bold]")
                    for i, line in enumerate(f, 1):
                        if i > lines:
                            break
                        # Truncate very long lines
                        if len(line) > 200:
                            line = line[:200] + "..."
                        console.print(f"  {i:2d}: {line.rstrip()}")

                    if i >= lines:
                        console.print(f"[dim]  ... ({lines} of many lines shown)[/dim]")
                    else:
                        console.print(f"[dim]  ... (all {i} lines shown)[/dim]")

            except Exception as e:
                console.print(f"[red]  Error: {e}[/red]")

            console.print()

        console.print(f"[green]✓[/green] Preview complete\n")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="install-dataset")
def install_set(
    ref: str = typer.Argument(
        ...,
        help="Dataset reference (local:/path, https://url, github:org/repo/path, etc.)",
    ),
    version: Optional[str] = typer.Option(
        None,
        "--version",
        "-v",
        help="Specific version to install",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force re-download even if cached",
    ),
):
    """
    Download and cache a dataset.

    Examples:
        echolake install-dataset github:echolake/datasets/mitre-attack/t1078
        echolake install-dataset https://example.com/datasets/my-set
        echolake install-dataset local:./my-dataset
    """
    try:
        from ..datasets.resolver import DatasetResolver
        from ..datasets.cache import LogSetCache

        # Add version to ref if specified
        if version:
            ref = f"{ref}@{version}"

        console.print(f"[bold]Installing dataset:[/bold] {ref}")

        # Resolve and download
        resolver = DatasetResolver()
        resolved = resolver.resolve(ref, force_download=force)

        console.print(f"[green]✓[/green] Installed: {resolved.manifest.metadata.name} v{resolved.manifest.metadata.version}")
        console.print(f"  Cached at: {resolved.base_path}")

        # Show file count
        bundled_count = len(resolved.manifest.files.bundled)
        ref_count = len(resolved.manifest.files.references)
        console.print(f"  Files: {bundled_count} bundled, {ref_count} references")

        # Show dependencies
        if resolved.manifest.dependencies:
            console.print(f"  Dependencies: {len(resolved.manifest.dependencies)}")
            for dep in resolved.manifest.dependencies:
                console.print(f"    - {dep.dataset} {dep.version}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="list-datasets")
def list_sets(
    repository: Optional[str] = typer.Option(
        None,
        "--repository",
        "-r",
        help="Filter by repository name",
    ),
    tags: Optional[str] = typer.Option(
        None,
        "--tags",
        "-t",
        help="Filter by tags (comma-separated)",
    ),
    mitre_technique: Optional[str] = typer.Option(
        None,
        "--mitre-technique",
        "-m",
        help="Filter by MITRE ATT&CK technique ID",
    ),
    local_only: bool = typer.Option(
        False,
        "--local-only",
        help="Show only locally cached datasets",
    ),
):
    """
    List available datasets.

    Examples:
        echolake list-datasets
        echolake list-datasets --repository official
        echolake list-datasets --tags authentication,credential-abuse
        echolake list-datasets --mitre-technique T1078
        echolake list-datasets --local-only
    """
    try:
        from ..datasets.registry import LogSetRegistry
        from ..datasets.resolver import DatasetResolver

        if local_only:
            # List cached datasets
            resolver = DatasetResolver()
            cached = resolver.list_cached()

            if not cached:
                console.print("[yellow]No cached datasets found[/yellow]")
                return

            table = Table(title="Cached Datasets")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="yellow")
            table.add_column("Description")
            table.add_column("Path", style="green")

            for cache_key, info in cached.items():
                table.add_row(
                    info["name"],
                    info["version"],
                    info["description"][:50] + "..." if len(info["description"]) > 50 else info["description"],
                    cache_key,
                )

            console.print(table)
        else:
            # List from repositories
            registry = LogSetRegistry()

            if not registry.repositories:
                console.print("[yellow]No repositories configured[/yellow]")
                console.print("\nTo add a repository, create ~/.echolake/repositories.yaml:")
                console.print("""
repositories:
  - name: "official"
    url: "github:echolake/datasets"
    description: "Official EchoLake datasets"
    enabled: true
""")
                return

            # Parse tags
            tag_list = None
            if tags:
                tag_list = [t.strip() for t in tags.split(',')]

            # List datasets
            datasets = registry.list_datasets(
                repository_name=repository,
                tags=tag_list,
                mitre_technique=mitre_technique,
            )

            if not datasets:
                console.print("[yellow]No datasets found matching criteria[/yellow]")
                return

            table = Table(title=f"Available Datasets ({len(datasets)} found)")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="yellow")
            table.add_column("Repository", style="magenta")
            table.add_column("Description")

            for dataset in datasets:
                desc = dataset.get("description", "")
                if len(desc) > 60:
                    desc = desc[:57] + "..."

                table.add_row(
                    dataset["name"],
                    dataset["version"],
                    dataset["repository"],
                    desc,
                )

            console.print(table)
            console.print(f"\n[dim]Use 'echolake info-dataset <reference>' for details[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="search-datasets")
def search_sets(
    query: str = typer.Argument(
        ...,
        help="Search query",
    ),
    search_in: Optional[str] = typer.Option(
        None,
        "--search-in",
        help="Fields to search (name,description,tags,mitre_attack)",
    ),
):
    """
    Search for datasets.

    Examples:
        echolake search-datasets "credential abuse"
        echolake search-datasets "T1078" --search-in mitre_attack
        echolake search-datasets "authentication" --search-in tags
    """
    try:
        from ..datasets.registry import LogSetRegistry

        registry = LogSetRegistry()

        if not registry.repositories:
            console.print("[yellow]No repositories configured[/yellow]")
            return

        # Parse search_in
        search_fields = None
        if search_in:
            search_fields = [f.strip() for f in search_in.split(',')]

        # Search
        results = registry.search_datasets(query, search_in=search_fields)

        if not results:
            console.print(f"[yellow]No datasets found matching '{query}'[/yellow]")
            return

        table = Table(title=f"Search Results for '{query}' ({len(results)} found)")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("Repository", style="magenta")
        table.add_column("Description")

        for dataset in results:
            desc = dataset.get("description", "")
            if len(desc) > 60:
                desc = desc[:57] + "..."

            table.add_row(
                dataset["name"],
                dataset["version"],
                dataset["repository"],
                desc,
            )

        console.print(table)
        console.print(f"\n[dim]Use 'echolake install-dataset <reference>' to install[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="list-profiles")
def list_profiles(
    tags: Optional[str] = typer.Option(
        None,
        "--tags",
        "-t",
        help="Filter by tags (comma-separated)",
    ),
):
    """
    List available echo profiles.

    Examples:
        echolake list-profiles
        echolake list-profiles --tags apt,training
    """
    try:
        from ..profiles import find_profiles

        profiles = find_profiles()

        if not profiles:
            console.print("[yellow]No profiles found[/yellow]")
            console.print("\nProfiles are searched in:")
            console.print("  - ./profiles/")
            console.print("  - ./examples/profiles/")
            console.print("  - ~/.echolake/profiles/")
            return

        # Filter by tags if specified
        if tags:
            tag_list = [t.strip() for t in tags.split(',')]
            profiles = [
                p for p in profiles
                if any(tag in p.get("tags", []) for tag in tag_list)
            ]

        if not profiles:
            console.print(f"[yellow]No profiles found with tags: {tags}[/yellow]")
            return

        table = Table(title=f"Echo Profiles ({len(profiles)} found)")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("Datasets", style="magenta", justify="right")
        table.add_column("Description")

        for profile in sorted(profiles, key=lambda x: x["name"]):
            desc = profile.get("description", "")
            if len(desc) > 60:
                desc = desc[:57] + "..."

            table.add_row(
                profile["name"],
                profile["version"],
                str(profile.get("datasets_count", 0)),
                desc,
            )

        console.print(table)
        console.print(f"\n[dim]Use 'echolake echo-profile <name> --destination <dest>' to echo[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="list-destinations")
def list_destinations(
    dest_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="Filter by destination type",
    ),
):
    """
    List available destinations.

    Examples:
        echolake list-destinations
        echolake list-destinations --type s3
    """
    try:
        from ..profiles import find_destinations

        destinations = find_destinations()

        if not destinations:
            console.print("[yellow]No destinations found[/yellow]")
            console.print("\nDestinations are searched in:")
            console.print("  - ./destinations/")
            console.print("  - ./examples/destinations/")
            console.print("  - ~/.echolake/destinations/")
            return

        # Filter by type if specified
        if dest_type:
            destinations = [
                d for d in destinations
                if d["type"].lower() == dest_type.lower()
            ]

        if not destinations:
            console.print(f"[yellow]No destinations found with type: {dest_type}[/yellow]")
            return

        table = Table(title=f"Destinations ({len(destinations)} found)")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Description")

        for dest in sorted(destinations, key=lambda x: x["name"]):
            desc = dest.get("description", "")
            if len(desc) > 60:
                desc = desc[:57] + "..."

            table.add_row(
                dest["name"],
                dest["type"],
                desc,
            )

        console.print(table)
        console.print(f"\n[dim]Use 'echolake echo-profile <profile> --destination <name>' to echo[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="echo-profile")
def echo_profile(
    profile_name: str = typer.Argument(
        ...,
        help="Profile name or path",
    ),
    destination: List[str] = typer.Option(
        ...,
        "--destination",
        "-d",
        help="Destination name(s) - can specify multiple times",
    ),
    delta_factor: Optional[float] = typer.Option(
        None,
        "--delta-factor",
        help="Override delta factor",
    ),
    target_time: Optional[str] = typer.Option(
        None,
        "--target-time",
        "-t",
        help="Override target time",
    ),
    schema: Optional[str] = typer.Option(
        None,
        "--schema",
        help="Override schema",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Dry run mode (don't write output)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose output",
    ),
):
    """
    Echo logs using an echo profile.

    Examples:
        # Basic echo
        echolake echo-profile weekly-apt-simulation --destination s3-archive

        # Multiple destinations
        echolake echo-profile my-profile -d s3-archive -d local-output

        # With overrides
        echolake echo-profile my-profile -d local-output --delta-factor 0.5

        # Dry run first
        echolake echo-profile my-profile -d s3-archive --dry-run
    """
    try:
        from ..profiles import load_profile, load_destination, load_credentials_file, ProfileExecutor

        console.print(f"[bold]Loading profile:[/bold] {profile_name}")

        # Load profile
        profile = load_profile(profile_name)
        console.print(f"[green]✓[/green] Profile: {profile.profile.name} v{profile.profile.version}")
        console.print(f"  Description: {profile.profile.description}")
        console.print(f"  Datasets: {len(profile.datasets)}")

        # Load destinations
        destinations = []
        console.print(f"\n[bold]Loading destination(s):[/bold]")
        for dest_name in destination:
            dest = load_destination(dest_name)
            destinations.append(dest)
            console.print(f"[green]✓[/green] Destination: {dest.destination.name} ({dest.type})")

        # Load credentials
        credentials = load_credentials_file()
        if credentials:
            console.print(f"\n[dim]Loaded credentials for {len(credentials)} destination(s)[/dim]")

        # Build runtime overrides
        overrides = {}
        if delta_factor is not None:
            overrides["delta_factor"] = delta_factor
        if target_time is not None:
            overrides["target_time"] = target_time
        if schema is not None:
            overrides["schema"] = schema

        # Show execution plan
        console.print(f"\n[bold]Execution Plan:[/bold]")
        for i, dataset_ref in enumerate(profile.datasets, 1):
            console.print(f"  {i}. {dataset_ref.ref}")
            if dataset_ref.description:
                console.print(f"     [dim]{dataset_ref.description}[/dim]")

        # Show timing config
        echo_cfg = profile.echo if hasattr(profile, 'echo') else profile.replay
        if overrides.get("delta_factor") is not None:
            console.print(f"\n[bold]Timing:[/bold] delta_factor={overrides['delta_factor']} [yellow](CLI override)[/yellow]")
        elif echo_cfg:
            console.print(f"\n[bold]Timing:[/bold] delta_factor={echo_cfg.delta_factor}")
        else:
            console.print(f"\n[bold]Timing:[/bold] delta_factor=1.0 [dim](default)[/dim]")

        # Show destinations
        console.print(f"\n[bold]Destinations:[/bold]")
        for dest in destinations:
            console.print(f"  - {dest.destination.name} ({dest.type})")

        if dry_run:
            console.print(f"\n[yellow]Dry run mode - analyzing without writing output[/yellow]")

        # Execute echo
        console.print(f"\n[bold]Starting echo...[/bold]\n")

        executor = ProfileExecutor(
            profile=profile,
            destinations=destinations,
            credentials=credentials,
            overrides=overrides,
        )

        results = executor.execute(dry_run=dry_run)

        # Show results
        console.print(f"\n[bold green]✓ Echo Complete[/bold green]\n")

        # Summary table
        summary_table = Table(title="Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="magenta")

        summary_table.add_row("Profile", results["profile"])
        summary_table.add_row("Version", results["version"])
        summary_table.add_row("Datasets Processed", str(len(results["datasets"])))
        summary_table.add_row("Total Events", f"{results['total_events']:,}")
        summary_table.add_row("Events Modified", f"{results['total_modified']:,}")
        summary_table.add_row("Errors", str(results["errors"]))

        console.print(summary_table)

        # Dataset details
        if results["datasets"] and verbose:
            console.print()
            dataset_table = Table(title="Dataset Details")
            dataset_table.add_column("Dataset", style="cyan")
            dataset_table.add_column("Events", style="magenta", justify="right")
            dataset_table.add_column("Modified", style="yellow", justify="right")

            for ds in results["datasets"]:
                if "error" not in ds:
                    dataset_table.add_row(
                        ds.get("ref", "unknown"),
                        f"{ds.get('event_count', 0):,}",
                        f"{ds.get('events_modified', 0):,}",
                    )

            console.print(dataset_table)

        if results["errors"] > 0:
            console.print(f"\n[yellow]Warning: {results['errors']} error(s) occurred during echo[/yellow]")

    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("\n[dim]Tip: Use 'echolake list-profiles' to see available profiles[/dim]")
        console.print("[dim]Tip: Use 'echolake list-destinations' to see available destinations[/dim]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


def _parse_source(source: str) -> tuple:
    """
    Parse source/destination string.

    Args:
        source: Source string (path, s3://bucket/path, gcs://bucket/path, etc.)

    Returns:
        Tuple of (type, path) where path includes bucket/prefix for cloud sources
    """
    if source.startswith("s3://"):
        return ("s3", source[5:])
    elif source.startswith("gs://") or source.startswith("gcs://"):
        prefix_len = 5 if source.startswith("gs://") else 6
        return ("gcs", source[prefix_len:])
    elif source.startswith("azure://") or source.startswith("wasb://"):
        prefix_len = 8 if source.startswith("azure://") else 7
        return ("azure", source[prefix_len:])
    else:
        return ("local", source)


def _split_cloud_path(cloud_path: str) -> tuple:
    """
    Split a cloud path into bucket and prefix.

    Args:
        cloud_path: Path like 'bucket-name/prefix/path'

    Returns:
        Tuple of (bucket, prefix)
    """
    parts = cloud_path.split("/", 1)
    bucket = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""
    return bucket, prefix


def _print_stats_tables(stats):
    """Print the detailed statistics tables."""
    from datetime import datetime
    from pathlib import Path

    summary = stats.summary()

    # Main statistics table
    table = Table(title="Echo Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Events Processed", str(summary['event_count']))
    table.add_row("Events Modified", str(summary['events_modified']))
    table.add_row("Errors", str(summary['errors']))

    if summary['duration_seconds']:
        table.add_row("Duration", f"{summary['duration_seconds']:.2f}s")

    console.print("\n")
    console.print(table)

    # Original timestamp range table
    if summary.get('original_earliest_time'):
        console.print()
        orig_table = Table(title="Original Timestamp Range")
        orig_table.add_column("Metric", style="cyan")
        orig_table.add_column("Value", style="yellow")

        earliest_dt = datetime.fromisoformat(summary['original_earliest_time'])
        latest_dt = datetime.fromisoformat(summary['original_latest_time'])

        orig_table.add_row("Earliest Time", earliest_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
        if summary.get('original_earliest_file'):
            orig_table.add_row("Earliest Found In", Path(summary['original_earliest_file']).name)
        orig_table.add_row("Latest Time", latest_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
        if summary.get('original_latest_file'):
            orig_table.add_row("Latest Found In", Path(summary['original_latest_file']).name)

        # Calculate span
        span = latest_dt - earliest_dt
        hours = span.total_seconds() / 3600
        orig_table.add_row("Time Span", f"{hours:.2f} hours")

        console.print(orig_table)

    # New timestamp range table
    if summary.get('new_earliest_time'):
        console.print()
        new_table = Table(title="Echoed Timestamp Range")
        new_table.add_column("Metric", style="cyan")
        new_table.add_column("Value", style="green")

        new_earliest_dt = datetime.fromisoformat(summary['new_earliest_time'])
        new_latest_dt = datetime.fromisoformat(summary['new_latest_time'])
        run_time_dt = datetime.fromisoformat(summary['run_time']) if summary.get('run_time') else None

        new_table.add_row("Earliest Time", new_earliest_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
        new_table.add_row("Latest Time", new_latest_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))

        # Calculate new span
        new_span = new_latest_dt - new_earliest_dt
        new_hours = new_span.total_seconds() / 3600
        new_table.add_row("Time Span", f"{new_hours:.2f} hours")

        # Always display run time (used to determine "events in future")
        if run_time_dt:
            new_table.add_row("Current Run Time", run_time_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
        else:
            new_table.add_row("Current Run Time", "N/A")

        if summary.get('delta_factor'):
            new_table.add_row("Delta Factor", f"{summary['delta_factor']}x")

        # Future events
        events_in_future = summary.get('events_in_future', 0)
        if events_in_future > 0:
            new_table.add_row("Events in Future", f"[red]{events_in_future}[/red]")
        else:
            new_table.add_row("Events in Future", f"[green]{events_in_future}[/green]")

        console.print(new_table)


def _print_stats(stats, show_timeline=False):
    """Print echo statistics."""
    _print_stats_tables(stats)

    # Optionally show timeline for completed echoes
    if show_timeline and stats.original_earliest_time and stats.new_earliest_time:
        # Note: In non-dry-run mode, we don't have histogram data since events aren't cached
        print_timeline(
            original_earliest=stats.original_earliest_time,
            original_latest=stats.original_latest_time,
            new_earliest=stats.new_earliest_time,
            new_latest=stats.new_latest_time,
            original_base=stats.original_base_time,
            new_base=stats.new_base_time,
            event_count=stats.event_count,
            events_by_bucket=None,  # No histogram in non-dry-run mode
            run_time=stats.run_time,
            delta_factor=stats.delta_factor or 1.0,
        )

    console.print("\n[green]✓[/green] Echo completed successfully!\n")


def _print_dry_run_results(stats, cfg, engine=None, show_timeline=False):
    """Print dry-run results with optional timeline visualization."""
    from datetime import datetime
    from pathlib import Path

    # Check if we have data to visualize
    if not stats.original_earliest_time or not stats.new_earliest_time:
        console.print("[yellow]No events found to visualize[/yellow]")
        return

    # Print the standard statistics tables first
    _print_stats_tables(stats)

    # Conditionally print timeline visualization
    if show_timeline:
        # Calculate histogram buckets from engine data
        events_by_bucket = None
        if engine and hasattr(engine, 'events_for_histogram') and engine.events_for_histogram:
            events_by_bucket = calculate_event_buckets(engine.events_for_histogram, num_buckets=12)

        # Print timeline visualization
        print_timeline(
            original_earliest=stats.original_earliest_time,
            original_latest=stats.original_latest_time,
            new_earliest=stats.new_earliest_time,
            new_latest=stats.new_latest_time,
            original_base=stats.original_base_time,
            new_base=stats.new_base_time,
            event_count=stats.event_count,
            events_by_bucket=events_by_bucket,
            run_time=stats.run_time,
            delta_factor=stats.delta_factor or 1.0,
        )

    # Print transformation summary
    print_transformation_summary(cfg, stats, dry_run=True)


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
