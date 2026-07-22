"""Core echo engine - orchestrates the echo process."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Optional
from pathlib import Path
import logging
import threading

from ..models.event import Event
from ..core.config import Config, EchoConfig, EchoStats
from ..core.timestamp import TimestampExtractor, TimestampManipulator
from ..core.interrupt_handler import setup_interrupt_handler
from ..core.raw_timestamp_shifter import shift_raw_timestamps
from ..inputs.sources import get_source
from ..inputs.formats import get_format
from ..inputs.schemas import get_schema
from ..outputs.destinations import get_destination
from ..outputs.formats import get_output_format

logger = logging.getLogger(__name__)


class EchoEngine:
    """
    Core echo engine that processes events from input to output.

    Orchestrates:
    1. Reading from input source
    2. Parsing with format handler
    3. Extracting events with schema handler
    4. Manipulating timestamps
    5. Writing to output destination
    """

    def __init__(self, config: Config, dry_run: bool = False, workers: int = 1):
        """
        Initialize echo engine.

        Args:
            config: Configuration object
            dry_run: If True, skip writing output (for preview/testing)
            workers: Number of concurrent file processing threads
        """
        # Track dataset info (must be set before resolving)
        self.resolved_dataset = None
        self.file_sourcetype_map: Dict[str, str] = {}  # symlink filename -> sourcetype

        # Resolve dataset if present
        if config.dataset:
            config = self._resolve_dataset_config(config)
            # Extract resolved dataset from config if present
            if hasattr(config, '_resolved_dataset'):
                self.resolved_dataset = config._resolved_dataset
                delattr(config, '_resolved_dataset')

        self.config = config
        self.dry_run = dry_run
        self.workers = max(1, workers)
        self.stats = EchoStats()
        self._stats_lock = threading.Lock()

        # Initialize components
        self.input_source = None
        self.input_format = None
        self.input_schema = None
        self.output_destination = None
        self.output_format = None
        self.timestamp_manipulator = None

        # For dry-run visualization
        self.events_for_histogram = []  # Stores (new_timestamps_tuple) for each event

    def setup(self):
        """Set up all components based on configuration."""
        if not self.config.input or not self.config.output:
            raise ValueError("Input and output configuration required")

        # Setup input
        input_cfg = self.config.input
        source_cfg = input_cfg.source

        source_kwargs = {}
        if source_cfg.type == 'local':
            source_kwargs = {
                'path': source_cfg.path,
                'pattern': source_cfg.pattern or '*',
            }
            # Add include_files if specified (for filtering large files)
            if source_cfg.include_files:
                source_kwargs['include_files'] = source_cfg.include_files
        elif source_cfg.type in ['s3', 'gcs']:
            source_kwargs = {
                'bucket': source_cfg.bucket,
                'prefix': source_cfg.prefix or '',
                'pattern': source_cfg.pattern or '*',
            }
        elif source_cfg.type == 'azure':
            source_kwargs = {
                'container': source_cfg.bucket,  # Using 'bucket' as container name
                'prefix': source_cfg.prefix or '',
                'pattern': source_cfg.pattern or '*',
            }

        self.input_source = get_source(source_cfg.type, **source_kwargs)
        self.input_format = get_format(input_cfg.format)

        # Only pass timestamp_patterns if there are patterns defined or schema is raw/None
        schema_kwargs = {}
        if input_cfg.timestamp_patterns or input_cfg.schema_type is None or input_cfg.schema_type == 'raw':
            schema_kwargs['timestamp_patterns'] = input_cfg.timestamp_patterns

        self.input_schema = get_schema(input_cfg.schema_type, **schema_kwargs)

        # Setup output
        output_cfg = self.config.output
        dest_cfg = output_cfg.destination

        dest_kwargs = {}
        if dest_cfg.type == 'local':
            dest_kwargs = {
                'path': dest_cfg.path,
                'path_template': dest_cfg.path_template,
                'compression': output_cfg.compression,
            }
        elif dest_cfg.type in ['s3', 'gcs']:
            dest_kwargs = {
                'bucket': dest_cfg.bucket,
                'path_template': dest_cfg.path_template,
                'compression': output_cfg.compression,
            }
        elif dest_cfg.type == 'azure':
            dest_kwargs = {
                'container': dest_cfg.bucket,
                'path_template': dest_cfg.path_template,
                'compression': output_cfg.compression,
            }
        elif dest_cfg.type in ('splunk_hec', 'hec'):
            import os
            # Force jsonl serialization so per-event fields survive to the
            # destination (it maps _raw/_time/host/source/sourcetype per event).
            output_cfg.format = 'jsonl'
            token = os.getenv(dest_cfg.hec_token_env, '')
            dest_kwargs = {
                'hec_url': dest_cfg.hec_url,
                'token': token,
                'index': dest_cfg.index,
                'verify_ssl': dest_cfg.verify_ssl,
                'use_raw_endpoint': dest_cfg.use_raw_endpoint,
                'default_host': dest_cfg.default_host,
                'source_override': dest_cfg.source_override,
                'sourcetype_override': dest_cfg.sourcetype_override,
                'time_field': dest_cfg.time_field,
                'raw_field': dest_cfg.raw_field,
                'host_field': dest_cfg.host_field,
                'source_field': dest_cfg.source_field,
                'sourcetype_field': dest_cfg.sourcetype_field,
                'batch_size': output_cfg.batch_size,
                'max_workers': dest_cfg.hec_max_workers,
                'dry_run': dest_cfg.hec_dry_run,
            }

        self.output_destination = get_destination(dest_cfg.type, **dest_kwargs)
        self.output_format = get_output_format(output_cfg.format)

        # Setup timestamp manipulator
        echo_cfg = self.config.echo
        self.timestamp_manipulator = TimestampManipulator(
            delta_factor=echo_cfg.delta_factor,
            base_time=echo_cfg.base_time,
            target_time=echo_cfg.target_time,
            prevent_future=echo_cfg.prevent_future,
            ceiling_time=echo_cfg.ceiling_time,
        )

    def run(self) -> EchoStats:
        """
        Run the echo process using two-pass approach.

        Phase 1: Read all files and extract events with timestamps
        Phase 2: Calculate consistent shift map and apply to all events

        Returns:
            EchoStats with operation statistics
        """
        self.stats.start_time = datetime.now(timezone.utc)
        self.stats.run_time = datetime.now(timezone.utc)  # Track run time for future event detection

        # Set up interrupt handler for immediate exit on Ctrl+C
        setup_interrupt_handler()

        try:
            self.setup()

            # Phase 1: Scan files to find timestamp range (or use pre-computed range from dataset metadata)
            file_list = list(self.input_source.list_files())

            # Check if dataset has timestamp range in metadata
            if self.resolved_dataset:
                try:
                    # ResolvedDataset has a manifest attribute
                    if hasattr(self.resolved_dataset, 'manifest'):
                        manifest = self.resolved_dataset.manifest
                        metadata = manifest.metadata

                        # timestamp_range is a Pydantic model field
                        if hasattr(metadata, 'timestamp_range') and metadata.timestamp_range:
                            from rich.console import Console
                            console = Console()
                            console.print("[green]✓ Using timestamp ranges from dataset metadata (skipping scan phase)[/green]")

                            ts_range = metadata.timestamp_range
                            from ..utils.time import parse_timestamp
                            self.stats.original_earliest_time = parse_timestamp(ts_range.earliest)
                            self.stats.original_latest_time = parse_timestamp(ts_range.latest)
                except Exception as e:
                    from rich.console import Console
                    Console().print(f"[yellow]⚠ Could not use timestamp metadata: {e}[/yellow]")

            # Passthrough mode: no timestamp changes, so no scan is needed.
            no_shift = self.config.echo.no_shift

            # If no timestamp range in metadata, scan files (skipped in passthrough)
            did_scan_phase = False
            if not no_shift and (not self.stats.original_earliest_time or not self.stats.original_latest_time):
                from rich.console import Console
                from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

                console = Console()
                console.print("\n[yellow]Phase 1: Scanning files for timestamp range...[/yellow]\n")
                did_scan_phase = True

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console
                ) as progress:
                    scan_task = progress.add_task("[cyan]Scanning files...", total=len(file_list))

                    for idx, file_id in enumerate(file_list, 1):
                        file_name = file_id.split('/')[-1][:50]  # Truncate long names
                        progress.update(scan_task, description=f"[cyan]Scanning (File {idx}/{len(file_list)}): {file_name}")
                        # Stream through file, track only min/max times
                        self._scan_file_for_timestamp_range(file_id)
                        progress.advance(scan_task)

                console.print("[green]✓ Scanning complete![/green]\n")

            # Calculate base time shifts (no timestamp list needed!)
            original_base = None
            new_base = None

            if self.stats.original_earliest_time and self.stats.original_latest_time:
                # Use earliest time as base
                original_base = self.stats.original_earliest_time
                max_delta = self.stats.original_latest_time - original_base

                # Calculate new base time
                initial_target = self.timestamp_manipulator._calculate_target_time()
                ceiling = self.timestamp_manipulator._calculate_ceiling_time()

                if self.timestamp_manipulator.prevent_future and ceiling:
                    # Calculate what the latest event time would be
                    max_new_delta = max_delta * self.timestamp_manipulator.delta_factor
                    projected_max = initial_target + max_new_delta

                    # If it would exceed ceiling, shift the base time back
                    if projected_max > ceiling:
                        new_base = ceiling - max_new_delta
                    else:
                        new_base = initial_target
                else:
                    new_base = initial_target

                self.stats.delta_factor = self.config.echo.delta_factor
                self.stats.new_base_time = new_base
                self.stats.original_base_time = original_base
                logger.info(f"Calculated time shifts: base {original_base} -> {new_base}")

            # Phase 2: Stream each file and process events individually (zero memory accumulation)
            if no_shift or (original_base and new_base):
                from rich.console import Console
                from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

                console = Console()
                phase_label = "Phase 2: " if did_scan_phase else ""
                console.print(f"\n[yellow]{phase_label}Processing and writing events...[/yellow]")
                if no_shift:
                    console.print("[dim]Passthrough: original timestamps, no scan.[/dim]\n")
                else:
                    console.print("[dim]Writing events with updated timestamps...[/dim]\n")

                # Calculate total bytes for accurate progress (not just file count)
                total_bytes = 0
                file_sizes = {}
                for file_id in file_list:
                    file_path = Path(file_id)
                    if file_path.exists():
                        size = file_path.stat().st_size
                        file_sizes[file_id] = size
                        total_bytes += size

                from rich.progress import TimeElapsedColumn
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("Overall: [progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("•"),
                    TextColumn("[cyan]{task.fields[events]:,} events"),
                    TextColumn("•"),
                    TextColumn("[yellow]{task.fields[rate]:.0f} events/sec"),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    process_task = progress.add_task(
                        "[green]Processing files...",
                        total=total_bytes,  # Track bytes, not file count
                        events=0,
                        rate=0.0
                    )

                    if self.workers > 1:
                        # Concurrent file processing
                        files_completed = [0]  # mutable counter for closure
                        def _process_file_task(file_id, idx):
                            file_size = file_sizes.get(file_id, 0)
                            self._stream_process_file(file_id, original_base, new_base, progress, process_task, file_size, no_shift=no_shift)
                            files_completed[0] += 1
                            file_name = file_id.split('/')[-1][:50]
                            progress.update(process_task, description=f"[green]Processing ({files_completed[0]}/{len(file_list)}): {file_name}")

                        with ThreadPoolExecutor(max_workers=self.workers) as executor:
                            futures = {
                                executor.submit(_process_file_task, file_id, idx): file_id
                                for idx, file_id in enumerate(file_list, 1)
                            }
                            for future in as_completed(futures):
                                exc = future.exception()
                                if exc:
                                    logger.error(f"File processing error: {exc}")
                                    self.stats.errors += 1
                    else:
                        # Sequential file processing (default)
                        for idx, file_id in enumerate(file_list, 1):
                            file_name = file_id.split('/')[-1][:50]
                            progress.update(process_task, description=f"[green]Processing (File {idx}/{len(file_list)}): {file_name}")
                            file_size = file_sizes.get(file_id, 0)
                            self._stream_process_file(file_id, original_base, new_base, progress, process_task, file_size, no_shift=no_shift)

                console.print("[green]✓ Processing complete![/green]\n")

        except KeyboardInterrupt:
            logger.warning("Echo interrupted by user")
            print("\n⚠️  Echo interrupted. Partial results may have been written.\n")
            raise
        except Exception as e:
            logger.error(f"Echo failed: {e}")
            self.stats.errors += 1
            raise
        finally:
            self.cleanup()
            self.stats.end_time = datetime.now(timezone.utc)

        return self.stats

    def _stream_process_file(self, file_id: str, original_base: datetime, new_base: datetime, progress=None, task_id=None, file_size_bytes=0, no_shift: bool = False):
        """
        Stream process a file - read events in small batches, apply shifts, write in batches.
        Uses minimal memory (only batch_size events at a time).
        Thread-safe: uses local counters, flushes to shared stats periodically.

        Args:
            file_id: File identifier
            original_base: Original base timestamp
            new_base: New base timestamp
            progress: Optional Progress object for live updates
            task_id: Optional task ID for progress updates
            file_size_bytes: Size of file in bytes for progress tracking
        """
        start_time = datetime.now(timezone.utc)
        UPDATE_INTERVAL = 1000  # Update every 1k events
        first_event = True

        # Track bytes written for progress updates
        bytes_written_in_file = 0

        delta_factor = self.timestamp_manipulator.delta_factor
        ceiling = self.timestamp_manipulator._calculate_ceiling_time()

        # Batch buffer (keeps only BATCH_SIZE events in memory at a time)
        BATCH_SIZE = 10000
        event_buffer = []

        # Look up sourcetype for this file
        file_name_for_lookup = Path(file_id).name
        sourcetype = self.file_sourcetype_map.get(file_name_for_lookup)
        write_metadata = {'sourcetype': sourcetype} if sourcetype else None

        # Get file content stream and parse (truly streaming - no full file load)
        content_stream = self.input_source.read_file(file_id)

        # Local counters (thread-safe — no shared state in hot loop)
        local_event_count = 0
        local_events_modified = 0
        local_errors = 0
        local_events_in_future = 0
        local_events_at_ceiling = 0
        local_new_earliest = None
        local_new_latest = None
        local_unflushed = 0  # events since last stats flush

        # Parse content stream (each format handles its own buffering)
        for raw_data in self.input_format.parse(content_stream):
            try:
                event = self.input_schema.extract_event(raw_data, self.config.input.format, sourcetype=sourcetype)
                local_event_count += 1
                local_unflushed += 1

                # Periodically flush local counters to shared stats
                if local_unflushed >= UPDATE_INTERVAL:
                    with self._stats_lock:
                        self.stats.event_count += local_unflushed
                        self.stats.events_modified += local_events_modified
                        self.stats.errors += local_errors
                        self.stats.events_in_future += local_events_in_future
                        self.stats.events_at_ceiling += local_events_at_ceiling
                        if local_new_earliest and (self.stats.new_earliest_time is None or local_new_earliest < self.stats.new_earliest_time):
                            self.stats.new_earliest_time = local_new_earliest
                        if local_new_latest and (self.stats.new_latest_time is None or local_new_latest > self.stats.new_latest_time):
                            self.stats.new_latest_time = local_new_latest
                    # Reset local delta counters (keep cumulative local_event_count)
                    local_events_modified = 0
                    local_errors = 0
                    local_events_in_future = 0
                    local_events_at_ceiling = 0
                    local_new_earliest = None
                    local_new_latest = None
                    local_unflushed = 0

                    # Update progress display
                    if progress and task_id is not None:
                        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                        rate = self.stats.event_count / elapsed if elapsed > 0 else 0
                        progress.update(task_id, events=self.stats.event_count, rate=rate)
                elif first_event and progress and task_id is not None:
                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    rate = self.stats.event_count / elapsed if elapsed > 0 else 0
                    progress.update(task_id, events=self.stats.event_count, rate=rate)
                    first_event = False

                # Passthrough (no_shift): leave every timestamp untouched and
                # skip the whole shift path (no base needed, so no scan phase).
                if not no_shift:
                    # Check if this is the base time file (for stats)
                    if not self.stats.original_base_time:
                        for field, ts in event.timestamps.items():
                            if ts == original_base:
                                with self._stats_lock:
                                    self.stats.original_base_time = original_base
                                    self.stats.original_base_file = file_id
                                break

                    # Apply timestamp shifts to this event
                    modified = False
                    for field, original_ts in event.timestamps.items():
                        original_delta = original_ts - original_base
                        new_delta = original_delta * delta_factor
                        new_ts = new_base + new_delta

                        # Apply ceiling if configured
                        if ceiling and new_ts > ceiling:
                            new_ts = ceiling
                            local_events_at_ceiling += 1

                        event.timestamps[field] = new_ts
                        modified = True

                        # Track new timestamp range (local)
                        if local_new_earliest is None or new_ts < local_new_earliest:
                            local_new_earliest = new_ts
                        if local_new_latest is None or new_ts > local_new_latest:
                            local_new_latest = new_ts

                        # Track future events
                        if ceiling and new_ts > self.stats.run_time:
                            local_events_in_future += 1

                    if modified:
                        local_events_modified += 1
                        # CRITICAL FIX: Update raw_data with new timestamps
                        event.raw_data = event._update_raw_data(event.timestamps)
                        # Shift timestamps embedded in _raw text (CSV exports)
                        if isinstance(event.raw_data, dict) and '_raw' in event.raw_data:
                            raw = event.raw_data['_raw']
                            if isinstance(raw, str) and raw:
                                event.raw_data['_raw'] = shift_raw_timestamps(
                                    raw, original_base, new_base, delta_factor, ceiling,
                                    sourcetype=sourcetype,
                                )

                # Add to buffer if not dry-run
                if not self.dry_run:
                    output_data = self.output_format.format_event(event)
                    event_buffer.append(output_data)

                    # Flush buffer when it reaches BATCH_SIZE
                    if len(event_buffer) >= BATCH_SIZE:
                        self.output_destination.write(file_id, event_buffer, metadata=write_metadata)
                        event_buffer = []  # Clear buffer

                        # Update overall progress incrementally
                        if progress and task_id is not None and file_size_bytes > 0:
                            bytes_to_advance = max(1, file_size_bytes // 1000)
                            bytes_to_advance = min(bytes_to_advance, file_size_bytes - bytes_written_in_file)
                            if bytes_to_advance > 0:
                                progress.advance(task_id, advance=bytes_to_advance)
                                bytes_written_in_file += bytes_to_advance

            except Exception as e:
                logger.warning(f"Failed to process event: {e}")
                local_errors += 1

        # Flush any remaining events in buffer
        if not self.dry_run and event_buffer:
            self.output_destination.write(file_id, event_buffer, metadata=write_metadata)

        # Flush remaining local counters to shared stats
        if local_unflushed > 0 or local_events_modified or local_errors:
            with self._stats_lock:
                self.stats.event_count += local_unflushed
                self.stats.events_modified += local_events_modified
                self.stats.errors += local_errors
                self.stats.events_in_future += local_events_in_future
                self.stats.events_at_ceiling += local_events_at_ceiling
                if local_new_earliest and (self.stats.new_earliest_time is None or local_new_earliest < self.stats.new_earliest_time):
                    self.stats.new_earliest_time = local_new_earliest
                if local_new_latest and (self.stats.new_latest_time is None or local_new_latest > self.stats.new_latest_time):
                    self.stats.new_latest_time = local_new_latest

        # Advance any remaining bytes for this file
        if progress and task_id is not None and file_size_bytes > 0:
            remaining_bytes = file_size_bytes - bytes_written_in_file
            if remaining_bytes > 0:
                progress.advance(task_id, advance=remaining_bytes)

        # Final progress update for this file (event rate)
        if progress and task_id is not None:
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            rate = self.stats.event_count / elapsed if elapsed > 0 else 0
            progress.update(task_id, events=self.stats.event_count, rate=rate)

    def _scan_file_for_timestamp_range(self, file_id: str):
        """
        Scan a file to find min/max timestamps (fully streaming - no memory accumulation).

        Args:
            file_id: File identifier from input source
        """
        # Look up sourcetype for this file
        file_name_for_lookup = Path(file_id).name
        sourcetype = self.file_sourcetype_map.get(file_name_for_lookup)

        # Get file content stream and parse (truly streaming)
        content_stream = self.input_source.read_file(file_id)

        # Parse content stream (don't load all into memory with list())
        for raw_data in self.input_format.parse(content_stream):
            try:
                event = self.input_schema.extract_event(raw_data, self.config.input.format, sourcetype=sourcetype)

                # Track only min/max timestamps, discard everything else
                for field, ts in event.timestamps.items():
                    if self.stats.original_earliest_time is None or ts < self.stats.original_earliest_time:
                        self.stats.original_earliest_time = ts
                        self.stats.original_earliest_file = file_id
                    if self.stats.original_latest_time is None or ts > self.stats.original_latest_time:
                        self.stats.original_latest_time = ts
                        self.stats.original_latest_file = file_id

                # Event is discarded here - not kept in memory

            except Exception as e:
                logger.warning(f"Error extracting timestamps from event: {e}")
                self.stats.errors += 1

    def _read_file(self, file_id: str) -> List[Event]:
        """
        Read and extract events from a single file (legacy method - loads all into memory).

        WARNING: This method loads all events into memory. Use streaming methods instead.

        Args:
            file_id: File identifier from input source

        Returns:
            List of extracted events
        """
        events: List[Event] = []

        # Look up sourcetype for this file
        file_name_for_lookup = Path(file_id).name
        sourcetype = self.file_sourcetype_map.get(file_name_for_lookup)

        # Get file content stream
        content_stream = self.input_source.read_file(file_id)

        # Parse content stream
        for raw_data in self.input_format.parse(content_stream):
            try:
                event = self.input_schema.extract_event(raw_data, self.config.input.format, sourcetype=sourcetype)
                events.append(event)
                self.stats.event_count += 1

                # Track original timestamp range
                for field, ts in event.timestamps.items():
                    # Track earliest
                    if self.stats.original_earliest_time is None or ts < self.stats.original_earliest_time:
                        self.stats.original_earliest_time = ts
                        self.stats.original_earliest_file = file_id
                    # Track latest
                    if self.stats.original_latest_time is None or ts > self.stats.original_latest_time:
                        self.stats.original_latest_time = ts
                        self.stats.original_latest_file = file_id

            except Exception as e:
                logger.warning(f"Failed to extract event: {e}")
                self.stats.errors += 1

        return events

    def _calculate_new_timestamps(self, file_id: str, events: List[Event], shift_map: Dict[str, timedelta]):
        """
        Calculate new timestamps for statistics (dry-run mode).

        Args:
            file_id: File identifier
            events: List of events
            shift_map: Shift map from calculate_shifts
        """
        try:
            # Apply shifts to events (but don't write)
            for event in events:
                modified_event = event.apply_timestamp_shifts(shift_map)
                if modified_event != event:
                    self.stats.events_modified += 1

                # Track new timestamp range and future events
                event_has_future_timestamp = False
                for field, new_ts in modified_event.timestamps.items():
                    # Track earliest new time
                    if self.stats.new_earliest_time is None or new_ts < self.stats.new_earliest_time:
                        self.stats.new_earliest_time = new_ts
                    # Track latest new time
                    if self.stats.new_latest_time is None or new_ts > self.stats.new_latest_time:
                        self.stats.new_latest_time = new_ts
                    # Check if any timestamp is significantly in future (> 1 second tolerance)
                    if self.stats.run_time:
                        time_diff = (new_ts - self.stats.run_time).total_seconds()
                        if time_diff > 1.0:  # More than 1 second in future
                            event_has_future_timestamp = True

                # Count event once if any of its timestamps are in the future
                if event_has_future_timestamp:
                    self.stats.events_in_future += 1

                # Collect timestamps for histogram (dry-run only)
                if self.dry_run and modified_event.timestamps:
                    self.events_for_histogram.append(tuple(modified_event.timestamps.values()))

        except Exception as e:
            logger.error(f"Failed to calculate new timestamps: {e}")
            self.stats.errors += 1

    def _apply_and_write(self, file_id: str, events: List[Event], shift_map: Dict[str, timedelta]):
        """
        Apply timestamp shifts to events and write to output.

        Args:
            file_id: File identifier
            events: List of events
            shift_map: Shift map from calculate_shifts
        """
        try:
            # Apply shifts to events
            modified_events = []
            for event in events:
                modified_event = event.apply_timestamp_shifts(shift_map)
                modified_events.append(modified_event)
                if modified_event != event:
                    self.stats.events_modified += 1

                # Track new timestamp range and future events
                event_has_future_timestamp = False
                for field, new_ts in modified_event.timestamps.items():
                    # Track earliest new time
                    if self.stats.new_earliest_time is None or new_ts < self.stats.new_earliest_time:
                        self.stats.new_earliest_time = new_ts
                    # Track latest new time
                    if self.stats.new_latest_time is None or new_ts > self.stats.new_latest_time:
                        self.stats.new_latest_time = new_ts
                    # Check if any timestamp is significantly in future (> 1 second tolerance)
                    if self.stats.run_time:
                        time_diff = (new_ts - self.stats.run_time).total_seconds()
                        if time_diff > 1.0:  # More than 1 second in future
                            event_has_future_timestamp = True

                # Count event once if any of its timestamps are in the future
                if event_has_future_timestamp:
                    self.stats.events_in_future += 1

            # Write to output
            self._write_events(file_id, modified_events)

        except Exception as e:
            logger.error(f"Failed to apply shifts: {e}")
            self.stats.errors += 1

    def _write_events(self, source_file_id: str, events: List[Event]):
        """
        Write events to output.

        Args:
            source_file_id: Source file identifier
            events: List of events to write
        """
        # Serialize events
        serialized_events = []
        for event in events:
            try:
                serialized = self.output_format.format_event(event)
                serialized_events.append(serialized)
            except Exception as e:
                logger.warning(f"Failed to serialize event: {e}")
                self.stats.errors += 1

        # Write to destination
        if serialized_events:
            try:
                self.output_destination.write(
                    source_file_id,
                    serialized_events,
                    batch_size=self.config.output.batch_size
                )
            except Exception as e:
                logger.error(f"Failed to write events: {e}")
                self.stats.errors += 1

    def cleanup(self):
        """Clean up resources."""
        if self.input_source:
            self.input_source.close()
        if self.output_destination:
            self.output_destination.close()

    def _resolve_dataset_config(self, config: Config) -> Config:
        """
        Resolve dataset and merge with configuration.

        Args:
            config: Original configuration with dataset field

        Returns:
            Config with dataset defaults merged

        Raises:
            ValueError: If dataset cannot be resolved
        """
        from ..datasets.resolver import DatasetResolver
        from ..datasets.models import ResolvedDataset

        # Create resolver
        resolver = DatasetResolver()

        # Build dataset reference
        dataset_ref = config.dataset.ref
        if config.dataset.version:
            dataset_ref = f"{dataset_ref}@{config.dataset.version}"

        # Resolve dataset
        logger.info(f"Resolving dataset: {dataset_ref}")
        resolved = resolver.resolve(dataset_ref)

        # Get merged defaults from dataset and dependencies
        dataset_defaults = resolved.get_merged_defaults()

        # Get user config (excluding dataset)
        user_config_dict = config.model_dump(exclude_unset=True, exclude={'dataset'})

        # Apply overrides from config if present (overrides go on top of user config)
        if config.dataset.overrides:
            user_config_dict = self._deep_merge(user_config_dict, config.dataset.overrides)

        # Merge dataset defaults with user config (including overrides)
        # Priority: User config + Overrides > Dataset defaults
        merged_config_dict = self._deep_merge(dataset_defaults, user_config_dict)

        # Create input config from dataset if not already specified
        # Also handle the case where dataset defaults provide partial input config
        # (e.g., format and timestamp_patterns) but no source
        if not merged_config_dict.get('input') or not merged_config_dict.get('input', {}).get('source'):
            # Download and cache file references
            from ..datasets.cache import DatasetCache
            cache = DatasetCache()

            cached_file_paths = []

            # Get bundled files
            bundled_files = resolved.get_all_bundled_files()
            cached_file_paths.extend(bundled_files)

            # Track which sourcetypes are covered by bundled files
            bundled_sourcetypes = set()
            for bf in resolved.manifest.files.bundled:
                if hasattr(bf, 'sourcetype') and bf.sourcetype:
                    bundled_sourcetypes.add(bf.sourcetype)

            # Download and cache file references (only for sourcetypes not covered by bundled files)
            file_references = resolved.get_all_file_references()
            uri_to_cached = {}  # Map URI -> cached Path for sourcetype mapping
            for file_ref in file_references:
                # Skip references for sourcetypes already covered by bundled files
                if hasattr(file_ref, 'sourcetype') and file_ref.sourcetype in bundled_sourcetypes:
                    continue
                try:
                    cached_path = cache.download_file_reference(
                        uri=file_ref.uri,
                        checksum=file_ref.checksum,
                        timeout=120,  # 2 minute timeout for large files
                    )
                    cached_file_paths.append(cached_path)
                    uri_to_cached[file_ref.uri] = cached_path
                except Exception as e:
                    # Log warning but continue with other files
                    print(f"Warning: Failed to download file reference {file_ref.uri}: {e}")

            if cached_file_paths:
                # Create input config using cached files
                from ..core.config import InputConfig, InputSourceConfig

                # Determine input strategy based on file types
                # For now, use a temporary directory approach
                import tempfile
                import shutil

                # Create temporary directory with symlinks to all cached files
                temp_dir = Path(tempfile.mkdtemp(prefix="echolake_dataset_"))

                for i, file_path in enumerate(cached_file_paths):
                    # Create symlink or copy file
                    link_name = temp_dir / file_path.name
                    if link_name.exists():
                        # Handle duplicate names
                        link_name = temp_dir / f"{i}_{file_path.name}"

                    try:
                        link_name.symlink_to(file_path)
                    except (OSError, NotImplementedError):
                        # Fallback to copy if symlinks not supported
                        shutil.copy2(file_path, link_name)

                # Build file-to-sourcetype mapping from dataset files
                for bf in resolved.manifest.files.bundled:
                    if hasattr(bf, 'sourcetype') and bf.sourcetype:
                        self.file_sourcetype_map[Path(bf.path).name] = bf.sourcetype
                for fr in resolved.manifest.files.references:
                    if hasattr(fr, 'sourcetype') and fr.sourcetype:
                        # Map the cached filename (with hash prefix) to sourcetype
                        cached_path = uri_to_cached.get(fr.uri)
                        if cached_path:
                            self.file_sourcetype_map[cached_path.name] = fr.sourcetype
                # Also check dependencies
                if resolved.resolved_dependencies:
                    for dep in resolved.resolved_dependencies:
                        for bf in dep.manifest.files.bundled:
                            if hasattr(bf, 'sourcetype') and bf.sourcetype:
                                self.file_sourcetype_map[Path(bf.path).name] = bf.sourcetype
                        for fr in dep.manifest.files.references:
                            if hasattr(fr, 'sourcetype') and fr.sourcetype:
                                cached_path = uri_to_cached.get(fr.uri)
                                if cached_path:
                                    self.file_sourcetype_map[cached_path.name] = fr.sourcetype

                # Determine format from dataset files or defaults
                # Priority: dataset defaults > bundled file format > file reference format > 'text'
                input_format = dataset_defaults.get('format')

                # If no default, check bundled files for format
                if not input_format:
                    bundled_files = resolved.manifest.files.bundled if resolved.manifest.files.bundled else []
                    if bundled_files and hasattr(bundled_files[0], 'format') and bundled_files[0].format:
                        input_format = bundled_files[0].format

                # If still no format, check file references
                if not input_format and file_references:
                    input_format = file_references[0].format

                # Final fallback to text
                if not input_format:
                    input_format = 'auto'  # Auto-detect format per line

                input_config = {
                    'source': {
                        'type': 'local',
                        'path': str(temp_dir),
                        'pattern': '**/*',  # Match all files
                    },
                    'format': input_format,
                }

                # Only add schema if present
                if dataset_defaults.get('schema_type'):
                    input_config['schema'] = dataset_defaults.get('schema_type')

                # Merge with any existing input config (e.g., dataset defaults with format/timestamp_patterns)
                existing_input = merged_config_dict.get('input', {})
                merged_config_dict['input'] = self._deep_merge(existing_input, input_config)
                merged_config_dict['_temp_dir'] = str(temp_dir)  # Track for cleanup

        # Create new config from merged dict
        new_config = Config(**merged_config_dict)

        # Store resolved dataset separately (not on config)
        # We'll access it via self.resolved_dataset in __init__
        # For now, create a temporary attribute to pass it through
        new_config._resolved_dataset = resolved

        return new_config

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = EchoEngine._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
