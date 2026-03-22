"""Visualization utilities for CLI output."""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

console = Console()


def print_timeline(
    original_earliest: datetime,
    original_latest: datetime,
    new_earliest: datetime,
    new_latest: datetime,
    original_base: Optional[datetime] = None,
    new_base: Optional[datetime] = None,
    event_count: int = 0,
    events_by_bucket: Optional[Dict[datetime, int]] = None,
    run_time: Optional[datetime] = None,
    delta_factor: float = 1.0,
):
    """
    Print a horizontal timeline visualization showing event distribution.

    Args:
        original_earliest: Earliest timestamp from original data
        original_latest: Latest timestamp from original data
        new_earliest: Earliest timestamp after echo
        new_latest: Latest timestamp after echo
        original_base: Original base time used for calculations
        new_base: New base time (target time)
        event_count: Total number of events
        events_by_bucket: Optional histogram data {bucket_time: event_count}
        run_time: Current time for reference
        delta_factor: Time delta multiplication factor
    """

    # Calculate spans
    original_span = original_latest - original_earliest
    new_span = new_latest - new_earliest

    original_hours = original_span.total_seconds() / 3600
    new_hours = new_span.total_seconds() / 3600

    # Original Timeline
    console.print()
    console.print(Panel(
        _build_timeline_text(
            earliest=original_earliest,
            latest=original_latest,
            base=original_base,
            span_hours=original_hours,
            title="ORIGINAL",
            events_by_bucket=None,  # Don't show histogram for original
        ),
        title="[bold cyan]Original Timeline[/bold cyan]",
        border_style="cyan"
    ))

    # Replayed Timeline
    console.print()
    console.print(Panel(
        _build_timeline_text(
            earliest=new_earliest,
            latest=new_latest,
            base=new_base,
            span_hours=new_hours,
            title="REPLAYED",
            events_by_bucket=events_by_bucket,
            run_time=run_time,
            delta_factor=delta_factor,
        ),
        title="[bold green]Replayed Timeline[/bold green]",
        border_style="green"
    ))


def _build_timeline_text(
    earliest: datetime,
    latest: datetime,
    base: Optional[datetime],
    span_hours: float,
    title: str,
    events_by_bucket: Optional[Dict[datetime, int]] = None,
    run_time: Optional[datetime] = None,
    delta_factor: Optional[float] = None,
) -> Text:
    """Build the text for a timeline display."""

    text = Text()

    # Timeline bar (60 chars wide)
    timeline_width = 60
    text.append("├" + "─" * timeline_width + "┤\n", style="dim")

    # Check if base is close to earliest or latest (within 1 minute)
    base_is_earliest = base and abs((base - earliest).total_seconds()) < 60
    base_is_latest = base and abs((base - latest).total_seconds()) < 60
    total_span = (latest - earliest).total_seconds()

    # Calculate base position if needed
    base_pos = 0
    if base and not base_is_earliest and not base_is_latest and total_span > 0:
        base_offset = (base - earliest).total_seconds()
        base_pos = int((base_offset / total_span) * (timeline_width - 30))
        base_pos = max(1, min(base_pos, timeline_width - 20))

    # Position markers
    text.append("│  ", style="dim")

    if base_is_earliest:
        # Base == Earliest, show combined marker
        text.append("[EARLIEST/BASE]", style="yellow bold")
        remaining = timeline_width - 16  # 16 for EARLIEST/BASE
        text.append(" " * remaining)
        text.append("[LATEST]", style="magenta bold")
    elif base_is_latest:
        # Base == Latest, show earliest, then latest/base
        text.append("[EARLIEST]", style="yellow bold")
        remaining = timeline_width - 10 - 12  # 10 for EARLIEST, 12 for LATEST/BASE
        remaining = max(0, remaining)
        text.append(" " * remaining)
        text.append("[LATEST/BASE]", style="magenta bold")
    else:
        # Show all three markers if base is different
        text.append("[EARLIEST]", style="yellow bold")

        if base:
            text.append(" " * base_pos)
            text.append("[BASE]", style="cyan bold")
            remaining = timeline_width - 10 - base_pos - 6  # EARLIEST + BASE + spaces
        else:
            remaining = timeline_width - 10

        remaining = max(0, remaining)
        text.append(" " * remaining)
        text.append("[LATEST]", style="magenta bold")

    text.append("  │\n", style="dim")

    # Times - align with markers above
    text.append("│  ", style="dim")
    text.append(f"{earliest.strftime('%Y-%m-%d %H:%M UTC')}", style="yellow")

    # Show base time if distinct from earliest and latest
    if base and not base_is_earliest and not base_is_latest:
        spaces = max(1, base_pos - 5)
        text.append(" " * spaces)
        text.append(f"{base.strftime('%H:%M UTC')}", style="cyan")
        remaining_spaces = max(1, timeline_width - 40 - base_pos)
        text.append(" " * remaining_spaces)
    else:
        spaces_before_latest = max(1, timeline_width - 40)
        text.append(" " * spaces_before_latest)

    text.append(f"{latest.strftime('%H:%M UTC')}", style="magenta")
    text.append("  │\n", style="dim")

    # Span info
    text.append("│", style="dim")
    text.append(f"  Time Span: {span_hours:.2f} hours", style="bright_white")
    if delta_factor and delta_factor != 1.0:
        text.append(f" ({delta_factor}x)", style="bright_blue")
    text.append(" " * (timeline_width - 30))
    text.append("│\n", style="dim")

    # Histogram if provided
    if events_by_bucket:
        text.append("│\n", style="dim")
        text.append("│  ", style="dim")
        text.append("Event Distribution:", style="bright_white underline")
        text.append("\n")

        histogram_text = _build_histogram(events_by_bucket, width=timeline_width - 4)
        for line in histogram_text.split('\n'):
            if line:
                text.append("│  ", style="dim")
                text.append(line)
                text.append("\n")

    # Current time marker for replayed timeline
    if run_time:
        text.append("│\n", style="dim")
        text.append("│  ", style="dim")
        text.append(f"Current Time: {run_time.strftime('%Y-%m-%d %H:%M:%S UTC')}", style="bright_cyan")
        text.append("\n")

    text.append("└" + "─" * timeline_width + "┘", style="dim")

    return text


def _build_histogram(
    events_by_bucket: Dict[datetime, int],
    width: int = 56,
    height: int = 8,
) -> str:
    """
    Build an ASCII histogram of event distribution.

    Args:
        events_by_bucket: Dictionary mapping time buckets to event counts
        width: Width of histogram in characters
        height: Height of histogram in bars

    Returns:
        String representation of histogram
    """
    if not events_by_bucket:
        return ""

    # Sort buckets
    sorted_buckets = sorted(events_by_bucket.items())

    # Find max count for scaling
    max_count = max(events_by_bucket.values())
    if max_count == 0:
        return ""

    # Build histogram
    lines = []

    # Determine bar width (at least 1 char per bucket)
    num_buckets = len(sorted_buckets)
    bar_width = max(1, width // num_buckets)

    # Scale counts to height
    scaled_counts = []
    for bucket_time, count in sorted_buckets:
        scaled = int((count / max_count) * height)
        scaled_counts.append((bucket_time, count, scaled))

    # Draw histogram bars
    bar_line = ""
    for bucket_time, count, scaled in scaled_counts:
        if count > 0:
            # Use different characters for different heights
            if scaled == 0:
                bar = "░"
            elif scaled < height // 3:
                bar = "▂"
            elif scaled < 2 * height // 3:
                bar = "▄"
            else:
                bar = "█"
            bar_line += bar * bar_width
        else:
            bar_line += " " * bar_width

    # Truncate to width
    bar_line = bar_line[:width]
    lines.append(bar_line)

    # Add time labels below (show first, middle, last)
    if len(sorted_buckets) >= 3:
        first_time = sorted_buckets[0][0]
        middle_time = sorted_buckets[len(sorted_buckets) // 2][0]
        last_time = sorted_buckets[-1][0]

        time_label = (
            f"{first_time.strftime('%H:%M UTC')}"
            + " " * (width // 3 - 9)
            + f"{middle_time.strftime('%H:%M UTC')}"
            + " " * (width // 3 - 9)
            + f"{last_time.strftime('%H:%M UTC')}"
        )
        lines.append(time_label[:width])

    return "\n".join(lines)


def calculate_event_buckets(
    events_with_timestamps: List[Tuple[datetime, ...]],
    num_buckets: int = 10,
) -> Dict[datetime, int]:
    """
    Group events into time buckets for histogram display.

    Args:
        events_with_timestamps: List of tuples containing event timestamps
        num_buckets: Number of buckets to create

    Returns:
        Dictionary mapping bucket start time to event count
    """
    if not events_with_timestamps:
        return {}

    # Flatten all timestamps
    all_timestamps = []
    for ts_tuple in events_with_timestamps:
        all_timestamps.extend(ts_tuple)

    if not all_timestamps:
        return {}

    # Find range
    earliest = min(all_timestamps)
    latest = max(all_timestamps)

    span = (latest - earliest).total_seconds()
    if span == 0:
        # All events at same time
        return {earliest: len(events_with_timestamps)}

    # Calculate bucket size
    bucket_size = span / num_buckets

    # Initialize buckets
    buckets = {}
    for i in range(num_buckets):
        bucket_start = earliest + timedelta(seconds=i * bucket_size)
        buckets[bucket_start] = 0

    # Count events in each bucket
    for ts in all_timestamps:
        # Find which bucket this timestamp belongs to
        bucket_index = int((ts - earliest).total_seconds() / bucket_size)
        bucket_index = min(bucket_index, num_buckets - 1)  # Cap at last bucket

        bucket_start = earliest + timedelta(seconds=bucket_index * bucket_size)
        buckets[bucket_start] += 1

    return buckets


def print_file_breakdown(
    files_info: List[Dict],
    show_ranges: bool = True,
):
    """
    Print a table showing per-file statistics.

    Args:
        files_info: List of dicts with file information
        show_ranges: Whether to show timestamp ranges
    """
    if not files_info:
        return

    console.print()
    table = Table(title="Files to be Processed")
    table.add_column("File", style="cyan")
    table.add_column("Events", style="magenta", justify="right")

    if show_ranges:
        table.add_column("Original Range", style="yellow")
        table.add_column("Replayed Range", style="green")

    for file_info in files_info:
        row = [
            file_info.get('filename', 'unknown'),
            str(file_info.get('event_count', 0)),
        ]

        if show_ranges:
            orig_start = file_info.get('original_start')
            orig_end = file_info.get('original_end')
            new_start = file_info.get('new_start')
            new_end = file_info.get('new_end')

            if orig_start and orig_end:
                row.append(f"{orig_start.strftime('%H:%M UTC')} - {orig_end.strftime('%H:%M UTC')}")
            else:
                row.append("N/A")

            if new_start and new_end:
                row.append(f"{new_start.strftime('%H:%M UTC')} - {new_end.strftime('%H:%M UTC')}")
            else:
                row.append("N/A")

        table.add_row(*row)

    console.print(table)


def print_transformation_summary(
    config,
    stats,
    dry_run: bool = True,
):
    """
    Print summary of what transformations will be/were applied.

    Args:
        config: Configuration object
        stats: EchoStats object
        dry_run: Whether this is a dry run
    """
    console.print()

    summary = Text()
    summary.append("Transformation Configuration:\n", style="bold bright_white")
    summary.append(f"  Base Time: ", style="bright_white")
    summary.append(f"{config.echo.base_time}", style="cyan")

    if stats.original_base_time:
        summary.append(f" → {stats.original_base_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="dim")
    else:
        summary.append("\n")

    summary.append(f"  Target Time: ", style="bright_white")
    summary.append(f"{config.echo.target_time}", style="cyan")

    if stats.new_base_time:
        summary.append(f" → {stats.new_base_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="dim")
    else:
        summary.append("\n")

    summary.append(f"  Delta Factor: ", style="bright_white")
    summary.append(f"{config.echo.delta_factor}x\n", style="cyan")

    summary.append(f"  Prevent Future: ", style="bright_white")
    summary.append(f"{config.echo.prevent_future}\n", style="cyan")

    if config.echo.ceiling_time:
        summary.append(f"  Ceiling Time: ", style="bright_white")
        summary.append(f"{config.echo.ceiling_time}\n", style="cyan")

    console.print(Panel(summary, border_style="blue"))

    # What would happen
    console.print()
    if dry_run:
        action_text = Text()
        action_text.append("What would happen:\n", style="bold yellow")
        action_text.append(f"  ✓ {stats.event_count} events would be read from {len(set([stats.original_earliest_file, stats.original_latest_file]))} file(s)\n", style="green")
        action_text.append(f"  ✓ All timestamps would be shifted\n", style="green")

        if stats.original_earliest_time and stats.original_latest_time:
            orig_span = (stats.original_latest_time - stats.original_earliest_time).total_seconds() / 3600
            new_span = (stats.new_latest_time - stats.new_earliest_time).total_seconds() / 3600 if stats.new_latest_time and stats.new_earliest_time else 0
            action_text.append(f"  ✓ Original span of {orig_span:.2f}h would become {new_span:.2f}h\n", style="green")

        # Check if ceiling was applied
        ceiling_applied = config.echo.prevent_future and stats.new_latest_time and stats.run_time
        ceiling_hit = False
        if ceiling_applied:
            # Check if the latest new time is very close to run_time (within 2 seconds)
            # This indicates ceiling was actually applied
            time_to_ceiling = (stats.run_time - stats.new_latest_time).total_seconds()
            ceiling_hit = abs(time_to_ceiling) < 2.0

        if stats.events_in_future > 0:
            if config.echo.prevent_future:
                action_text.append(f"  ⚠ {stats.events_in_future} events would exceed ceiling (capped to {config.echo.ceiling_time})\n", style="yellow")
            else:
                action_text.append(f"  ⚠ {stats.events_in_future} events would be in the future (allowed)\n", style="yellow")
        elif ceiling_hit:
            # Ceiling was applied but no events ended up in future after capping
            action_text.append(f"  ⚠ Events were capped at ceiling time ({config.echo.ceiling_time})\n", style="yellow")
            if stats.original_latest_time and stats.new_latest_time:
                # Show the impact
                action_text.append(f"  ℹ Latest event capped from intended time to ceiling\n", style="blue")
        else:
            action_text.append(f"  ✓ 0 events would be in the future\n", style="green")

        # Show how many events would actually be written
        events_to_write = stats.event_count
        if ceiling_hit or (stats.events_in_future > 0 and config.echo.prevent_future):
            action_text.append(f"  ✓ All {events_to_write} events would be written (with ceiling adjustments)\n", style="green")
        else:
            action_text.append(f"  ✓ All {events_to_write} events would be written\n", style="green")

        if config.output:
            dest = config.output.destination
            output_path = dest.path or dest.bucket
            action_text.append(f"  ✓ Output would be written to: {output_path}\n", style="green")

        console.print(Panel(action_text, title="[bold yellow]Dry Run Summary[/bold yellow]", border_style="yellow"))
    else:
        console.print("[green]✓[/green] Echo completed successfully!\n")
