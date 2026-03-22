"""Change map algorithm for applying timestamp transformations to text/JSON."""

from typing import Dict, List, Tuple, Union
import json


class ChangeMap:
    """
    Manage and apply changes to text content with conflict detection.

    Uses right-to-left application to maintain position accuracy and
    deduplication to handle multiple occurrences of the same value.
    """

    def __init__(self):
        """Initialize empty change map."""
        self.changes: List[Tuple[int, int, str, str]] = []  # (start, end, old_val, new_val)

    def add_change(self, text: str, old_value: str, new_value: str) -> int:
        """
        Add a change to the map.

        Args:
            text: Full text to search in
            old_value: Value to replace
            new_value: Replacement value

        Returns:
            Number of changes added
        """
        count = 0
        start = 0

        while True:
            pos = text.find(old_value, start)
            if pos == -1:
                break

            end = pos + len(old_value)
            self.changes.append((pos, end, old_value, new_value))
            count += 1
            start = end

        return count

    def apply(self, text: str) -> str:
        """
        Apply all changes to text using right-to-left algorithm.

        Args:
            text: Original text

        Returns:
            Modified text
        """
        if not self.changes:
            return text

        # Sort by position (right to left) and deduplicate
        sorted_changes = self._sort_and_deduplicate()

        # Apply changes right to left
        result = text
        for start, end, old_val, new_val in sorted_changes:
            # Verify the old value is still at this position
            if result[start:end] == old_val:
                result = result[:start] + new_val + result[end:]

        return result

    def _sort_and_deduplicate(self) -> List[Tuple[int, int, str, str]]:
        """
        Sort changes by position (descending) and deduplicate.

        Returns:
            Deduplicated and sorted change list
        """
        # Sort by start position in descending order (right to left)
        sorted_changes = sorted(self.changes, key=lambda x: x[0], reverse=True)

        # Deduplicate by position
        seen_positions = set()
        deduplicated = []

        for change in sorted_changes:
            start = change[0]
            if start not in seen_positions:
                seen_positions.add(start)
                deduplicated.append(change)

        return deduplicated

    def detect_conflicts(self) -> List[str]:
        """
        Detect overlapping changes.

        Returns:
            List of conflict descriptions
        """
        conflicts = []
        sorted_changes = sorted(self.changes, key=lambda x: x[0])

        for i in range(len(sorted_changes) - 1):
            current_start, current_end, _, _ = sorted_changes[i]
            next_start, next_end, _, _ = sorted_changes[i + 1]

            if next_start < current_end:
                conflicts.append(
                    f"Overlap detected: positions {current_start}-{current_end} "
                    f"and {next_start}-{next_end}"
                )

        return conflicts

    def clear(self):
        """Clear all changes."""
        self.changes = []

    def __len__(self) -> int:
        """Return number of changes."""
        return len(self.changes)


class JSONChangeMap:
    """
    Change map specialized for JSON/JSONL data.

    Handles nested field updates while preserving JSON structure.
    """

    def __init__(self):
        """Initialize JSON change map."""
        self.field_changes: Dict[str, Dict[str, str]] = {}  # {field_path: {old: new}}

    def add_field_change(self, field_path: str, old_value: str, new_value: str):
        """
        Add a field change.

        Args:
            field_path: Dot-notation field path (e.g., '_event_time' or 'metadata.timestamp')
            old_value: Old value as string
            new_value: New value as string
        """
        if field_path not in self.field_changes:
            self.field_changes[field_path] = {}

        self.field_changes[field_path][old_value] = new_value

    def apply_to_dict(self, data: dict) -> dict:
        """
        Apply changes to a dictionary.

        Args:
            data: Original dictionary

        Returns:
            Modified dictionary (new instance)
        """
        result = data.copy()

        for field_path, value_map in self.field_changes.items():
            self._update_nested_field(result, field_path, value_map)

        return result

    def apply_to_json_line(self, json_line: str) -> str:
        """
        Apply changes to a JSON line.

        Args:
            json_line: JSON string

        Returns:
            Modified JSON string
        """
        try:
            data = json.loads(json_line)
            modified = self.apply_to_dict(data)
            return json.dumps(modified, separators=(',', ':'))
        except json.JSONDecodeError:
            return json_line

    def _update_nested_field(self, data: dict, field_path: str, value_map: Dict[str, str]):
        """
        Update a nested field in dictionary.

        Args:
            data: Dictionary to update (modified in place)
            field_path: Dot-notation path
            value_map: Map of old values to new values
        """
        parts = field_path.split('.')
        current = data

        # Navigate to parent
        for part in parts[:-1]:
            if part not in current:
                return
            current = current[part]
            if not isinstance(current, dict):
                return

        # Update final field
        final_key = parts[-1]
        if final_key in current:
            old_val = str(current[final_key])
            if old_val in value_map:
                # Preserve type if possible
                new_val = value_map[old_val]
                if isinstance(current[final_key], int):
                    try:
                        current[final_key] = int(new_val)
                    except ValueError:
                        current[final_key] = new_val
                elif isinstance(current[final_key], float):
                    try:
                        current[final_key] = float(new_val)
                    except ValueError:
                        current[final_key] = new_val
                else:
                    current[final_key] = new_val

    def clear(self):
        """Clear all changes."""
        self.field_changes.clear()

    def __len__(self) -> int:
        """Return number of field paths with changes."""
        return len(self.field_changes)
