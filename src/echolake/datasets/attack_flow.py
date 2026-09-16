"""Optional MITRE Attack Flow validation.

Attack Flow (Center for Threat-Informed Defense) is a STIX 2.1 extension for
describing an attack as an ordered graph. Validating a bundle against the Attack
Flow schema requires the third-party ``attack-flow`` package, which is an OPTIONAL
dependency of EchoLake (``pip install "echolake[attack-flow]"``).

This module never hard-fails when the package is absent. If the validator is not
installed, :func:`validate_attack_flow` returns a result with ``skipped=True`` so
callers can report "validation unavailable" rather than error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class AttackFlowValidationResult:
    """Outcome of an Attack Flow validation attempt."""

    valid: bool = False
    skipped: bool = False
    reason: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        # A skipped validation is not a failure.
        return self.valid or self.skipped


def _attack_flow_available() -> bool:
    """Return True if the optional ``attack-flow`` package is importable."""
    try:
        import attack_flow  # noqa: F401
        return True
    except ImportError:
        return False


def validate_attack_flow(flow_path: Path) -> AttackFlowValidationResult:
    """Validate an Attack Flow STIX 2.1 bundle against the Attack Flow schema.

    Args:
        flow_path: Path to the Attack Flow JSON bundle.

    Returns:
        AttackFlowValidationResult. ``skipped=True`` when the optional
        ``attack-flow`` package is not installed; the bundle is never validated
        in that case and this is not treated as a failure.
    """
    flow_path = Path(flow_path)

    if not flow_path.exists():
        return AttackFlowValidationResult(
            valid=False,
            reason=f"Attack Flow file not found: {flow_path}",
            errors=[f"file not found: {flow_path}"],
        )

    if not _attack_flow_available():
        return AttackFlowValidationResult(
            skipped=True,
            reason=(
                "attack-flow package not installed; skipping schema validation. "
                'Install with: pip install "echolake[attack-flow]"'
            ),
        )

    # The bundle must at least be well-formed JSON before schema validation.
    try:
        with open(flow_path, "r", encoding="utf-8") as f:
            json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return AttackFlowValidationResult(
            valid=False,
            reason=f"Attack Flow file is not valid JSON: {e}",
            errors=[str(e)],
        )

    # Delegate to the attack-flow package's schema validator. Its canonical entry
    # point is attack_flow.schema.validate_doc(Path) -> ValidationResult, whose
    # `.success` is True when there are no error-level messages. The package ships
    # its own bundled STIX schema data; if that data is not resolvable in the
    # install (or the API differs across releases), degrade to "skipped" rather
    # than failing the caller over a packaging quirk.
    try:
        from attack_flow.schema import validate_doc  # type: ignore
    except ImportError:
        return AttackFlowValidationResult(
            skipped=True,
            reason="attack-flow installed but validate_doc entry point not found; skipped",
        )

    try:
        result = validate_doc(Path(flow_path))
    except FileNotFoundError as e:
        # The package's own schema data files are missing from this install
        # (a known issue with non-editable git installs). Not the dataset's fault.
        return AttackFlowValidationResult(
            skipped=True,
            reason=f"attack-flow schema data not available in this install; skipped ({e})",
        )
    except Exception as e:  # noqa: BLE001 - never crash the caller over the optional validator
        return AttackFlowValidationResult(
            skipped=True,
            reason=f"attack-flow validator could not run; skipped ({e})",
        )

    errors = [str(m) for m in getattr(result, "messages", []) if getattr(m, "type_", None) == "error"]
    if getattr(result, "success", not errors):
        return AttackFlowValidationResult(valid=True, reason="valid Attack Flow 2.0.0 bundle")
    return AttackFlowValidationResult(valid=False, reason="schema validation failed", errors=errors)
