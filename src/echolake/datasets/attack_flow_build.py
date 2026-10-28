"""Build a MITRE Attack Flow bundle from a dataset manifest.

The manifest's ``entities``, ``observables``, and ``kill_chain`` blocks are the
single source of truth; this module derives the Attack Flow (a STIX 2.1 bundle
carrying the Attack Flow 2.0.0 extension) from them so the flow never drifts
from the manifest.

Mapping, in STIX 2.1 vocabulary:

- entities -> STIX objects (``infrastructure``, ``identity``, ``threat-actor``,
  ``tool``, ``malware``, or the ``user-account`` observable), each exposed to the
  flow through an ``attack-asset`` whose ``object_ref`` points at it. An
  infrastructure's listed observables are linked with ``consists-of``.
- observables -> STIX cyber-observable objects with the spec's deterministic
  ids (so the same IP or hash gets the same id in every dataset). When an
  observable carries ``indicator_types`` it also gets a STIX ``indicator`` with
  a pattern over the observable, ATT&CK kill-chain phases, and confidence,
  linked ``based-on`` the observable and ``indicates`` the entities it belongs to.
- kill_chain -> one ``attack-action`` per technique per stage, chained with
  ``effect_refs``, carrying ``execution_start``/``execution_end``, ``asset_refs``
  to the stage's entities, and ``related-to`` relationships from the stage's
  observables, which is how the official Attack Flow corpus attaches evidence.

Identifiers are deterministic: shared objects (the author identity and ATT&CK
attack-patterns) use one project namespace, dataset objects use a per-dataset
namespace, and observables use the STIX canonical UUIDv5. Building twice yields
byte-identical output.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .models import (
    ATTACK_TACTICS,
    STIX_VALUE_OBSERVABLES,
    DatasetManifest,
    KillChainStage,
    ScenarioEntity,
    ScenarioObservable,
)

EXT_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
EXT_SCHEMA_URL = (
    "https://center-for-threat-informed-defense.github.io/attack-flow/stix/"
    "attack-flow-schema-2.0.0.json"
)
CTID_IDENTITY_ID = "identity--d673f8cb-c168-42da-8ed4-0cb26725f86c"
ECHOLAKE_IDENTITY_ID = "identity--9aab5679-38f7-55db-920c-5163cc72b44d"
ECHOLAKE_IDENTITY_TS = "2026-09-08T00:00:00.000Z"
GLOBAL_NS = uuid.uuid5(uuid.NAMESPACE_URL, "echolake")
EXT_BLOCK = {EXT_ID: {"extension_type": "new-sdo"}}

# Keys on a ScenarioObservable / ScenarioEntity that are manifest annotations,
# not STIX properties, and must never reach a STIX constructor.
_ANNOTATIONS = {
    "id", "type", "indicator_types", "kill_chain_phases", "techniques",
    "confidence", "first_seen", "last_seen", "description", "pattern",
    "pattern_type", "rule", "role", "observables",
}


class AttackFlowBuildError(ValueError):
    """Raised when the manifest cannot be turned into a valid flow."""


def _ns(dataset_name: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"echolake/{dataset_name}")


def _sid(ns: uuid.UUID, kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(ns, f'{kind}:{key}')}"


def _ts(manifest: DatasetManifest) -> str:
    """Deterministic created/modified timestamp from the manifest's dates."""
    date = manifest.metadata.updated or manifest.metadata.created
    if not date:
        raise AttackFlowBuildError("metadata.created (or updated) is required to stamp the flow")
    date = str(date)
    if "T" in date:
        return date if date.endswith("Z") else date + "Z"
    return f"{date}T00:00:00.000Z"


def _technique_url(tid: str) -> str:
    base, _, sub = tid.partition(".")
    return f"https://attack.mitre.org/techniques/{base}/{sub}/" if sub else f"https://attack.mitre.org/techniques/{base}/"


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _props(obj: Union[ScenarioEntity, ScenarioObservable]) -> Dict[str, Any]:
    """STIX properties for an entity/observable: declared fields plus extras, minus annotations."""
    data = obj.model_dump(exclude_none=True)
    data.update(obj.model_extra or {})
    return {k: v for k, v in data.items() if k not in _ANNOTATIONS}


# ---------------------------------------------------------------------------
# Fixed objects
# ---------------------------------------------------------------------------

def _extension_definition() -> Dict[str, Any]:
    return {
        "type": "extension-definition",
        "id": EXT_ID,
        "spec_version": "2.1",
        "name": "Attack Flow",
        "description": "Extends STIX 2.1 with features to create Attack Flows.",
        "created": "2022-08-02T19:34:35.143Z",
        "modified": "2022-08-02T19:34:35.143Z",
        "created_by_ref": CTID_IDENTITY_ID,
        "schema": EXT_SCHEMA_URL,
        "version": "2.0.0",
        "extension_types": ["new-sdo"],
        "external_references": [
            {"source_name": "Documentation", "description": "Documentation for Attack Flow",
             "url": "https://center-for-threat-informed-defense.github.io/attack-flow"},
            {"source_name": "GitHub", "description": "Source code repository for Attack Flow",
             "url": "https://github.com/center-for-threat-informed-defense/attack-flow"},
        ],
    }


def _ctid_identity() -> Dict[str, Any]:
    return {
        "type": "identity", "spec_version": "2.1", "id": CTID_IDENTITY_ID,
        "created_by_ref": CTID_IDENTITY_ID,
        "created": "2022-08-02T19:34:35.143Z", "modified": "2022-08-02T19:34:35.143Z",
        "name": "MITRE Center for Threat-Informed Defense", "identity_class": "organization",
    }


def _echolake_identity() -> Dict[str, Any]:
    return {
        "type": "identity", "spec_version": "2.1", "id": ECHOLAKE_IDENTITY_ID,
        "created": ECHOLAKE_IDENTITY_TS, "modified": ECHOLAKE_IDENTITY_TS,
        "name": "EchoLake Project", "identity_class": "organization",
    }


def _attack_pattern(tid: str, name: Optional[str]) -> Dict[str, Any]:
    return {
        "type": "attack-pattern", "spec_version": "2.1",
        "id": _sid(GLOBAL_NS, "attack-pattern", tid),
        "created_by_ref": ECHOLAKE_IDENTITY_ID,
        "created": ECHOLAKE_IDENTITY_TS, "modified": ECHOLAKE_IDENTITY_TS,
        "name": name or tid,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": tid, "url": _technique_url(tid)}
        ],
    }


# ---------------------------------------------------------------------------
# STIX object construction (observables, entities, indicators)
# ---------------------------------------------------------------------------

def _sco_class(stix2: Any, stype: str) -> Any:
    table = {
        "ipv4-addr": stix2.IPv4Address, "ipv6-addr": stix2.IPv6Address,
        "mac-addr": stix2.MACAddress, "domain-name": stix2.DomainName,
        "url": stix2.URL, "email-addr": stix2.EmailAddress,
        "email-message": stix2.EmailMessage, "file": stix2.File,
        "directory": stix2.Directory, "process": stix2.Process,
        "user-account": stix2.UserAccount,
        "windows-registry-key": stix2.WindowsRegistryKey,
        "network-traffic": stix2.NetworkTraffic, "software": stix2.Software,
        "mutex": stix2.Mutex, "x509-certificate": stix2.X509Certificate,
        "artifact": stix2.Artifact, "autonomous-system": stix2.AutonomousSystem,
    }
    return table[stype]


# STIX observable types that have a `name` property. For every other type the
# manifest `name` is only a label for the derived indicator and must not reach
# the STIX constructor.
_NAMED_SCO_TYPES = {"file", "process", "mutex", "software"}


def _build_sco(stix2: Any, ns: uuid.UUID, handle: str, stype: str, props: Dict[str, Any]) -> Any:
    """Construct a STIX observable. Canonical deterministic id where the spec
    defines one; a dataset-namespaced id for process, which the spec leaves random."""
    props = dict(props)
    if stype == "windows-registry-key" and isinstance(props.get("values"), list):
        props["values"] = [
            v if not isinstance(v, dict) else stix2.WindowsRegistryValueType(**v)
            for v in props["values"]
        ]
    if stype == "user-account" and "name" in props:
        props["display_name"] = props.pop("name")
    elif stype not in _NAMED_SCO_TYPES:
        props.pop("name", None)
    if stype == "process":
        props.setdefault("id", _sid(ns, "process", handle))
    try:
        return _sco_class(stix2, stype)(**props)
    except Exception as e:  # noqa: BLE001 - re-raise with the manifest handle for context
        raise AttackFlowBuildError(f"observable/entity {handle!r} ({stype}): {e}") from e


def _pattern_for(obs: ScenarioObservable, props: Dict[str, Any]) -> str:
    t = obs.type
    if t in STIX_VALUE_OBSERVABLES:
        return f"[{t}:value = '{_escape(obs.value or '')}']"
    if t == "file":
        hashes = props.get("hashes") or {}
        for alg in ("SHA-256", "SHA-1", "MD5", "SHA-512"):
            if alg in hashes:
                return f"[file:hashes.'{alg}' = '{_escape(str(hashes[alg]))}']"
        return f"[file:name = '{_escape(obs.name or '')}']"
    if t == "process":
        cl = props.get("command_line")
        return f"[process:command_line = '{_escape(str(cl))}']" if cl else f"[process:pid = {props.get('pid', 0)}]"
    if t == "windows-registry-key":
        return f"[windows-registry-key:key = '{_escape(str(props.get('key')))}']"
    if t == "user-account":
        login = props.get("account_login") or props.get("user_id")
        field = "account_login" if props.get("account_login") else "user_id"
        return f"[user-account:{field} = '{_escape(str(login))}']"
    if t in ("mutex", "software"):
        return f"[{t}:name = '{_escape(obs.name or '')}']"
    if t == "directory":
        return f"[directory:path = '{_escape(str(props.get('path')))}']"
    if t == "email-message":
        return f"[email-message:subject = '{_escape(str(props.get('subject', '')))}']"
    raise AttackFlowBuildError(f"observable {obs.id!r}: no pattern rule for type {t!r}; give it type indicator with an explicit pattern")


def _rule_ref(rule: str) -> Dict[str, Any]:
    """An external_references entry pointing at an external detection rule file."""
    base = rule.rstrip("/").rsplit("/", 1)[-1]
    for ext in (".yml", ".yaml"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    ref: Dict[str, Any] = {"source_name": "sigma-rule", "external_id": base}
    if rule.startswith(("http://", "https://")):
        ref["url"] = rule
    else:
        ref["description"] = rule
    return ref


def _build_indicator(stix2: Any, ns: uuid.UUID, obs: ScenarioObservable, pattern: str,
                     pattern_type: str, ts: str, valid_from: str) -> Any:
    kwargs: Dict[str, Any] = dict(
        id=_sid(ns, "indicator", obs.id),
        created_by_ref=ECHOLAKE_IDENTITY_ID, created=ts, modified=ts,
        name=obs.name or obs.value or obs.id,
        pattern=pattern, pattern_type=pattern_type, valid_from=valid_from,
        indicator_types=list(obs.indicator_types) or ["unknown"],
    )
    if pattern_type == "stix":
        kwargs["pattern_version"] = "2.1"
    if obs.description:
        kwargs["description"] = obs.description
    if obs.kill_chain_phases:
        kwargs["kill_chain_phases"] = [
            stix2.KillChainPhase(kill_chain_name="mitre-attack", phase_name=p)
            for p in obs.kill_chain_phases
        ]
    if obs.confidence is not None:
        kwargs["confidence"] = obs.confidence
    if obs.techniques:
        kwargs["labels"] = list(obs.techniques)
    if obs.last_seen:
        kwargs["valid_until"] = obs.last_seen
    try:
        return stix2.Indicator(**kwargs)
    except Exception as e:  # noqa: BLE001
        raise AttackFlowBuildError(f"observable {obs.id!r} indicator: {e}") from e


def _build_entity(stix2: Any, ns: uuid.UUID, ent: ScenarioEntity, ts: str) -> Any:
    props = _props(ent)
    if ent.type == "user-account":
        return _build_sco(stix2, ns, ent.id, "user-account", props)
    classes = {
        "infrastructure": stix2.Infrastructure, "identity": stix2.Identity,
        "threat-actor": stix2.ThreatActor, "intrusion-set": stix2.IntrusionSet,
        "campaign": stix2.Campaign, "tool": stix2.Tool, "malware": stix2.Malware,
    }
    kwargs: Dict[str, Any] = dict(
        id=_sid(ns, ent.type, ent.id), created_by_ref=ECHOLAKE_IDENTITY_ID,
        created=ts, modified=ts, name=ent.name,
    )
    if ent.description:
        kwargs["description"] = ent.description
    if ent.type == "malware":
        kwargs.setdefault("is_family", False)
    kwargs.update({k: v for k, v in props.items() if k != "name"})
    try:
        return classes[ent.type](**kwargs)
    except Exception as e:  # noqa: BLE001
        raise AttackFlowBuildError(f"entity {ent.id!r} ({ent.type}): {e}") from e


def _relationship(stix2: Any, ns: uuid.UUID, rel: str, src: str, tgt: str, ts: str) -> Any:
    return stix2.Relationship(
        id=_sid(ns, "relationship", f"{rel}:{src}:{tgt}"),
        relationship_type=rel, source_ref=src, target_ref=tgt,
        created_by_ref=ECHOLAKE_IDENTITY_ID, created=ts, modified=ts,
        allow_custom=True,  # targets may be Attack Flow objects (attack-action), a custom STIX type
    )


def _as_dict(obj: Any) -> Dict[str, Any]:
    return obj if isinstance(obj, dict) else json.loads(obj.serialize())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_attack_flow(manifest: DatasetManifest) -> Dict[str, Any]:
    """Return the Attack Flow bundle (as a dict) for a manifest with scenario blocks."""
    try:
        import stix2  # the STIX library is a build-time requirement, not a replay one
    except ImportError as e:  # pragma: no cover
        raise AttackFlowBuildError("building an Attack Flow requires the stix2 package (pip install stix2)") from e

    if not manifest.kill_chain:
        raise AttackFlowBuildError("manifest has no kill_chain block; nothing to build")
    name = manifest.metadata.name
    ns = _ns(name)
    ts = _ts(manifest)
    valid_from_default = (
        manifest.metadata.timestamp_range.earliest if manifest.metadata.timestamp_range else ts
    )
    tech_names = {
        t.id: t.name for t in (manifest.metadata.mitre_attack.techniques if manifest.metadata.mitre_attack else [])
    }

    objects: List[Dict[str, Any]] = [_extension_definition(), _ctid_identity(), _echolake_identity()]
    seen: set = set(o["id"] for o in objects)

    def add(obj: Any) -> str:
        d = _as_dict(obj)
        if d["id"] not in seen:
            seen.add(d["id"])
            objects.append(d)
        return d["id"]

    # Observables: SCO (or pattern-only indicator) plus an indicator when marked.
    sco_id: Dict[str, str] = {}
    ind_id: Dict[str, str] = {}
    rule_refs: Dict[str, str] = {}
    obs_by_id = {o.id: o for o in manifest.observables}
    pending_rels: List[Tuple[str, str, str]] = []
    for obs in manifest.observables:
        props = _props(obs)
        if obs.type == "indicator":
            if obs.rule:
                rule_refs[obs.id] = obs.rule  # external reference on the action; no indicator object
                continue
            if obs.pattern_type == "sigma":
                continue  # inline Sigma is never emitted into the bundle
            ind = _build_indicator(stix2, ns, obs, obs.pattern or "", obs.pattern_type or "stix", ts,
                                   obs.first_seen or valid_from_default)
            ind_id[obs.id] = add(ind)
            continue
        if obs.type == "user-account" and "name" in props:
            props["display_name"] = props.pop("name")
        sco = _build_sco(stix2, ns, obs.id, obs.type, props)
        sco_id[obs.id] = add(sco)
        if obs.indicator_types:
            pattern = _pattern_for(obs, props)
            ind = _build_indicator(stix2, ns, obs, pattern, "stix", ts, obs.first_seen or valid_from_default)
            ind_id[obs.id] = add(ind)
            pending_rels.append(("based-on", ind_id[obs.id], sco_id[obs.id]))

    # Entities: STIX object plus an attack-asset pointing at it.
    ent_id: Dict[str, str] = {}
    asset_id: Dict[str, str] = {}
    for ent in manifest.entities:
        ent_id[ent.id] = add(_build_entity(stix2, ns, ent, ts))
        desc = ent.description or ""
        if ent.role:
            desc = f"{ent.role}. {desc}".strip(". ").strip() if desc else ent.role
        asset: Dict[str, Any] = {
            "type": "attack-asset", "spec_version": "2.1",
            "id": _sid(ns, "attack-asset", ent.id), "created": ts, "modified": ts,
            "name": ent.name or (ent.model_extra or {}).get("account_login") or ent.id,
            "object_ref": ent_id[ent.id], "extensions": EXT_BLOCK,
        }
        if desc:
            asset["description"] = desc
        asset_id[ent.id] = add(asset)
        for h in ent.observables:
            target = sco_id.get(h) or ind_id.get(h)
            if not target:
                continue  # detection reference or dropped sigma: entities do not link to it
            rel = "consists-of" if ent.type == "infrastructure" else "related-to"
            pending_rels.append((rel, ent_id[ent.id], target))
            if h in ind_id and ent.type in ("infrastructure", "malware", "tool", "threat-actor", "intrusion-set", "campaign") and h in sco_id:
                pending_rels.append(("indicates", ind_id[h], ent_id[ent.id]))

    # Attack patterns (one per technique, shared namespace).
    ap_id: Dict[str, str] = {}
    for stage in manifest.kill_chain:
        for tid in stage.techniques:
            if tid not in ap_id:
                ap_id[tid] = add(_attack_pattern(tid, tech_names.get(tid)))

    # Actions: one per technique per stage, chained.
    stage_actions: Dict[str, List[str]] = {}
    for stage in manifest.kill_chain:
        stage_actions[stage.id] = [_sid(ns, "attack-action", f"{stage.id}:{tid}") for tid in stage.techniques]
    order = [s.id for s in manifest.kill_chain]
    action_objs: List[Dict[str, Any]] = []
    action_by_id: Dict[str, Dict[str, Any]] = {}
    for idx, stage in enumerate(manifest.kill_chain):
        nxt = stage.next if stage.next is not None else (order[idx + 1:idx + 2])
        ids = stage_actions[stage.id]
        for j, tid in enumerate(stage.techniques):
            multi = len(stage.techniques) > 1
            action: Dict[str, Any] = {
                "type": "attack-action", "spec_version": "2.1", "id": ids[j],
                "created": ts, "modified": ts,
                "name": f"{stage.id} {stage.name}" + (f" ({tid})" if multi else ""),
                "technique_id": tid, "technique_ref": ap_id[tid],
                "extensions": EXT_BLOCK,
            }
            if stage.tactic:
                action["tactic_id"] = ATTACK_TACTICS[stage.tactic]
            if j == 0 and stage.description:
                action["description"] = stage.description
            elif multi:
                action["description"] = f"Part of stage {stage.id}: {stage.name}."
            if stage.execution_start:
                action["execution_start"] = stage.execution_start
            if stage.execution_end:
                action["execution_end"] = stage.execution_end
            if stage.assets:
                action["asset_refs"] = [asset_id[h] for h in stage.assets]
            effects: List[str] = []
            if j + 1 < len(ids):
                effects.append(ids[j + 1])
            else:
                for nid in nxt:
                    effects.append(stage_actions[nid][0])
            if effects:
                action["effect_refs"] = effects
            action_objs.append(action)
            action_by_id[ids[j]] = action
        for h in stage.observables:
            if h in rule_refs:
                tid = next((t for t in obs_by_id[h].techniques if t in stage.techniques), None)
                target = _sid(ns, "attack-action", f"{stage.id}:{tid}") if tid else ids[0]
                action_by_id[target].setdefault("external_references", []).append(_rule_ref(rule_refs[h]))
                continue
            src = ind_id.get(h) or sco_id.get(h)
            if not src:
                continue  # dropped sigma observable with no rule reference
            pending_rels.append(("related-to", src, ids[0]))

    first = stage_actions[manifest.kill_chain[0].id][0]
    flow: Dict[str, Any] = {
        "type": "attack-flow", "spec_version": "2.1", "id": _sid(ns, "attack-flow", "main"),
        "created_by_ref": ECHOLAKE_IDENTITY_ID, "created": ts, "modified": ts,
        "name": name, "description": manifest.metadata.description.strip(),
        "scope": "incident", "start_refs": [first],
        "external_references": [
            {"source_name": "echolake-dataset", "description": f"{name} v{manifest.metadata.version}"}
        ],
        "extensions": EXT_BLOCK,
    }
    add(flow)
    for a in action_objs:
        add(a)
    for rel, src, tgt in pending_rels:
        add(_relationship(stix2, ns, rel, src, tgt, ts))

    return {"type": "bundle", "id": _sid(ns, "bundle", "main"), "objects": objects}


def write_attack_flow(manifest_path: Union[str, Path], output: Optional[Union[str, Path]] = None) -> Path:
    """Build the flow for a manifest and write it beside the manifest.

    The output path defaults to ``metadata.attack_flow.path`` (relative to the
    dataset root) or ``attack_flow.json``.
    """
    manifest_path = Path(manifest_path)
    manifest = DatasetManifest.from_file(manifest_path)
    bundle = build_attack_flow(manifest)
    if output is None:
        rel = manifest.metadata.attack_flow.path if manifest.metadata.attack_flow else "attack_flow.json"
        output = manifest_path.parent / rel
    output = Path(output)
    output.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return output
