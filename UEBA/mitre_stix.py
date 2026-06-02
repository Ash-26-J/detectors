"""
mitre_stix.py — dynamic MITRE ATT&CK technique lookup from the local STIX bundle.

Loads enterprise-attack.json once, builds name/keyword → external_id maps,
and lets callers resolve technique IDs without any hardcoded strings.
"""

import json, os, re

_BUNDLE = os.path.join(os.path.dirname(__file__), "..", "enterprise-attack.json")

# populated on first call to _load()
_name_to_id   = {}   # lowercase full name  → "T1217"
_id_to_obj    = {}   # "T1217"              → {"id": ..., "name": ..., "description": ...}

def _load():
    if _name_to_id:
        return
    try:
        with open(_BUNDLE, encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as exc:
        raise RuntimeError(f"Cannot load STIX bundle: {_BUNDLE}") from exc

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x-mitre-deprecated"):
            continue

        eid  = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                eid = ref.get("external_id", "")
                break
        if not eid:
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")

        record = {
            "id":          eid,
            "name":        name,
            "description": desc,
            "tactic":      [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])],
        }

        _id_to_obj[eid]          = record
        _name_to_id[name.lower()] = eid

def resolve(query: str) -> dict:
    """
    Look up a technique by name or external_id (e.g. "T1217").
    Returns {"id": "T1217", "name": "...", "description": "...", "tactic": [...]}
    or an empty dict if nothing matches.

    Match priority:
      1. Exact external_id  (e.g. "T1217" or "T1555.003")
      2. Exact name         (case-insensitive)
      3. Substring of name  (first match)
    """
    _load()
    q = query.strip()

    # 1. exact id
    if re.match(r"^T\d{4}(\.\d{3})?$", q, re.IGNORECASE):
        return _id_to_obj.get(q.upper(), {})

    ql = q.lower()

    # 2. exact name
    if ql in _name_to_id:
        return _id_to_obj.get(_name_to_id[ql], {})

    # 3. substring match — prefer sub-technique names when the query contains a slash or dot
    for name, eid in _name_to_id.items():
        if ql in name:
            return _id_to_obj.get(eid, {})

    return {}

def resolve_id(query: str) -> str:
    """Convenience: return just the external_id string, or '' on no match."""
    return resolve(query).get("id", "")

def technique_info(eid: str) -> dict:
    """Return the full record for a known external_id."""
    _load()
    return _id_to_obj.get(eid, {})

def all_techniques() -> dict:
    """Return the full id→record mapping (loads bundle if needed)."""
    _load()
    return dict(_id_to_obj)
