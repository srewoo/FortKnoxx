"""
SARIF 2.1.0 exporter.

SARIF (Static Analysis Results Interchange Format) is the standard
format consumed by GitHub Code Scanning, GitLab, Sonar, and most major
IDEs. Producing SARIF lets every FortKnoxx scanner light up in those
tools without per-vendor adapters.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from typing import Any, Dict, Iterable, List

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def export(findings: Iterable[Any], tool_name: str = "FortKnoxx") -> Dict[str, Any]:
    """Build a SARIF log from any iterable of finding-like objects.

    Findings can be dicts (the new scanner-wrapper format) or dataclass
    instances exposing similar attributes; we read fields defensively
    via :func:`_get`.
    """
    rules_index: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = str(_get(f, "id") or _get(f, "finding_id") or "FORTKNOXX-UNKNOWN")
        if rule_id not in rules_index:
            rules_index[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": _get(f, "title", default=rule_id) or rule_id},
                "fullDescription": {"text": _get(f, "description", default="") or ""},
                "helpUri": _first_ref(f),
                "properties": {"scanner": _get(f, "scanner", default="external")},
            }

        results.append({
            "ruleId": rule_id,
            "level": _SEV_TO_LEVEL.get((_get(f, "severity", default="medium") or "medium").lower(), "warning"),
            "message": {"text": _get(f, "description", default=_get(f, "title", default=rule_id)) or rule_id},
            "locations": _locations(f),
            "properties": {
                "severity": _get(f, "severity", default="medium"),
                "scanner": _get(f, "scanner", default="external"),
                "package": _get(f, "package"),
                "ecosystem": _get(f, "ecosystem"),
                "installed_version": _get(f, "installed_version"),
                "fixed_version": _get(f, "fixed_version"),
                "cve_id": _get(f, "cve_id"),
                "cvss_score": _get(f, "cvss_score"),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/fortknoxx",
                    "rules": list(rules_index.values()),
                }
            },
            "results": results,
        }],
    }


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _first_ref(obj: Any):
    refs = _get(obj, "references")
    if isinstance(refs, list) and refs:
        return refs[0]
    return None


def _locations(obj: Any) -> List[Dict[str, Any]]:
    file_path = _get(obj, "file_path")
    line = _get(obj, "line_start") or _get(obj, "line")
    url = _get(obj, "url")

    if file_path:
        return [{
            "physicalLocation": {
                "artifactLocation": {"uri": file_path},
                **({"region": {"startLine": int(line)}} if isinstance(line, int) and line > 0 else {}),
            }
        }]
    if url:
        return [{"physicalLocation": {"artifactLocation": {"uri": url}}}]
    return []
