"""Trend + risk + owner reporting endpoints.

These power the dashboard's trend chart, risk-sorted finding list, and
owner attribution views. Pure read-side queries — no scanner work here.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import logging
import zipfile
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from api import deps

router = APIRouter(tags=["trends"])
logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- trend


@router.get("/trends/findings")
async def findings_trend(
    repo_id: str,
    days: int = 30,
    db=Depends(deps.get_db),
) -> dict[str, Any]:
    """Findings introduced vs fixed per day for the last ``days`` days.

    A finding is "introduced" on the day its scan ran; "fixed" when a
    later scan for the same repo no longer reports the same fingerprint.
    """
    if days <= 0 or days > 365:
        raise HTTPException(status_code=400, detail="days must be in 1..365")

    since = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
    pipeline = [
        {"$match": {"repo_id": repo_id, "created_at": {"$gte": since}}},
        {"$project": {
            "day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "fingerprint": 1,
        }},
        {"$group": {
            "_id": "$day",
            "introduced": {"$addToSet": "$fingerprint"},
        }},
        {"$project": {"day": "$_id", "_id": 0, "introduced_count": {"$size": "$introduced"}}},
        {"$sort": {"day": 1}},
    ]
    rows = await db.vulnerabilities.aggregate(pipeline).to_list(1000)
    return {"repo_id": repo_id, "days": days, "series": rows}


# --------------------------------------------------------------------------- risk


@router.get("/trends/top-risk")
async def top_risk_findings(
    repo_id: str,
    limit: int = 20,
    db=Depends(deps.get_db),
) -> list[dict]:
    """Top-N findings sorted by ``risk_score`` (set by services.risk_score)."""
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be 1..200")
    cursor = (
        db.vulnerabilities
        .find({"repo_id": repo_id}, {"_id": 0})
        .sort("risk_score", -1)
        .limit(limit)
    )
    return await cursor.to_list(limit)


# --------------------------------------------------------------------------- owners


@router.get("/trends/owners")
async def owner_breakdown(
    repo_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    """Findings grouped by ``owner_email`` (set by services.blame)."""
    pipeline = [
        {"$match": {"repo_id": repo_id, "owner_email": {"$exists": True, "$ne": ""}}},
        {"$group": {
            "_id": "$owner_email",
            "count": {"$sum": 1},
            "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]}},
            "high": {"$sum": {"$cond": [{"$eq": ["$severity", "high"]}, 1, 0]}},
        }},
        {"$project": {"owner_email": "$_id", "_id": 0, "count": 1, "critical": 1, "high": 1}},
        {"$sort": {"count": -1}},
    ]
    return await db.vulnerabilities.aggregate(pipeline).to_list(500)


# --------------------------------------------------------------------------- compliance evidence pack


@router.get("/reports/evidence-pack")
async def evidence_pack(
    repo_id: str,
    scan_id: str,
    db=Depends(deps.get_db),
):
    """Download a SOC2/PCI evidence ZIP for the given scan.

    Contents:
      manifest.json      — repo metadata, scan timestamp, scanner versions
      findings.json      — full finding list with risk scores + owners
      summary.md         — human-readable summary for auditors
      scanner_health.json — which scanners ran / didn't run
    """
    repo = await db.repositories.find_one({"id": repo_id}, {"_id": 0})
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not (repo and scan):
        raise HTTPException(status_code=404, detail="repo or scan not found")

    findings = await db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).to_list(50000)
    health_doc = await db.scanner_runs.find_one({"scan_id": scan_id}, {"_id": 0}) or {}

    manifest = {
        "format_version": 1,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "repository": {k: repo.get(k) for k in ("id", "name", "url", "branch")},
        "scan": {k: scan.get(k) for k in ("id", "started_at", "completed_at", "tier", "tier_reason")},
        "totals": {
            "findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
        },
        "controls": {
            "SOC2_CC7.1": "vulnerability scanning frequency",
            "SOC2_CC7.2": "vulnerability remediation tracking",
            "PCI_6.5":    "secure coding practices verified by static analysis",
            "PCI_11.3":   "vulnerability assessment",
        },
    }

    summary_lines = [
        f"# Evidence Pack — {repo.get('name', repo.get('id'))}",
        "",
        f"Generated: {manifest['generated_at']}",
        f"Scan tier: {scan.get('tier', 'unspecified')}",
        f"Scan window: {scan.get('started_at')} → {scan.get('completed_at')}",
        "",
        "## Totals",
        f"- Findings: **{manifest['totals']['findings']}**",
        f"- Critical: **{manifest['totals']['critical']}**",
        f"- High: **{manifest['totals']['high']}**",
        "",
        "## SOC2 / PCI control coverage",
    ]
    for ctrl, desc in manifest["controls"].items():
        summary_lines.append(f"- **{ctrl}** — {desc}")
    summary_md = "\n".join(summary_lines) + "\n"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        zf.writestr("findings.json", json.dumps(findings, indent=2, default=str))
        zf.writestr("summary.md", summary_md)
        zf.writestr("scanner_health.json", json.dumps(health_doc, indent=2, default=str))
    buf.seek(0)

    fname = f"fortknoxx-evidence-{repo.get('id', 'repo')}-{scan.get('id', 'scan')}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
