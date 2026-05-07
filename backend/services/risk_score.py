"""Risk-based prioritization.

Risk = severity × reachability × EPSS × asset_criticality

* severity              — discrete weight per severity level.
* reachability          — 1.0 if vulnerable function is actually called from
                          an entrypoint, 0.4 if unknown, 0.1 if explicitly
                          marked unreachable.
* EPSS                  — Exploit Prediction Scoring System. Free API at
                          first.org. Cached per CVE for 24 h to stay free.
* asset_criticality     — repo/service tag in {critical, high, medium, low}
                          → weight in {1.0, 0.75, 0.5, 0.25}.

Output is normalised to 0–100 so the UI can sort findings consistently and
display a single number alongside severity.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
_EPSS_CACHE_COLLECTION = "epss_cache"
_EPSS_TTL_HOURS = 24

_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}
_REACHABILITY_WEIGHT = {True: 1.0, None: 0.4, False: 0.1}
_ASSET_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


async def _epss_for_cve(cve_id: str, *, db=None, client: Optional[httpx.AsyncClient] = None) -> float:
    """Return the EPSS score for ``cve_id`` (0–1). Cached for 24h.

    Returns 0.0 when the CVE is unknown to FIRST or the network call fails —
    we never block scoring on EPSS availability.
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return 0.0

    # Cache lookup.
    if db is not None:
        try:
            doc = await db[_EPSS_CACHE_COLLECTION].find_one({"_id": cve_id})
        except Exception as exc:
            logger.debug("EPSS cache read failed: %s", exc)
            doc = None
        if doc:
            ts = doc.get("fetched_at")
            if isinstance(ts, dt.datetime) and (dt.datetime.now(dt.UTC) - ts).total_seconds() < _EPSS_TTL_HOURS * 3600:
                return float(doc.get("score", 0.0))

    own_client = client is None
    client = client or httpx.AsyncClient(timeout=5.0)
    try:
        resp = await client.get(EPSS_API, params={"cve": cve_id})
        resp.raise_for_status()
        data = resp.json().get("data") or []
        score = float(data[0]["epss"]) if data else 0.0
    except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
        logger.debug("EPSS fetch failed for %s: %s", cve_id, exc)
        score = 0.0
    finally:
        if own_client:
            await client.aclose()

    if db is not None:
        try:
            await db[_EPSS_CACHE_COLLECTION].update_one(
                {"_id": cve_id},
                {"$set": {"score": score, "fetched_at": dt.datetime.now(dt.UTC)}},
                upsert=True,
            )
        except Exception as exc:
            logger.debug("EPSS cache write failed: %s", exc)
    return score


def _severity(value) -> float:
    if isinstance(value, list):
        value = value[0] if value else "medium"
    return _SEVERITY_WEIGHT.get(str(value or "medium").lower(), 0.5)


def _reachability(value) -> float:
    return _REACHABILITY_WEIGHT.get(value, 0.4)


def _asset_weight(tag: Optional[str]) -> float:
    return _ASSET_WEIGHT.get(str(tag or "medium").lower(), 0.5)


async def score_finding(
    finding: dict,
    *,
    asset_criticality: Optional[str] = None,
    db=None,
    client: Optional[httpx.AsyncClient] = None,
) -> int:
    """Compute the 0–100 risk score for a single finding."""
    sev = _severity(finding.get("severity"))
    reach = _reachability(finding.get("reachable"))
    epss = await _epss_for_cve(finding.get("cve_id") or finding.get("cve"), db=db, client=client)
    asset = _asset_weight(asset_criticality or finding.get("asset_criticality"))

    raw = sev * reach * (0.5 + 0.5 * epss) * asset
    return max(0, min(100, round(raw * 100)))


async def score_findings(
    findings: list[dict],
    *,
    asset_criticality: Optional[str] = None,
    db=None,
) -> list[dict]:
    """Annotate every finding with ``risk_score`` in place; returns the list.

    Uses a single HTTP client + bounded concurrency so EPSS lookups don't
    fan out to hundreds of parallel requests on a large scan.
    """
    if not findings:
        return findings

    sem = asyncio.Semaphore(8)
    async with httpx.AsyncClient(timeout=5.0) as client:
        async def _one(f: dict):
            async with sem:
                f["risk_score"] = await score_finding(
                    f, asset_criticality=asset_criticality, db=db, client=client,
                )

        await asyncio.gather(*(_one(f) for f in findings))
    return findings
