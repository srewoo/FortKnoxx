"""Report generation route — JSON / CSV / PDF formats.

Extracted from server.py during Phase 1.5. The PDF rendering happens
inside `reporting.pdf_report.PDFSecurityReport`; this route just
orchestrates DB reads and dispatches by `format`.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from api import deps
from api.schemas import ReportRequest
from services.owasp import OWASP_CATEGORIES

router = APIRouter(tags=["reports"])
logger = logging.getLogger(__name__)


@router.post("/reports/generate")
async def generate_report(
    request: ReportRequest,
    db=Depends(deps.get_db),
) -> Any:
    try:
        scan = await db.scans.find_one({"id": request.scan_id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        repo = await db.repositories.find_one({"id": request.repo_id}, {"_id": 0})
        vulns = await db.vulnerabilities.find({"scan_id": request.scan_id}, {"_id": 0}).to_list(10000)

        if request.format == "json":
            return {
                "repository": repo,
                "scan": scan,
                "vulnerabilities": vulns,
                "owasp_mapping": OWASP_CATEGORIES,
            }
        if request.format == "csv":
            csv_data = [
                {
                    "file": vuln.get("file_path", ""),
                    "line": f"{vuln.get('line_start', '')}-{vuln.get('line_end', '')}",
                    "severity": vuln.get("severity", ""),
                    "owasp": vuln.get("owasp_category", ""),
                    "title": vuln.get("title", ""),
                    "description": vuln.get("description", ""),
                    "tool": vuln.get("detected_by", ""),
                }
                for vuln in vulns
            ]
            return {"format": "csv", "data": csv_data}
        if request.format == "pdf":
            from reporting.pdf_report import PDFSecurityReport

            pdf_generator = PDFSecurityReport()
            pdf_bytes = pdf_generator.generate_report(
                repo_data=repo,
                scan_data=scan,
                vulnerabilities=vulns,
            )
            filename = f"security_report_{request.repo_id}_{request.scan_id}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        return {"message": "Unsupported format. Use: json, csv, or pdf"}

    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — surfaced as 500 with stack in logs.
        logger.exception("Error generating report for scan %s", request.scan_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
