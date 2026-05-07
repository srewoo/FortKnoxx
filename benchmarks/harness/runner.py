"""Benchmark runner.

Workflow:
  1. Load ground truth for each requested dataset.
  2. Run the FortKnoxx scanner stack against the dataset's source tree.
  3. Map raw scanner output → predictions ``{case_id, scanner, cwe}``.
  4. Compute per-scanner / per-CWE metrics.
  5. Write raw.json + summary.md to ``benchmarks/results/<timestamp>/``.

The runner is intentionally orchestrator-light: it shells out to scanner
CLIs that are already installed by ``install_all_scanners.sh``, parses
their JSON/SARIF output, and joins to ground truth. We avoid loading the
full FastAPI app so CI doesn't need MongoDB/Redis to produce numbers.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .ground_truth import GroundTruthCase, load_ground_truth
from .metrics import compute_metrics, render_summary

logger = logging.getLogger("benchmark")

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_ROOT = REPO_ROOT / "benchmarks" / "datasets"
RESULTS_ROOT = REPO_ROOT / "benchmarks" / "results"

# Scanners → CLI invocations. Each command must produce JSON on stdout
# (or honour --output / -o semantics that the adapter knows about).
DEFAULT_SCANNERS: dict[str, list[str]] = {
    "semgrep": ["semgrep", "--config=auto", "--json", "--quiet"],
    "bandit": ["bandit", "-r", "-f", "json", "-q"],
    "gosec": ["gosec", "-fmt=json", "./..."],
}


@dataclass
class ScannerInvocation:
    name: str
    cmd: list[str]
    parser: callable                                 # bytes -> list[dict]


@dataclass
class BenchmarkRun:
    dataset: str
    timestamp: str
    cases: int
    predictions: list[dict] = field(default_factory=list)
    metrics: list[dict] = field(default_factory=list)


# --------------------------------------------------------------------------- parsers


def _parse_semgrep(out: bytes) -> list[dict]:
    try:
        data = json.loads(out or b"{}")
    except json.JSONDecodeError:
        return []
    preds = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        preds.append({
            "case_id": _case_id_from_path(r.get("path", "")),
            "file": r.get("path"),
            "line": (r.get("start") or {}).get("line"),
            "scanner": "semgrep",
            "cwe": _normalise_cwe(cwe),
            "rule_id": r.get("check_id"),
        })
    return preds


def _parse_bandit(out: bytes) -> list[dict]:
    try:
        data = json.loads(out or b"{}")
    except json.JSONDecodeError:
        return []
    preds = []
    for r in data.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        preds.append({
            "case_id": _case_id_from_path(r.get("filename", "")),
            "file": r.get("filename"),
            "line": r.get("line_number"),
            "scanner": "bandit",
            "cwe": _normalise_cwe(cwe),
            "rule_id": r.get("test_id"),
        })
    return preds


def _parse_gosec(out: bytes) -> list[dict]:
    try:
        data = json.loads(out or b"{}")
    except json.JSONDecodeError:
        return []
    preds = []
    for r in data.get("Issues", []):
        preds.append({
            "case_id": _case_id_from_path(r.get("file", "")),
            "file": r.get("file"),
            "line": r.get("line"),
            "scanner": "gosec",
            "cwe": _normalise_cwe(r.get("cwe", {}).get("id")),
            "rule_id": r.get("rule_id"),
        })
    return preds


_SCANNER_TABLE: dict[str, ScannerInvocation] = {
    "semgrep": ScannerInvocation("semgrep", DEFAULT_SCANNERS["semgrep"], _parse_semgrep),
    "bandit":  ScannerInvocation("bandit",  DEFAULT_SCANNERS["bandit"],  _parse_bandit),
    "gosec":   ScannerInvocation("gosec",   DEFAULT_SCANNERS["gosec"],   _parse_gosec),
}


# --------------------------------------------------------------------------- helpers


def _case_id_from_path(path: str) -> str:
    """Map a scanner-emitted path back to a ground-truth case_id.

    Both Juliet and OWASP Benchmark name files after the case id, so the
    file stem is sufficient. BigVul / SecurityEval ground truth records
    the full path, so we keep the full posix form too.
    """
    if not path:
        return ""
    return Path(path).stem


def _normalise_cwe(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    return s if s.upper().startswith("CWE-") else f"CWE-{s.lstrip('CWE').lstrip('-')}"


def _run_scanner(invocation: ScannerInvocation, target: Path) -> list[dict]:
    cmd = [*invocation.cmd, str(target)] if invocation.name != "gosec" else invocation.cmd
    logger.info("$ %s  (cwd=%s)", " ".join(cmd), target if invocation.name == "gosec" else "<repo>")
    try:
        proc = subprocess.run(
            cmd,
            cwd=target if invocation.name == "gosec" else None,
            capture_output=True,
            timeout=900,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.warning("scanner %s unavailable or timed out: %s", invocation.name, exc)
        return []
    return invocation.parser(proc.stdout)


# --------------------------------------------------------------------------- runner


@dataclass
class BenchmarkRunner:
    datasets: list[str]
    scanners: list[str]
    output_dir: Path = RESULTS_ROOT

    def run(self) -> list[BenchmarkRun]:
        timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_dir = self.output_dir / timestamp
        run_dir.mkdir(parents=True, exist_ok=True)

        runs: list[BenchmarkRun] = []
        for dataset in self.datasets:
            ds_root = DATASETS_ROOT / dataset
            cases = load_ground_truth(dataset, ds_root)
            if not cases:
                logger.warning("dataset %s has no cases — skipped", dataset)
                continue

            preds = self._scan_dataset(ds_root)
            run = BenchmarkRun(dataset=dataset, timestamp=timestamp, cases=len(cases))
            run.predictions = preds
            metrics = compute_metrics(preds, [_gt_to_dict(c) for c in cases])
            run.metrics = [m.to_dict() for m in metrics]

            (run_dir / f"{dataset}.json").write_text(
                json.dumps({
                    "dataset": dataset,
                    "timestamp": timestamp,
                    "cases": run.cases,
                    "predictions": run.predictions,
                    "metrics": run.metrics,
                }, indent=2)
            )
            (run_dir / f"{dataset}.md").write_text(render_summary(metrics, dataset=dataset))
            logger.info("wrote results for %s → %s", dataset, run_dir)
            runs.append(run)

        # Latest pointer for docs/.
        if runs:
            latest = REPO_ROOT / "docs" / "benchmarks" / "latest.md"
            latest.parent.mkdir(parents=True, exist_ok=True)
            latest.write_text(_combine_summaries(runs, run_dir))
        return runs

    def _scan_dataset(self, target: Path) -> list[dict]:
        all_preds: list[dict] = []
        for name in self.scanners:
            invocation = _SCANNER_TABLE.get(name)
            if invocation is None:
                logger.warning("scanner %s not registered in harness — skipped", name)
                continue
            all_preds.extend(_run_scanner(invocation, target))
        return all_preds


def _gt_to_dict(c: GroundTruthCase) -> dict:
    return {
        "case_id": c.case_id if c.dataset != "owasp_benchmark" else Path(c.file_path).stem,
        "cwe": c.cwe,
        "is_vulnerable": c.is_vulnerable,
        "dataset": c.dataset,
    }


def _combine_summaries(runs: list[BenchmarkRun], run_dir: Path) -> str:
    parts = ["# FortKnoxx Benchmark Results", "", f"Run: `{runs[0].timestamp}`", ""]
    for r in runs:
        parts.append((run_dir / f"{r.dataset}.md").read_text())
        parts.append("")
    return "\n".join(parts)


# --------------------------------------------------------------------------- CLI


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="benchmark", description=__doc__)
    p.add_argument(
        "--datasets",
        default="owasp_benchmark,juliet_java,security_eval,bigvul",
        help="comma-separated dataset names",
    )
    p.add_argument(
        "--scanners",
        default="semgrep,bandit,gosec",
        help="comma-separated scanner names registered in the harness",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    runner = BenchmarkRunner(
        datasets=[d.strip() for d in args.datasets.split(",") if d.strip()],
        scanners=[s.strip() for s in args.scanners.split(",") if s.strip()],
    )
    runs = runner.run()
    print(f"\nCompleted {len(runs)} benchmark run(s).")
    return 0 if runs else 1


if __name__ == "__main__":
    raise SystemExit(main())
