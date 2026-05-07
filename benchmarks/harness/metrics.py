"""Precision / recall / F1 / FP-rate per scanner per CWE family."""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Allow `from engines.triage import canonical_cwe_family` when the harness is
# invoked outside the backend venv path.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from engines.triage import canonical_cwe_family  # noqa: E402


@dataclass
class _Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0


@dataclass
class ScannerMetrics:
    scanner: str
    cwe_family: str
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fp_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "cwe_family": self.cwe_family,
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fp_rate": round(self.fp_rate, 4),
        }


def compute_metrics(predictions: list[dict], ground_truth: list[dict]) -> list[ScannerMetrics]:
    """Cross-tabulate predictions × ground truth.

    A prediction is ``{case_id, scanner, cwe}``.
    A ground-truth row is ``{case_id, cwe, is_vulnerable}``.
    Match key for TP: case_id + canonical CWE family.
    """
    gt_by_case: dict[str, dict] = {g["case_id"]: g for g in ground_truth}
    counts: dict[tuple[str, str], _Counts] = defaultdict(_Counts)

    # Index predictions by (case_id, family) so we can dedupe scanner-level
    # multi-detection on the same case as a single TP/FP.
    pred_index: dict[tuple[str, str, str], None] = {}
    scanners_seen: set[str] = set()
    for p in predictions:
        family = canonical_cwe_family(p.get("cwe"))
        key = (p["case_id"], p["scanner"], family)
        pred_index[key] = None
        scanners_seen.add(p["scanner"])

    # Iterate over (scanner × case) and classify.
    for scanner in scanners_seen:
        for case_id, gt in gt_by_case.items():
            gt_family = canonical_cwe_family(gt.get("cwe"))
            predicted_families = {
                fam for (cid, sc, fam) in pred_index
                if cid == case_id and sc == scanner
            }
            if gt["is_vulnerable"]:
                if gt_family in predicted_families:
                    counts[(scanner, gt_family)].tp += 1
                else:
                    counts[(scanner, gt_family)].fn += 1
                # Other scanners' detections of *unrelated* families on a
                # vulnerable case still count as FP under that family.
                for fam in predicted_families - {gt_family}:
                    counts[(scanner, fam)].fp += 1
            else:
                # Benign case. Any detection is a FP.
                if predicted_families:
                    for fam in predicted_families:
                        counts[(scanner, fam)].fp += 1
                else:
                    # TN bookkeeping is per-scanner-not-per-family — record
                    # against "unclassified" to avoid double-counting.
                    counts[(scanner, "unclassified")].tn += 1

    return [
        ScannerMetrics(scanner=sc, cwe_family=fam, **vars(c))
        for (sc, fam), c in sorted(counts.items())
    ]


def render_summary(metrics: list[ScannerMetrics], *, dataset: str) -> str:
    """Markdown summary table — what gets committed to docs/benchmarks/."""
    lines = [
        f"# Benchmark — {dataset}",
        "",
        "| Scanner | CWE family | TP | FP | FN | TN | Precision | Recall | F1 | FP rate |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for m in metrics:
        lines.append(
            f"| {m.scanner} | {m.cwe_family} "
            f"| {m.tp} | {m.fp} | {m.fn} | {m.tn} "
            f"| {m.precision:.3f} | {m.recall:.3f} | {m.f1:.3f} | {m.fp_rate:.3f} |"
        )
    return "\n".join(lines) + "\n"
