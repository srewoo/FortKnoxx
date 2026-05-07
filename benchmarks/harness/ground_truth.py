"""Ground-truth model + per-dataset loaders.

A ``GroundTruthCase`` represents a single labelled (file, expected outcome)
sample. Datasets ship metadata in different shapes — the loaders below
normalise them onto this dataclass so the metrics code stays generic.
"""

from __future__ import annotations

import csv
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class GroundTruthCase:
    """One labelled sample."""

    case_id: str
    file_path: str          # path relative to dataset root
    cwe: str | None         # canonical "CWE-89" form; None for benign
    is_vulnerable: bool
    dataset: str            # owasp_benchmark | juliet | security_eval | bigvul
    metadata: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- registry


def load_ground_truth(dataset: str, root: Path) -> list[GroundTruthCase]:
    """Dispatch to the right loader. Returns [] if dataset isn't fetched."""
    if not root.is_dir():
        logger.warning("dataset %s not present at %s — run benchmarks/datasets/fetch.sh", dataset, root)
        return []

    loaders = {
        "owasp_benchmark": _load_owasp_benchmark,
        "juliet_java": _load_juliet,
        "security_eval": _load_security_eval,
        "bigvul": _load_bigvul,
    }
    if dataset not in loaders:
        raise ValueError(f"unknown dataset: {dataset}")
    return loaders[dataset](root)


# --------------------------------------------------------------------------- OWASP Benchmark
# Each test case is a Java file under src/main/java/.../BenchmarkTestNNNNN.java
# with a paired NNNNN.xml metadata file declaring the CWE and "real" vs "fake".


_OWASP_FILE_RE = re.compile(r"BenchmarkTest(\d+)\.java$")


def _load_owasp_benchmark(root: Path) -> list[GroundTruthCase]:
    cases: list[GroundTruthCase] = []
    expected = root / "expectedresults-1.2.csv"
    if not expected.is_file():
        logger.warning("OWASP Benchmark expected-results CSV missing at %s", expected)
        return []

    # CSV cols: # test name, category, real vulnerability, cwe
    src_root = root / "src" / "main" / "java"
    with expected.open(newline="") as fh:
        reader = csv.DictReader(fh, skipinitialspace=True)
        for row in reader:
            name = (row.get("# test name") or row.get("test name") or "").strip()
            if not name:
                continue
            real = (row.get("real vulnerability") or "").strip().lower() == "true"
            cwe = (row.get("cwe") or "").strip()
            cwe = f"CWE-{cwe}" if cwe.isdigit() else cwe or None
            # Locate the actual .java file by walking once. Index lazily via dict.
            cases.append(
                GroundTruthCase(
                    case_id=name,
                    file_path=str(src_root / "org" / "owasp" / "benchmark" / "testcode" / f"{name}.java"),
                    cwe=cwe,
                    is_vulnerable=real,
                    dataset="owasp_benchmark",
                    metadata={"category": (row.get("category") or "").strip()},
                )
            )
    return cases


# --------------------------------------------------------------------------- Juliet
# Files live under testcases/CWE<id>_<desc>/<...>/CWEnnn_*.java with names
# encoding the variant (good/bad). Bad => vulnerable.


def _load_juliet(root: Path) -> list[GroundTruthCase]:
    cases: list[GroundTruthCase] = []
    test_root = root / "testcases"
    if not test_root.is_dir():
        return cases

    for path in test_root.rglob("*.java"):
        rel = path.relative_to(root).as_posix()
        # Path looks like: testcases/CWE89_SQL_Injection/.../CWE89_xxx.java
        parts = path.parts
        cwe_dir = next((p for p in parts if p.startswith("CWE")), None)
        if not cwe_dir:
            continue
        cwe_num = re.match(r"CWE(\d+)", cwe_dir)
        if not cwe_num:
            continue
        cwe = f"CWE-{cwe_num.group(1)}"

        # Filename heuristic — bad/good variants.
        name = path.stem.lower()
        if "bad" in name and "good" not in name:
            is_vuln = True
        elif "good" in name and "bad" not in name:
            is_vuln = False
        else:
            # Mixed files have both; we don't try to slice them.
            continue

        cases.append(
            GroundTruthCase(
                case_id=rel,
                file_path=str(path),
                cwe=cwe,
                is_vulnerable=is_vuln,
                dataset="juliet_java",
            )
        )
    return cases


# --------------------------------------------------------------------------- SecurityEval
# JSONL with one record per case: {"id": "...", "cwe": "CWE-89", "code": "..."}


def _load_security_eval(root: Path) -> list[GroundTruthCase]:
    cases: list[GroundTruthCase] = []
    candidates = list(root.rglob("*.jsonl")) + list(root.rglob("dataset.json"))
    for f in candidates:
        with f.open() as fh:
            try:
                if f.suffix == ".jsonl":
                    rows = (json.loads(line) for line in fh if line.strip())
                else:
                    rows = json.load(fh)
            except json.JSONDecodeError as exc:
                logger.warning("failed to parse %s: %s", f, exc)
                continue
            for row in rows:
                cwe = row.get("cwe") or row.get("CWE")
                if cwe and not str(cwe).startswith("CWE-"):
                    cwe = f"CWE-{cwe}"
                cases.append(
                    GroundTruthCase(
                        case_id=str(row.get("id") or row.get("name") or len(cases)),
                        file_path=str(row.get("file") or row.get("path") or ""),
                        cwe=cwe,
                        is_vulnerable=True,  # SecurityEval is positive-only
                        dataset="security_eval",
                        metadata={"code": row.get("code", "")[:2000]},
                    )
                )
    return cases


# --------------------------------------------------------------------------- BigVul
# CSV with vulnerable/non-vulnerable pre/post commits and CWE labels.


def _load_bigvul(root: Path) -> list[GroundTruthCase]:
    cases: list[GroundTruthCase] = []
    for csv_file in root.rglob("*.csv"):
        try:
            with csv_file.open(newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    cwe = row.get("CWE ID") or row.get("cwe_id") or row.get("cwe")
                    if cwe and not str(cwe).startswith("CWE-"):
                        cwe = f"CWE-{cwe}"
                    is_vuln = str(row.get("vul") or row.get("vulnerable") or "").strip() in {"1", "true", "True"}
                    cases.append(
                        GroundTruthCase(
                            case_id=str(row.get("CVE ID") or row.get("commit_id") or len(cases)),
                            file_path=row.get("file_name", "") or "",
                            cwe=cwe,
                            is_vulnerable=is_vuln,
                            dataset="bigvul",
                        )
                    )
        except (csv.Error, UnicodeDecodeError) as exc:
            logger.warning("skipping %s: %s", csv_file, exc)
    return cases
