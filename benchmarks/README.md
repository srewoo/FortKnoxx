# FortKnoxx Benchmark Harness

Run the FortKnoxx scanner stack against published vulnerability datasets
and produce precision / recall / F1 numbers — per scanner, per CWE.

The point: turn AI-scanner claims into measurable evidence.

## Datasets

| Dataset | Language | Cases | License | Use |
| --- | --- | --- | --- | --- |
| OWASP Benchmark v1.2 | Java | ~3 000 | Apache-2.0 | SAST primary |
| Juliet Test Suite (NIST) | Java, C, C++ | ~64 000 | NIST PD | Cross-language |
| SecurityEval | Python | ~130 | MIT | LLM-vuln targeted |
| BigVul | C/C++ | ~3 700 real CVEs | MIT | Real-world |

Datasets are **not** vendored. `benchmarks/datasets/fetch.sh` clones each
into `benchmarks/datasets/<name>/` on demand.

## Layout

```
benchmarks/
├── harness/        # runner code (Python)
│   ├── runner.py
│   ├── ground_truth.py
│   ├── metrics.py
│   └── adapters/   # one adapter per dataset
├── datasets/       # gitignored, populated by fetch.sh
│   └── fetch.sh
├── results/        # gitignored; per-run JSON + Markdown
└── README.md
```

## Quick start

```bash
make benchmark                                # all datasets, all scanners
make benchmark DATASET=owasp_benchmark        # just one dataset
make benchmark SCANNERS=semgrep,bandit        # scanner subset
```

The harness emits two artifacts under `benchmarks/results/<timestamp>/`:

* `raw.json`     — every prediction vs ground-truth pair.
* `summary.md`   — precision / recall / F1 / FP-rate per scanner per CWE.

`docs/benchmarks/latest.md` is updated symlink-style on every run so the
top of the doc tree always shows current numbers.

## Reproducibility

The runner pins:

* Scanner versions (recorded into `summary.md`).
* Dataset commit SHAs (`benchmarks/datasets/.shas`).
* Python version + key package versions.

So `make benchmark` from a fresh clone produces matching numbers — that's
the whole point of publishing them.
