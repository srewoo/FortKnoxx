# FortKnoxx Benchmark Results

These pages turn FortKnoxx's AI scanner claims into measurable evidence.

* `latest.md` — symlink-style live document overwritten on every
  `make benchmark` run. Always reflects the current scanner stack.
* `<dataset>.md` — per-dataset breakdown, copied from the most recent
  `benchmarks/results/<timestamp>/<dataset>.md`.

How to regenerate locally:

```bash
make benchmark                                    # all datasets, default scanners
make benchmark DATASETS=owasp_benchmark           # one dataset
make benchmark SCANNERS=semgrep,bandit,gosec      # scanner subset
```

Reproducibility:

* Datasets pinned by SHA in `benchmarks/datasets/.shas`.
* Scanner versions captured in the run output.
* Pure-Python harness — no MongoDB, Redis, or LLM keys required.
