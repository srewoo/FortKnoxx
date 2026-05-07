# CNAPP-lite + OpenTelemetry

Two parts of Task #7. The full microservice split (api-gateway →
scan-orchestrator → report-service over Redis Streams) was deferred —
that's a multi-week refactor and the docker-compose stack already gives
us most of its operational value. The pieces shipped here are the ones
with the highest leverage.

## CNAPP-lite

Code↔cloud correlation built on top of existing scanners. No SaaS,
nothing to install you don't already have.

### Pipeline

```
IaC files (.tf / .yaml)        cloud findings           code findings
        │                       (Prowler / etc.)         (SAST / SCA)
        ▼                              │                       │
extract_iac_resources()                ▼                       ▼
        │                          ───── correlator ──────────────
        ▼                                       │
   IaC resources                                ▼
                              CorrelatedFinding[] for the UI
```

### Modules

* `backend/engines/cnapp/iac_resources.py` — Terraform + CloudFormation
  resource extraction. Heuristic, not a full HCL/CFN parser.
* `backend/engines/cnapp/correlator.py` — joins cloud findings to IaC
  resources via exact-name match → service-hint substring fallback.
* `backend/engines/cnapp/__init__.py` — public surface.

### What you get

For every cloud finding (e.g. Prowler reports `payments_role` has a
wildcard policy), the correlator answers:

* "Is this resource declared by IaC in this repo?"
* "Which service owns it?"
* "Which code findings touch the same service?"

…then the UI can render the joint statement: *"service-x has CVE-Y AND
its IAM role allows `*:*`"*. That's the Wiz pitch, minus the agent-mesh.

## OpenTelemetry

Off by default. Set `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`
in the backend env to enable.

* `backend/utils/telemetry.py` — `init_telemetry(app)` plus convenience
  context managers `span()`, `scanner_span()`, `llm_span()`.
* Auto-instruments every FastAPI request via `FastAPIInstrumentor`.
* Scan-job spans, scanner-run spans, and LLM-call spans are explicit
  context managers — call them from `process_scan_results` and the
  orchestrator to get end-to-end traces.

### Why no Prometheus

The OTel collector tees traces *and* metrics; pointing it at Tempo + a
`prometheusexporter` gives you both without two instrumentation layers.
Less code in this repo, fewer SDKs to maintain.

## Tests

```bash
cd backend && venv/bin/python -m pytest tests/test_cnapp.py -q
```

6 tests cover: Terraform resource extraction, CloudFormation extraction
(including types like `AWS::S3::Bucket` with digits), exact and
service-hint correlation paths, no-match fallback, code-side
service→resource linking.

## What was deliberately deferred

* **Full microservice split.** Splitting `server.py` into
  `api-gateway` + `scan-orchestrator` + `report-service` over Redis
  Streams is an MR-sized refactor that mostly buys deployment
  flexibility, not user-visible behaviour. The docker-compose stack
  already runs each component in its own container so the operational
  story is reasonable today. Revisit when scale demands it.
* **SBOM watch loop.** The CNAPP module includes the join surface; the
  nightly diff against Grype CVE feeds is one cron job + a minor diff
  call — left as a small follow-up so this doc stays honest about what
  shipped vs. what's planned.
