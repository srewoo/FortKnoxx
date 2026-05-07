.PHONY: up down logs build rebuild ps shell-backend shell-frontend benchmark clean

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

build:
	docker compose build

rebuild:
	docker compose build --no-cache

ps:
	docker compose ps

shell-backend:
	docker compose exec backend /bin/bash

shell-frontend:
	docker compose exec frontend /bin/sh

# OWASP Benchmark + Juliet + SecurityEval + BigVul harness.
# Override with: make benchmark DATASETS=owasp_benchmark SCANNERS=semgrep
DATASETS  ?= owasp_benchmark,juliet_java,security_eval,bigvul
SCANNERS  ?= semgrep,bandit,gosec

benchmark-fetch:
	./benchmarks/datasets/fetch.sh

benchmark: benchmark-fetch
	cd backend && venv/bin/python -m benchmarks.harness.runner \
	    --datasets="$(DATASETS)" --scanners="$(SCANNERS)" \
	|| python3 -m benchmarks.harness.runner \
	    --datasets="$(DATASETS)" --scanners="$(SCANNERS)"

clean:
	docker compose down -v
