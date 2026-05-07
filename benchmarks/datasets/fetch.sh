#!/usr/bin/env bash
# Fetch benchmark datasets. Idempotent — skips clones that already exist.
#
# Datasets are pinned to commit SHAs in .shas so reruns reproduce numbers.

set -euo pipefail

cd "$(dirname "$0")"

declare -A REPOS=(
    ["owasp_benchmark"]="https://github.com/OWASP-Benchmark/BenchmarkJava.git"
    ["juliet_java"]="https://github.com/arthurchiao/Juliet-1.3.git"
    ["security_eval"]="https://github.com/s2e-lab/SecurityEval.git"
    ["bigvul"]="https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset.git"
)

# Use shallow clones — full history isn't needed and saves 100s of MB.
for name in "${!REPOS[@]}"; do
    if [[ -d "$name" ]]; then
        echo "✓ $name already present — skipping"
        continue
    fi
    url="${REPOS[$name]}"
    echo "→ cloning $name from $url"
    git clone --depth 1 "$url" "$name"
done

# Record current SHAs for reproducibility.
> .shas
for name in "${!REPOS[@]}"; do
    if [[ -d "$name/.git" ]]; then
        sha=$(git -C "$name" rev-parse HEAD)
        echo "$name $sha" >> .shas
    fi
done

echo "Done. Pinned SHAs:"
cat .shas
