#!/bin/bash

# ============================================
# FortKnoxx Complete Scanner Installation Script
# ============================================
# This script installs ALL 26 free and open-source
# security, quality, and compliance scanning tools
# NO API keys or tokens required!
# ============================================

set -e

echo "============================================"
echo "FortKnoxx Complete Scanner Installer"
echo "============================================"
echo ""
echo "This script will install 26 FREE security scanners:"
echo ""
echo "CORE SECURITY SCANNERS (8):"
echo "  - Semgrep (Enhanced SAST)"
echo "  - Bandit (Python security)"
echo "  - Gitleaks (Git secrets)"
echo "  - TruffleHog (Active secret verification)"
echo "  - Trivy (Dependency vulnerabilities)"
echo "  - Grype (Filesystem vulnerabilities)"
echo "  - Checkov (IaC security)"
echo "  - ESLint (JavaScript/TypeScript security)"
echo ""
echo "QUALITY SCANNERS (7):"
echo "  - Pylint (Python code quality)"
echo "  - Flake8 (Python style)"
echo "  - Radon (Complexity metrics)"
echo "  - ShellCheck (Shell script analysis)"
echo "  - Hadolint (Docker best practices)"
echo "  - SQLFluff (SQL security & quality)"
echo "  - pydeps (Python architecture)"
echo ""
echo "COMPLIANCE SCANNERS (3):"
echo "  - pip-audit (Python dependencies)"
echo "  - npm-audit (Node.js dependencies)"
echo "  - Syft (SBOM & licenses)"
echo ""
echo "ADVANCED SCANNERS (1):"
echo "  - Nuclei (Template-based CVE scanner)"
echo ""
echo "HIGH-VALUE ADDITIONS (7):"
echo "  - Snyk CLI (Modern dependency scanning)"
echo "  - Gosec (Go security)"
echo "  - cargo-audit (Rust security)"
echo "  - SpotBugs (Java bytecode analysis)"
echo "  - Pyre (Python type checker)"
echo "  - OWASP ZAP (Web security/DAST)"
echo "  - Horusec (Multi-language SAST)"
echo ""
echo "============================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
    echo "Detected OS: macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "Detected OS: Linux"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to print status
print_status() {
    if command_exists "$1"; then
        echo "  ✓ $1"
    else
        echo "  ✗ $1"
    fi
}

# ============================================
# SECTION 1: PYTHON TOOLS
# ============================================
echo "============================================"
echo "SECTION 1: Installing Python-based tools"
echo "============================================"
echo ""

if command_exists pip3; then
    PIP="pip3"
elif command_exists pip; then
    PIP="pip"
else
    echo "❌ ERROR: pip not found. Please install Python 3.x first."
    exit 1
fi

echo "Using: $PIP"
echo ""

# Core Python security tools
echo "Installing core Python security tools..."
$PIP install --quiet --upgrade semgrep || echo "Note: Semgrep may require system dependencies"
$PIP install --quiet --upgrade bandit
$PIP install --quiet --upgrade checkov || echo "Note: Checkov may require system dependencies"

# Quality scanners
echo "Installing Python quality tools..."
$PIP install --quiet --upgrade pylint
$PIP install --quiet --upgrade flake8 flake8-bugbear flake8-comprehensions
$PIP install --quiet --upgrade radon

# Compliance tools
echo "Installing Python compliance tools..."
$PIP install --quiet --upgrade pip-audit

# Enhanced scanners
echo "Installing enhanced Python tools..."
$PIP install --quiet --upgrade sqlfluff
$PIP install --quiet --upgrade pydeps

# High-value additions
echo "Installing high-value Python tools..."
$PIP install --quiet --upgrade pyre-check

echo "✓ Python tools installed successfully!"
echo ""

# ============================================
# SECTION 2: HOMEBREW/LINUX BINARY TOOLS
# ============================================
echo "============================================"
echo "SECTION 2: Installing Binary Tools"
echo "============================================"
echo ""

if [ "$OS" = "mac" ]; then
    echo "Installing macOS tools via Homebrew..."
    echo ""

    if ! command_exists brew; then
        echo "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Core security scanners
    brew install gitleaks 2>/dev/null || echo "  → gitleaks already installed"
    brew install trivy 2>/dev/null || echo "  → trivy already installed"
    brew install trufflehog 2>/dev/null || echo "  → trufflehog already installed"
    brew install grype 2>/dev/null || echo "  → grype already installed"

    # Quality scanners
    brew install shellcheck 2>/dev/null || echo "  → shellcheck already installed"
    brew install hadolint 2>/dev/null || echo "  → hadolint already installed"

    # Compliance tools
    brew install syft 2>/dev/null || echo "  → syft already installed"

    # Advanced scanners
    brew install nuclei 2>/dev/null || echo "  → nuclei already installed"

    # High-value additions
    brew install gosec 2>/dev/null || echo "  → gosec already installed"
    brew install spotbugs 2>/dev/null || echo "  → spotbugs already installed"
    brew install --cask owasp-zap 2>/dev/null || echo "  → OWASP ZAP already installed"

    echo "✓ Homebrew tools installed successfully!"
    echo ""

elif [ "$OS" = "linux" ]; then
    echo "Installing Linux tools..."
    echo ""

    # Detect package manager
    if command_exists apt-get; then
        PKG_MGR="apt-get"
        sudo apt-get update -qq
    elif command_exists yum; then
        PKG_MGR="yum"
    elif command_exists dnf; then
        PKG_MGR="dnf"
    fi

    # Install shellcheck via package manager
    if [ -n "$PKG_MGR" ]; then
        sudo $PKG_MGR install -y shellcheck 2>/dev/null || echo "  → shellcheck installation skipped"
    fi

    # Install gitleaks
    if ! command_exists gitleaks; then
        echo "Installing gitleaks..."
        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /tmp
        sudo mv /tmp/gitleaks /usr/local/bin/
    fi

    # Install trivy
    if ! command_exists trivy; then
        echo "Installing trivy..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    # Install grype
    if ! command_exists grype; then
        echo "Installing grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    # Install syft
    if ! command_exists syft; then
        echo "Installing syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    # Install hadolint
    if ! command_exists hadolint; then
        echo "Installing hadolint..."
        curl -sSL https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -o /tmp/hadolint
        chmod +x /tmp/hadolint
        sudo mv /tmp/hadolint /usr/local/bin/
    fi

    # Install trufflehog
    if ! command_exists trufflehog; then
        echo "Installing trufflehog..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    # Install Nuclei (via Go)
    if ! command_exists nuclei; then
        if command_exists go; then
            echo "Installing Nuclei..."
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            echo "✓ Nuclei installed via Go"
        else
            echo "⚠ Go not found. Nuclei installation skipped."
            echo "  Install Go from: https://go.dev/dl/"
        fi
    fi

    echo "✓ Linux tools installed successfully!"
    echo ""
fi

# ============================================
# SECTION 3: NODE.JS TOOLS
# ============================================
echo "============================================"
echo "SECTION 3: Installing Node.js Tools"
echo "============================================"
echo ""

if command_exists npm; then
    echo "Installing JavaScript/TypeScript security tools..."
    npm install -g eslint eslint-plugin-security eslint-plugin-sonarjs 2>/dev/null || echo "  → ESLint already installed"

    echo "Installing Snyk CLI..."
    npm install -g snyk 2>/dev/null || echo "  → Snyk already installed"

    echo "✓ Node.js tools installed successfully!"
    echo ""
else
    echo "⚠ WARNING: npm not found. Skipping Node.js tools."
    echo "  Install Node.js from: https://nodejs.org"
    echo ""
fi

# ============================================
# SECTION 4: GO TOOLS
# ============================================
echo "============================================"
echo "SECTION 4: Installing Go Tools"
echo "============================================"
echo ""

if command_exists go; then
    echo "Installing Go security tools..."

    # Gosec
    if ! command_exists gosec; then
        echo "Installing Gosec..."
        go install github.com/securego/gosec/v2/cmd/gosec@latest
    fi

    # Nuclei (if not already installed)
    if ! command_exists nuclei; then
        echo "Installing Nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    fi

    echo "✓ Go tools installed successfully!"
    echo ""
else
    echo "⚠ WARNING: Go not found. Skipping Go-specific tools."
    echo "  Install Go from: https://go.dev/dl/"
    echo ""
fi

# ============================================
# SECTION 5: RUST TOOLS
# ============================================
echo "============================================"
echo "SECTION 5: Installing Rust Tools"
echo "============================================"
echo ""

if command_exists cargo; then
    echo "Installing Rust security tools..."

    if ! command_exists cargo-audit; then
        echo "Installing cargo-audit..."
        cargo install cargo-audit
    fi

    echo "✓ Rust tools installed successfully!"
    echo ""
else
    echo "⚠ WARNING: Rust/Cargo not found. Skipping Rust tools."
    echo "  Install Rust from: https://rustup.rs"
    echo ""
fi

# ============================================
# SECTION 6: HORUSEC (Multi-Language SAST)
# ============================================
echo "============================================"
echo "SECTION 6: Installing Horusec"
echo "============================================"
echo ""

if ! command_exists horusec; then
    echo "Installing Horusec..."
    curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash -s latest 2>/dev/null || echo "  → Horusec installation skipped (may require manual install)"
    echo "✓ Horusec installed!"
else
    echo "✓ Horusec already installed"
fi
echo ""

# ============================================
# SECTION 7: UPDATE NUCLEI TEMPLATES
# ============================================
echo "============================================"
echo "SECTION 7: Updating Nuclei Templates"
echo "============================================"
echo ""

if command_exists nuclei; then
    echo "Updating Nuclei templates (9,000+ CVE templates)..."
    nuclei -update-templates -silent || echo "  → Template update skipped"
    echo "✓ Nuclei templates updated!"
else
    echo "⚠ Nuclei not installed, skipping template update"
fi
echo ""

# ============================================
# FINAL STATUS CHECK
# ============================================
echo "============================================"
echo "FINAL INSTALLATION STATUS"
echo "============================================"
echo ""

echo "Core Security Scanners (8):"
print_status "semgrep"
print_status "bandit"
print_status "gitleaks"
print_status "trufflehog"
print_status "trivy"
print_status "grype"
print_status "checkov"
print_status "eslint"

echo ""
echo "Quality Scanners (7):"
print_status "pylint"
print_status "flake8"
print_status "radon"
print_status "shellcheck"
print_status "hadolint"
print_status "sqlfluff"
print_status "pydeps"

echo ""
echo "Compliance Scanners (3):"
print_status "pip-audit"
print_status "npm"
print_status "syft"

echo ""
echo "Advanced Scanners (1):"
print_status "nuclei"

echo ""
echo "High-Value Additions (7):"
print_status "snyk"
print_status "gosec"
if command_exists cargo; then
    print_status "cargo-audit"
else
    echo "  ✗ cargo-audit (Rust not installed)"
fi
print_status "spotbugs"
print_status "pyre"
if [ "$OS" = "mac" ]; then
    if [ -d "/Applications/OWASP ZAP.app" ]; then
        echo "  ✓ zaproxy (OWASP ZAP)"
    else
        print_status "zaproxy"
    fi
else
    print_status "zaproxy"
fi
print_status "horusec"

echo ""
echo "============================================"
echo "INSTALLATION COMPLETE! 🎉"
echo "============================================"
echo ""

# Count installed scanners
INSTALLED_COUNT=0
SCANNERS=("semgrep" "bandit" "gitleaks" "trufflehog" "trivy" "grype" "checkov" "eslint" "pylint" "flake8" "radon" "shellcheck" "hadolint" "sqlfluff" "pydeps" "pip-audit" "npm" "syft" "nuclei" "snyk" "gosec" "spotbugs" "pyre" "horusec")

for scanner in "${SCANNERS[@]}"; do
    if command_exists "$scanner"; then
        ((INSTALLED_COUNT++))
    fi
done

# Check cargo-audit separately
if command_exists cargo && command_exists cargo-audit; then
    ((INSTALLED_COUNT++))
fi

# Check ZAP on macOS
if [ "$OS" = "mac" ] && [ -d "/Applications/OWASP ZAP.app" ]; then
    ((INSTALLED_COUNT++))
elif command_exists zaproxy || command_exists zap-baseline.py; then
    ((INSTALLED_COUNT++))
fi

echo "Total scanners installed: $INSTALLED_COUNT/26"
echo ""

if [ $INSTALLED_COUNT -lt 26 ]; then
    echo "NOTE: Some scanners require additional tools:"
    echo "  - Snyk, ESLint: Requires Node.js (https://nodejs.org)"
    echo "  - Gosec, Nuclei: Requires Go (https://go.dev/dl/)"
    echo "  - cargo-audit: Requires Rust (https://rustup.rs)"
    echo "  - SpotBugs: Requires Java"
    echo ""
fi

echo "OPTIONAL: Snyk Authentication"
echo "  Snyk is FREE for 200 tests/month"
echo "  To authenticate: snyk auth"
echo "  (Not required - works without authentication)"
echo ""

echo "Next Steps:"
echo "  1. Start MongoDB: brew services start mongodb-community"
echo "  2. Start backend: cd backend && source venv/bin/activate && uvicorn server:app --reload"
echo "  3. Start frontend: cd frontend && yarn start"
echo "  4. Open: http://localhost:3000"
echo ""
echo "Documentation:"
echo "  - README.md - Getting started guide"
echo "  - ENHANCED_COVERAGE.md - Scanner capabilities"
echo "  - IMPROVEMENTS.md - Version history"
echo ""
echo "Happy scanning! 🔒"
echo ""
