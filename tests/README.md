# FortKnoxx Scanner Tests

This directory contains test scripts for validating FortKnoxx security scanners.

## Test Scripts

### test_scanner.py

Comprehensive test suite that validates all FortKnoxx security scanners by running them against a deliberately vulnerable test repository.

#### Features

- Tests 8 security scanners:
  - **Semgrep**: Multi-language SAST scanner
  - **Bandit**: Python security scanner
  - **ShellCheck**: Shell script analysis
  - **Hadolint**: Dockerfile linter
  - **Gosec**: Go security scanner
  - **Gitleaks**: Secret detection
  - **SQLFluff**: SQL linting
  - **Checkov**: Infrastructure-as-Code scanner

- Validates each scanner:
  - Checks if scanner is installed
  - Runs scanner on vulnerable test repository
  - Verifies scanner output can be parsed
  - Reports number of issues found
  - Provides detailed error messages on failures

#### Usage

```bash
# Run all scanner tests
python3 tests/test_scanner.py

# Run with verbose output
python3 tests/test_scanner.py --verbose

# Test specific scanner
python3 tests/test_scanner.py --scanner semgrep

# Use custom test repository
python3 tests/test_scanner.py --repo /path/to/test/repo

# Show help
python3 tests/test_scanner.py --help
```

#### Example Output

```
======================================================================
    FortKnoxx Scanner Validation Test Suite
======================================================================

Test Repository: /tmp/vulnerable-test-app
Running 8 scanner(s)...

Testing Semgrep...
✅ Semgrep              :   50 issues (min: 40) ✅
Testing Bandit...
✅ Bandit               :   15 issues (min: 10) ✅
Testing ShellCheck...
✅ ShellCheck           :   11 issues (min: 5) ✅
Testing Hadolint...
✅ Hadolint             :    8 issues (min: 5) ✅
Testing Gosec...
✅ Gosec                :    8 issues (min: 5) ✅
Testing Gitleaks...
✅ Gitleaks             :    0 issues (min: 0) ✅
Testing SQLFluff...
✅ SQLFluff             :    0 issues (min: 0) ✅
Testing Checkov...
✅ Checkov              :    0 issues (min: 0) ✅

======================================================================
                         TEST SUMMARY
======================================================================

Total Scanners Tested: 8
Passed: 8
Total Issues Found: 92

======================================================================

✅ ALL SCANNERS WORKING CORRECTLY! ✅
```

#### Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed

#### Requirements

- Python 3.7+
- All security scanners must be installed (see `install_all_scanners.sh`)
- Vulnerable test repository at `/tmp/vulnerable-test-app` (or custom path)

#### Test Repository

The script expects a test repository with intentional vulnerabilities. The default location is `/tmp/vulnerable-test-app`. This repository should contain:

- Python files with security issues (for Semgrep, Bandit)
- Shell scripts with problems (for ShellCheck)
- Dockerfile with misconfigurations (for Hadolint)
- Go files with security issues (for Gosec)
- SQL files with style issues (for SQLFluff)
- Kubernetes/IaC files (for Checkov)
- Hardcoded secrets (for Gitleaks)

#### CI/CD Integration

This test script can be integrated into CI/CD pipelines:

```bash
# Run in CI
python3 tests/test_scanner.py || exit 1
```

#### Troubleshooting

**Scanner not found errors:**
- Run `install_all_scanners.sh` to install all scanners

**Test repository not found:**
- Create the vulnerable test repository first
- Or specify custom path with `--repo`

**Parser errors:**
- Check scanner output format hasn't changed
- Verify scanner version compatibility

## Adding New Scanner Tests

To add a new scanner test:

1. Add a new test method to the `ScannerValidator` class:
   ```python
   def test_new_scanner(self) -> ScannerResult:
       """Test NewScanner"""
       self.log("Testing NewScanner...", "INFO")

       if not self.check_scanner_installed("newscanner"):
           return ScannerResult("NewScanner", False, 0, 5, "Scanner not installed")

       # Run scanner and parse results
       # ...

       return ScannerResult(
           "NewScanner",
           success,
           issues_found,
           expected_min,
           error_message,
           details
       )
   ```

2. Add the scanner to the `run_all_tests` method:
   ```python
   scanners = {
       # ... existing scanners ...
       "newscanner": self.test_new_scanner,
   }
   ```

3. Test the new scanner:
   ```bash
   python3 tests/test_scanner.py --scanner newscanner --verbose
   ```

## License

Part of FortKnoxx Security Scanner Platform
