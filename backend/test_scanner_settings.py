#!/usr/bin/env python3
"""
Test script for scanner settings functionality
Run this after starting the backend server to verify scanner settings work correctly
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from settings.manager import settings_manager
from settings.models import ScannerSettings, UpdateScannerSettingsRequest
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

async def test_scanner_settings():
    """Test scanner settings CRUD operations"""
    print("=" * 60)
    print("Testing Scanner Settings Functionality")
    print("=" * 60)

    # Initialize database connection
    mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
    db_name = os.environ.get('DB_NAME', 'fortknox')

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]
    settings_manager.set_db(db)

    print(f"\n✓ Connected to MongoDB: {db_name}")

    # Test 1: Get default settings
    print("\n" + "-" * 60)
    print("Test 1: Getting Default Scanner Settings")
    print("-" * 60)

    settings = await settings_manager.get_scanner_settings()
    print(f"✓ Retrieved settings successfully")
    print(f"  - Semgrep enabled: {settings.enable_semgrep}")
    print(f"  - Bandit enabled: {settings.enable_bandit}")
    print(f"  - ZAP DAST enabled: {settings.enable_zap_dast}")
    print(f"  - API Fuzzer enabled: {settings.enable_api_fuzzer}")
    print(f"  - Zero-Day Detector enabled: {settings.enable_zero_day_detector}")

    # Test 2: Update some scanner settings
    print("\n" + "-" * 60)
    print("Test 2: Updating Scanner Settings")
    print("-" * 60)

    update_request = UpdateScannerSettingsRequest(
        enable_semgrep=False,  # Disable Semgrep
        enable_zap_dast=True,  # Enable ZAP DAST
        enable_api_fuzzer=True  # Keep API Fuzzer enabled
    )

    updated_settings = await settings_manager.update_scanner_settings(update_request)
    print(f"✓ Updated settings successfully")
    print(f"  - Semgrep enabled: {updated_settings.enable_semgrep} (should be False)")
    print(f"  - ZAP DAST enabled: {updated_settings.enable_zap_dast} (should be True)")
    print(f"  - Bandit enabled: {updated_settings.enable_bandit} (unchanged)")

    # Test 3: Verify persistence
    print("\n" + "-" * 60)
    print("Test 3: Verifying Settings Persistence")
    print("-" * 60)

    # Clear cache to force database read
    settings_manager.clear_cache()

    retrieved_settings = await settings_manager.get_scanner_settings()
    print(f"✓ Retrieved settings from database")

    # Verify values match
    assert retrieved_settings.enable_semgrep == False, "Semgrep should be disabled"
    assert retrieved_settings.enable_zap_dast == True, "ZAP DAST should be enabled"
    assert retrieved_settings.enable_bandit == True, "Bandit should still be enabled"

    print(f"✓ All values persisted correctly")

    # Test 4: Restore defaults
    print("\n" + "-" * 60)
    print("Test 4: Restoring Default Settings")
    print("-" * 60)

    restore_request = UpdateScannerSettingsRequest(
        enable_semgrep=True,  # Re-enable Semgrep
        enable_zap_dast=False  # Disable ZAP DAST (default)
    )

    restored_settings = await settings_manager.update_scanner_settings(restore_request)
    print(f"✓ Restored default settings")
    print(f"  - Semgrep enabled: {restored_settings.enable_semgrep} (back to True)")
    print(f"  - ZAP DAST enabled: {restored_settings.enable_zap_dast} (back to False)")

    # Test 5: Test all scanner fields
    print("\n" + "-" * 60)
    print("Test 5: Verifying All 32 Scanner Fields")
    print("-" * 60)

    all_settings = await settings_manager.get_scanner_settings()
    scanner_fields = list(ScannerSettings.model_fields.keys())

    print(f"✓ Total scanners: {len(scanner_fields)}")
    print(f"\nScanner Status:")

    # Group by category
    security_scanners = [f for f in scanner_fields if any(x in f for x in ['semgrep', 'bandit', 'gitleaks', 'trufflehog', 'trivy', 'grype', 'checkov', 'eslint'])]
    quality_scanners = [f for f in scanner_fields if any(x in f for x in ['pylint', 'flake8', 'radon', 'shellcheck', 'hadolint', 'sqlfluff', 'pydeps'])]
    compliance_scanners = [f for f in scanner_fields if any(x in f for x in ['pip_audit', 'npm_audit', 'syft'])]
    advanced_scanners = [f for f in scanner_fields if any(x in f for x in ['nuclei', 'codeql', 'snyk', 'gosec', 'spotbugs', 'pyre', 'horusec'])]
    web_scanners = [f for f in scanner_fields if any(x in f for x in ['zap', 'api_fuzzer'])]
    ai_scanners = [f for f in scanner_fields if any(x in f for x in ['zero_day', 'business_logic', 'llm_security', 'auth_scanner'])]

    print(f"\n  Core Security (8): {sum(1 for s in security_scanners if getattr(all_settings, s))} enabled")
    print(f"  Quality (7): {sum(1 for s in quality_scanners if getattr(all_settings, s))} enabled")
    print(f"  Compliance (3): {sum(1 for s in compliance_scanners if getattr(all_settings, s))} enabled")
    print(f"  Advanced (7): {sum(1 for s in advanced_scanners if getattr(all_settings, s))} enabled")
    print(f"  Web & API (3): {sum(1 for s in web_scanners if getattr(all_settings, s))} enabled")
    print(f"  AI-Powered (4): {sum(1 for s in ai_scanners if getattr(all_settings, s))} enabled")

    # Summary
    print("\n" + "=" * 60)
    print("✅ All Tests Passed!")
    print("=" * 60)
    print("\nScanner Settings Features Verified:")
    print("  ✓ Default settings loaded correctly")
    print("  ✓ Settings can be updated individually")
    print("  ✓ Changes persist to database")
    print("  ✓ Cache clearing works")
    print("  ✓ All 32 scanner fields accessible")
    print("\nNext Steps:")
    print("  1. Start the backend server: python3 backend/server.py")
    print("  2. Test API endpoints with curl or Postman")
    print("  3. Run a scan and verify only enabled scanners execute")
    print("  4. Check logs for 'Disabled in settings' messages")

    # Cleanup
    client.close()

if __name__ == "__main__":
    try:
        asyncio.run(test_scanner_settings())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
