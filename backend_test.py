#!/usr/bin/env python3
"""
Security Intelligence Platform Backend API Tests
Tests all backend endpoints for functionality and integration
"""

import requests
import json
import time
import sys
from datetime import datetime

class SecurityPlatformTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        self.repo_id = None
        self.scan_id = None
        self.vulnerability_id = None

    def log_test(self, name, success, details="", expected_status=None, actual_status=None):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            print(f"❌ {name} - {details}")
            if expected_status and actual_status:
                print(f"   Expected: {expected_status}, Got: {actual_status}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def test_api_health(self):
        """Test API health endpoint"""
        try:
            response = requests.get(f"{self.api_url}/", timeout=10)
            success = response.status_code == 200
            self.log_test("API Health Check", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            if success:
                data = response.json()
                print(f"   API Version: {data.get('version', 'Unknown')}")
            return success
        except Exception as e:
            self.log_test("API Health Check", False, f"Connection error: {str(e)}")
            return False

    def test_create_repository(self):
        """Test repository creation"""
        try:
            # Use a small public repository for testing
            repo_data = {
                "name": "test-security-repo",
                "url": "https://github.com/octocat/Hello-World",
                "access_token": "dummy_token_for_public_repo",
                "branch": "master"
            }
            
            response = requests.post(f"{self.api_url}/repositories", 
                                   json=repo_data, timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                self.repo_id = data.get('id')
                print(f"   Created repository ID: {self.repo_id}")
            
            self.log_test("Create Repository", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Create Repository", False, f"Error: {str(e)}")
            return False

    def test_list_repositories(self):
        """Test repository listing"""
        try:
            response = requests.get(f"{self.api_url}/repositories", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   Found {len(data)} repositories")
            
            self.log_test("List Repositories", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("List Repositories", False, f"Error: {str(e)}")
            return False

    def test_get_repository(self):
        """Test get single repository"""
        if not self.repo_id:
            self.log_test("Get Repository", False, "No repository ID available")
            return False
        
        try:
            response = requests.get(f"{self.api_url}/repositories/{self.repo_id}", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   Repository: {data.get('name', 'Unknown')}")
            
            self.log_test("Get Repository", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Get Repository", False, f"Error: {str(e)}")
            return False

    def test_start_scan(self):
        """Test starting a security scan"""
        if not self.repo_id:
            self.log_test("Start Scan", False, "No repository ID available")
            return False
        
        try:
            response = requests.post(f"{self.api_url}/scans/{self.repo_id}", timeout=30)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                self.scan_id = data.get('scan_id')
                print(f"   Started scan ID: {self.scan_id}")
                print(f"   Status: {data.get('status', 'Unknown')}")
            
            self.log_test("Start Scan", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Start Scan", False, f"Error: {str(e)}")
            return False

    def test_get_scans(self):
        """Test getting scan history"""
        if not self.repo_id:
            self.log_test("Get Scans", False, "No repository ID available")
            return False
        
        try:
            response = requests.get(f"{self.api_url}/scans/{self.repo_id}", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   Found {len(data)} scans")
                if data:
                    latest_scan = data[0]
                    print(f"   Latest scan status: {latest_scan.get('status', 'Unknown')}")
            
            self.log_test("Get Scans", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Get Scans", False, f"Error: {str(e)}")
            return False

    def test_get_scan_detail(self):
        """Test getting scan details"""
        if not self.scan_id:
            self.log_test("Get Scan Detail", False, "No scan ID available")
            return False
        
        try:
            response = requests.get(f"{self.api_url}/scans/detail/{self.scan_id}", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   Scan status: {data.get('status', 'Unknown')}")
                print(f"   Vulnerabilities: {data.get('vulnerabilities_count', 0)}")
            
            self.log_test("Get Scan Detail", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Get Scan Detail", False, f"Error: {str(e)}")
            return False

    def test_get_vulnerabilities(self):
        """Test getting vulnerabilities"""
        if not self.scan_id:
            self.log_test("Get Vulnerabilities", False, "No scan ID available")
            return False
        
        try:
            response = requests.get(f"{self.api_url}/vulnerabilities/{self.scan_id}", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   Found {len(data)} vulnerabilities")
                if data:
                    self.vulnerability_id = data[0].get('id')
                    print(f"   Sample vulnerability: {data[0].get('title', 'Unknown')}")
            
            self.log_test("Get Vulnerabilities", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Get Vulnerabilities", False, f"Error: {str(e)}")
            return False

    def test_owasp_categories(self):
        """Test OWASP categories endpoint"""
        try:
            response = requests.get(f"{self.api_url}/owasp/categories", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   OWASP categories: {len(data)}")
            
            self.log_test("OWASP Categories", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("OWASP Categories", False, f"Error: {str(e)}")
            return False

    def test_ai_fix_recommendation(self):
        """Test AI fix recommendation"""
        if not self.vulnerability_id:
            self.log_test("AI Fix Recommendation", False, "No vulnerability ID available")
            return False
        
        try:
            ai_request = {
                "vulnerability_id": self.vulnerability_id,
                "provider": "anthropic",
                "model": "claude-4-sonnet-20250514"
            }
            
            response = requests.post(f"{self.api_url}/ai/fix-recommendation", 
                                   json=ai_request, timeout=60)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   AI Provider: {data.get('provider', 'Unknown')}")
                print(f"   Model: {data.get('model', 'Unknown')}")
                recommendation = data.get('recommendation', '')
                print(f"   Recommendation length: {len(recommendation)} chars")
            
            self.log_test("AI Fix Recommendation", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("AI Fix Recommendation", False, f"Error: {str(e)}")
            return False

    def test_repository_stats(self):
        """Test repository statistics"""
        if not self.repo_id:
            self.log_test("Repository Stats", False, "No repository ID available")
            return False
        
        try:
            response = requests.get(f"{self.api_url}/stats/{self.repo_id}", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                if 'message' in data:
                    print(f"   {data['message']}")
                else:
                    print(f"   Security score: {data.get('security_score', 'N/A')}")
                    print(f"   Total vulnerabilities: {data.get('total_vulnerabilities', 0)}")
            
            self.log_test("Repository Stats", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Repository Stats", False, f"Error: {str(e)}")
            return False

    def test_generate_report(self):
        """Test report generation"""
        if not self.repo_id or not self.scan_id:
            self.log_test("Generate Report", False, "Missing repository or scan ID")
            return False
        
        try:
            report_request = {
                "repo_id": self.repo_id,
                "scan_id": self.scan_id,
                "format": "json"
            }
            
            response = requests.post(f"{self.api_url}/reports/generate", 
                                   json=report_request, timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                print(f"   Report contains: {len(data.get('vulnerabilities', []))} vulnerabilities")
            
            self.log_test("Generate Report", success, 
                         f"Status: {response.status_code}", 200, response.status_code)
            return success
        except Exception as e:
            self.log_test("Generate Report", False, f"Error: {str(e)}")
            return False

    def wait_for_scan_completion(self, max_wait=120):
        """Wait for scan to complete"""
        if not self.scan_id:
            return False
        
        print(f"\n⏳ Waiting for scan {self.scan_id} to complete...")
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = requests.get(f"{self.api_url}/scans/detail/{self.scan_id}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    status = data.get('status', 'unknown')
                    print(f"   Scan status: {status}")
                    
                    if status == "completed":
                        print(f"   ✅ Scan completed in {int(time.time() - start_time)} seconds")
                        return True
                    elif status == "failed":
                        print(f"   ❌ Scan failed")
                        return False
                
                time.sleep(10)  # Wait 10 seconds before checking again
            except Exception as e:
                print(f"   Error checking scan status: {str(e)}")
                time.sleep(5)
        
        print(f"   ⏰ Scan timeout after {max_wait} seconds")
        return False

    def run_all_tests(self):
        """Run all backend tests"""
        print("🚀 Starting Security Intelligence Platform Backend Tests")
        print(f"🔗 Testing API at: {self.api_url}")
        print("=" * 60)
        
        # Basic API tests
        if not self.test_api_health():
            print("❌ API health check failed - stopping tests")
            return self.get_results()
        
        # Repository management tests
        self.test_create_repository()
        self.test_list_repositories()
        self.test_get_repository()
        
        # Scanning tests
        self.test_start_scan()
        self.test_get_scans()
        self.test_get_scan_detail()
        
        # Wait for scan to complete (for a small repo, this should be quick)
        scan_completed = self.wait_for_scan_completion(max_wait=180)
        
        # Vulnerability and analysis tests
        self.test_get_vulnerabilities()
        self.test_owasp_categories()
        
        # AI and reporting tests (only if we have vulnerabilities)
        if self.vulnerability_id:
            self.test_ai_fix_recommendation()
        
        self.test_repository_stats()
        self.test_generate_report()
        
        return self.get_results()

    def get_results(self):
        """Get test results summary"""
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} passed ({success_rate:.1f}%)")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
        else:
            print("⚠️  Some tests failed - check logs above")
        
        return {
            "total_tests": self.tests_run,
            "passed_tests": self.tests_passed,
            "success_rate": success_rate,
            "test_details": self.test_results,
            "repo_id": self.repo_id,
            "scan_id": self.scan_id,
            "vulnerability_id": self.vulnerability_id
        }

def main():
    """Main test execution"""
    tester = SecurityPlatformTester()
    results = tester.run_all_tests()
    
    # Return appropriate exit code
    return 0 if results["success_rate"] == 100 else 1

if __name__ == "__main__":
    sys.exit(main())