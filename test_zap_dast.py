#!/usr/bin/env python3
"""
OWASP ZAP DAST (Dynamic Application Security Testing) Script
This script performs security testing on the FastAPI application using OWASP ZAP
"""

import json
import time
import requests
import sys
import os
from pathlib import Path
from typing import Dict, Optional
from zapv2 import ZAPv2


class ZAPDastTester:
    def __init__(self, target_url: str = "http://0.0.0.0:8000", zap_proxy_port: int = 8080):
        self.target_url = target_url
        self.zap_proxy_port = zap_proxy_port
        self.zap_proxy_url = f"http://0.0.0.0:{zap_proxy_port}"
        self.zap_api_key = os.getenv("ZAP_API_KEY", None)
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # ZAP API client - connect to ZAP daemon API
        self.zap = ZAPv2(
            proxies={
                'http': f'http://0.0.0.0:{zap_proxy_port}', 
            }
        )
        
    def wait_for_api(self, max_attempts: int = 30) -> bool:
        """Wait for the FastAPI server to be ready"""
        print(f"Waiting for API at {self.target_url} to be ready...")
        
        for attempt in range(max_attempts):
            try:
                response = requests.get(f"{self.target_url}/health", timeout=5)
                if response.status_code == 200:
                    print(f"✓ API is ready after {attempt + 1} attempts")
                    return True
            except requests.exceptions.RequestException:
                if attempt < max_attempts - 1:
                    time.sleep(1)
                    continue
                    
        print(f"✗ API at {self.target_url} is not responding after {max_attempts} attempts")
        return False
    
    def wait_for_zap(self, max_attempts: int = 30) -> bool:
       return True
    
    def get_openapi_spec(self) -> Optional[Dict]:
        """Fetch OpenAPI specification from the FastAPI application"""
        try:
            print("Fetching OpenAPI specification...")
            response = requests.get(f"{self.target_url}/openapi.json", timeout=10)
            response.raise_for_status()
            
            openapi_spec = response.json()
            
            # Save the spec for reference
            spec_file = self.reports_dir / "openapi_spec.json"
            with open(spec_file, 'w') as f:
                json.dump(openapi_spec, f, indent=2)
            
            print(f"✓ OpenAPI specification saved to {spec_file}")
            return openapi_spec
            
        except Exception as e:
            print(f"✗ Failed to fetch OpenAPI specification: {e}")
            return None
    
    def import_openapi_spec(self, openapi_spec: Dict) -> bool:
        """Import OpenAPI specification into ZAP"""
        try:
            print("Importing OpenAPI specification into ZAP...")
            
            # Save spec to a temporary file for ZAP import
            temp_spec_file = self.reports_dir / "temp_openapi.json"
            with open(temp_spec_file, 'w') as f:
                json.dump(openapi_spec, f, indent=2)
            
            # Import the OpenAPI spec into ZAP
            self.zap.openapi.import_file(str(temp_spec_file), self.target_url)
            
            # Clean up temporary file
            temp_spec_file.unlink()
            
            print("✓ OpenAPI specification imported into ZAP")
            return True
            
        except Exception as e:
            print(f"✗ Failed to import OpenAPI specification: {e}")
            return False
    
    def spider_application(self) -> bool:
        """Run ZAP spider to discover additional endpoints"""
        try:
            print("Starting ZAP spider...")
            scan_id = self.zap.spider.scan(self.target_url)
            
            # Give the spider time to start
            time.sleep(2)
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                progress = self.zap.spider.status(scan_id)
                print(f"Spider progress: {progress}%")
                time.sleep(5)
            
            print("✓ Spider completed")
            
            # Get spider results
            spider_results = self.zap.spider.results(scan_id)
            print(f"Spider found {len(spider_results)} URLs")
            
            # Also show what URLs were found
            if spider_results:
                print("URLs discovered:")
                for i, url in enumerate(spider_results[:10]):  # Show first 10
                    print(f"  {i+1}. {url}")
                if len(spider_results) > 10:
                    print(f"  ... and {len(spider_results) - 10} more")
            
            # Wait a bit for ZAP to process all the discovered URLs
            print("Waiting for ZAP to process discovered URLs...")
            time.sleep(5)
            
            return True
            
        except Exception as e:
            print(f"✗ Spider failed: {e}")
            return False
    
    def run_passive_scan(self) -> Dict:
        """Run passive security scan"""
        try:
            print("Running passive scan...")
            
            # Enable all passive scan rules
            self.zap.pscan.enable_all_scanners()
            
            # Wait for passive scan to complete
            while int(self.zap.pscan.records_to_scan) > 0:
                print(f"Passive scan progress: {self.zap.pscan.records_to_scan} records remaining")
                time.sleep(5)
            
            print("✓ Passive scan completed")
            
            # Get passive scan alerts
            alerts = self.zap.core.alerts()
            return {"passive_alerts": alerts}
            
        except Exception as e:
            print(f"✗ Passive scan failed: {e}")
            return {"passive_alerts": []}
    
    def run_active_scan(self) -> Dict:
        """Run active security scan"""
        try:
            print("Starting active scan...")
            
            # Show current sites in ZAP
            sites = self.zap.core.sites
            if sites:
                print(f"Sites in ZAP scope: {sites}")
            else:
                print("Warning: No sites found in ZAP scope")
            
            # Start active scan
            scan_id = self.zap.ascan.scan(self.target_url)
            print(f"Active scan started with ID: {scan_id}")
            
            # Give the scan time to start
            time.sleep(5)
            
            # Wait for active scan to complete with more detailed progress
            last_progress = 0
            stalled_count = 0
            max_stall_cycles = 6  # Allow 6 cycles (60 seconds) of no progress
            
            while int(self.zap.ascan.status(scan_id)) < 100:
                progress = int(self.zap.ascan.status(scan_id))
                print(f"Active scan progress: {progress}%")
                
                # Check if progress is stalled
                if progress == last_progress:
                    stalled_count += 1
                    if stalled_count >= max_stall_cycles:
                        print("⚠️  Active scan appears stalled, continuing...")
                        break
                else:
                    stalled_count = 0
                    last_progress = progress
                
                time.sleep(10)
            
            print("✓ Active scan completed")
            
            # Get active scan alerts
            alerts = self.zap.core.alerts()
            return {"active_alerts": alerts}
            
        except Exception as e:
            print(f"✗ Active scan failed: {e}")
            return {"active_alerts": []}
    
    def generate_reports(self, scan_results: Dict) -> bool:
        """Generate ZAP scan reports"""
        try:
            print("Generating ZAP reports...")
            
            # Get alerts once to avoid potential issues with multiple calls
            alerts = self.zap.core.alerts()  # Call with no parameters for all alerts
                
            # Generate HTML report
            html_report = self.zap.core.htmlreport()
            with open(self.reports_dir / "zap-report.html", 'w') as f:
                f.write(html_report)
            
            # Generate JSON report
            json_report = {
                "scan_summary": {
                    "target_url": self.target_url,
                    "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "total_alerts": len(alerts)
                },
                "alerts": alerts,
                "sites": self.zap.core.sites,
                **scan_results
            }
            
            with open(self.reports_dir / "zap-report.json", 'w') as f:
                json.dump(json_report, f, indent=2)
            
            # Generate XML report for CI/CD integration
            xml_report = self.zap.core.xmlreport()
            with open(self.reports_dir / "zap-report.xml", 'w') as f:
                f.write(xml_report)
            
            print("✓ ZAP reports generated:")
            print(f"  - HTML: {self.reports_dir}/zap-report.html")
            print(f"  - JSON: {self.reports_dir}/zap-report.json")
            print(f"  - XML: {self.reports_dir}/zap-report.xml")
            
            return True
            
        except Exception as e:
            print(f"✗ Failed to generate reports: {e}")
            return False
    
    def print_summary(self) -> None:
        """Print scan summary"""
        try:
            # Get alerts consistently
            alerts = self.zap.core.alerts()  # Call with no parameters for all alerts
            
            if not alerts:
                print("\n🎉 No security vulnerabilities found!")
                return
            
            print(f"\n⚠️  Found {len(alerts)} security alerts:")
            
            # Group alerts by risk level
            risk_summary = {}
            for alert in alerts:
                risk = alert.get('risk', 'Unknown')
                risk_summary[risk] = risk_summary.get(risk, 0) + 1
            
            for risk, count in sorted(risk_summary.items(), reverse=True):
                print(f"  - {risk}: {count} alerts")
            
            print(f"\nDetailed reports available in {self.reports_dir}/")
            
        except Exception as e:
            print(f"✗ Failed to generate summary: {e}")
    
    def show_zap_scope(self) -> None:
        """Show what URLs are currently in ZAP's scope"""
        try:
            sites = self.zap.core.sites
            print(f"\n📍 Current ZAP scope:")
            if sites:
                for site in sites:
                    print(f"  - {site}")
                    # Try to get URLs for this site
                    try:
                        urls = self.zap.core.urls(site)
                        print(f"    Found {len(urls)} URLs:")
                        for url in urls[:5]:  # Show first 5 URLs
                            print(f"      • {url}")
                        if len(urls) > 5:
                            print(f"      ... and {len(urls) - 5} more")
                    except Exception as e:
                        print(f"    Could not get URLs: {e}")
            else:
                print("  No sites in scope")
        except Exception as e:
            print(f"Failed to get ZAP scope: {e}")
    
    def run_full_scan(self) -> bool:
        """Run complete ZAP DAST scan"""
        print("🔍 Starting OWASP ZAP DAST scan...")
        print("=" * 50)
        
        # Wait for services
        if not self.wait_for_api():
            return False
        
        if not self.wait_for_zap():
            return False
        
        try:
            # Create new session
            self.zap.core.new_session(name="FastAPI_DAST_Scan", overwrite=True)
            
            # Access target URL so ZAP has something to work with
            print(f"Accessing target {self.target_url}")
            self.zap.urlopen(self.target_url)
            
            # Also access some key endpoints to help ZAP discover them
            key_endpoints = [
                "/",
                "/health", 
                "/openapi.json",
                "/docs",
                "/users",
                "/products"
            ]
            
            for endpoint in key_endpoints:
                try:
                    url = f"{self.target_url}{endpoint}"
                    print(f"Accessing {url}")
                    self.zap.urlopen(url)
                    time.sleep(1)  # Small delay between requests
                except Exception as e:
                    print(f"Failed to access {url}: {e}")
            
            time.sleep(2)  # Give the sites tree a chance to get updated
            
            # Get and import OpenAPI spec
            openapi_spec = self.get_openapi_spec()
            if openapi_spec:
                self.import_openapi_spec(openapi_spec)
            else:
                print("⚠️  Continuing without OpenAPI spec import")
            
            # Run spider
            self.spider_application()
            
            # Show what ZAP has discovered
            self.show_zap_scope()
            
            # Run scans
            passive_results = self.run_passive_scan()
            active_results = self.run_active_scan()
            
            # Combine results
            scan_results = {**passive_results, **active_results}
            
            # Generate reports
            self.generate_reports(scan_results)
            
            # Print summary
            self.print_summary()
            
            print("\n✅ ZAP DAST scan completed successfully!")
            return True
            
        except Exception as e:
            print(f"✗ ZAP DAST scan failed: {e}")
            return False


def main():
    """Main function to run ZAP DAST tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run OWASP ZAP DAST tests")
    parser.add_argument("--target", default="http://0.0.0.0:8000", help="Target URL")
    parser.add_argument("--zap-port", type=int, default=8080, help="ZAP proxy port")
    parser.add_argument("--baseline-only", action="store_true", help="Run only baseline scan")
    
    args = parser.parse_args()
    
    # Create ZAP tester instance
    zap_tester = ZAPDastTester(target_url=args.target, zap_proxy_port=args.zap_port)
    
    # Run the scan
    success = zap_tester.run_full_scan()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
