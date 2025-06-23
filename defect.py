import os
import sys
from pathlib import Path
from datetime import datetime
import httpx

# Load environment variables from .env file if it exists
def load_env_file():
    """Load environment variables from .env file"""
    env_file = Path('.env')
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Don't override existing environment variables
                    if key not in os.environ:
                        os.environ[key] = value

# Load .env file first
load_env_file()

# === Load environment variables ===
DD_HOST = os.environ.get("DD_HOST", "https://demo.defectdojo.org")  # Default to public demo instance
DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY")  # From user profile
PRODUCT_NAME = os.environ.get("DD_PRODUCT_NAME", "Security Test Project")
ENGAGEMENT_NAME = os.environ.get("DD_ENGAGEMENT_NAME", f"ZAP Scan {datetime.now().strftime('%Y-%m-%d')}")
USER_ID = int(os.environ.get("DD_USER_ID", "1"))  # Default to admin user

# === DefectDojo API Client using httpx ===
class DefectDojoClient:
    def __init__(self, host: str, api_key: str):
        self.host = host.rstrip('/')
        self.api_key = api_key
        self.client = httpx.Client(
            base_url=f"{self.host}/api/v2",
            headers={
                "Authorization": f"Token {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()
    
    def _request(self, method: str, endpoint: str, **kwargs):
        """Make HTTP request to DefectDojo API"""
        try:
            response = self.client.request(method, endpoint, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            print(f"❌ HTTP error {e.response.status_code}: {e.response.text}")
            raise
        except Exception as e:
            print(f"❌ Request failed: {e}")
            raise
    
    def get_products(self, name: str = None):
        """Get products, optionally filtered by name"""
        params = {"name": name} if name else {}
        return self._request("GET", "/products/", params=params)
    
    def create_product(self, name: str, description: str = "", prod_type: int = 1):
        """Create a new product"""
        data = {
            "name": name,
            "description": description,
            "prod_type": prod_type
        }
        return self._request("POST", "/products/", json=data)
    
    def get_engagements(self, product_id: int = None):
        """Get engagements, optionally filtered by product"""
        params = {"product": product_id} if product_id else {}
        return self._request("GET", "/engagements/", params=params)
    
    def create_engagement(self, name: str, product_id: int, lead: int, 
                         status: str = "In Progress", 
                         target_start: str = None, target_end: str = None,
                         description: str = ""):
        """Create a new engagement"""
        today = datetime.now().strftime("%Y-%m-%d")
        data = {
            "name": name,
            "description": description,
            "product": product_id,
            "lead": lead,
            "status": status,
            "target_start": target_start or today,
            "target_end": target_end or today,
        }
        return self._request("POST", "/engagements/", json=data)
    
    def import_scan(self, scan_type: str, file_path: str, engagement_id: int, 
                   lead: int = None, scan_date: str = None, active: bool = True, 
                   verified: bool = False):
        """Import scan results"""
        if not Path(file_path).exists():
            raise FileNotFoundError(f"Scan file not found: {file_path}")
        
        data = {
            "scan_type": scan_type,
            "engagement": engagement_id,
            "lead": lead or USER_ID,
            "scan_date": scan_date or datetime.now().strftime("%Y-%m-%d"),
            "active": active,
            "verified": verified,
        }
        
        with open(file_path, 'rb') as f:
            files = {'file': f}
            # For multipart form data, we need to remove Content-Type header
            headers = {"Authorization": f"Token {self.api_key}"}
            response = httpx.post(
                f"{self.host}/api/v2/import-scan/",
                headers=headers,
                data=data,
                files=files,
                timeout=60.0
            )
            response.raise_for_status()
            return response.json()

# === Helper Functions ===
def get_git_info():
    """Get git repository information for engagement naming"""
    try:
        import subprocess
        # Get current branch
        branch = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 
                                       cwd=Path.cwd(), text=True).strip()
        # Get latest commit hash (short)
        commit = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], 
                                       cwd=Path.cwd(), text=True).strip()
        return branch, commit
    except:
        return "main", "unknown"

def get_zap_report_path():
    """Find ZAP XML report file"""
    reports_dir = Path("reports")
    zap_files = list(reports_dir.glob("zap-report.xml"))
    if not zap_files:
        print("❌ No ZAP XML report found in reports/ directory")
        print("   Make sure to run 'make zap-scan' first")
        return None
    return zap_files[0]

# === Main Logic ===
def main():
    """Upload ZAP scan results to DefectDojo"""
    
    # Validate required environment variables
    if not DEFECTDOJO_API_KEY:
        print("❌ DEFECTDOJO_API_KEY environment variable is required")
        print("   Get your API key from DefectDojo user profile")
        return 1
    
    # Find ZAP report
    zap_report = get_zap_report_path()
    if not zap_report:
        return 1
    
    # Get git info for better engagement naming
    branch, commit = get_git_info()
    engagement_name = f"{ENGAGEMENT_NAME} - {branch}@{commit}"
    
    print(f"🚀 Uploading ZAP scan to DefectDojo...")
    print(f"   Host: {DD_HOST}")
    print(f"   Product: {PRODUCT_NAME}")
    print(f"   Engagement: {engagement_name}")
    print(f"   Report: {zap_report}")
    
    try:
        with DefectDojoClient(DD_HOST, DEFECTDOJO_API_KEY) as api:
            
            # Step 1: Find or create product
            print(f"🔎 Checking for existing product: {PRODUCT_NAME}")
            products_response = api.get_products(name=PRODUCT_NAME)
            
            if products_response["count"] == 0:
                print("📦 Product not found, creating...")
                product = api.create_product(
                    name=PRODUCT_NAME,
                    description=f"Security testing for {PRODUCT_NAME}",
                    prod_type=1
                )
                print(f"✅ Created product: {product['name']} (ID: {product['id']})")
            else:
                product = products_response["results"][0]
                print(f"✅ Found existing product: {product['name']} (ID: {product['id']})")
            
            # Step 2: Create engagement
            print(f"📁 Creating engagement: {engagement_name}")
            engagement = api.create_engagement(
                name=engagement_name,
                product_id=product["id"],
                lead=USER_ID,
                status="In Progress",
                target_start=datetime.now().strftime("%Y-%m-%d"),
                target_end=datetime.now().strftime("%Y-%m-%d"),
                description=f"ZAP DAST scan for branch {branch} at commit {commit}"
            )
            print(f"✅ Created engagement: {engagement['name']} (ID: {engagement['id']})")
            
            # Step 3: Upload ZAP scan
            print("📤 Uploading ZAP scan results...")
            scan_result = api.import_scan(
                scan_type="ZAP Scan",
                file_path=str(zap_report),
                engagement_id=engagement["id"],
                lead=USER_ID,
                scan_date=datetime.now().strftime("%Y-%m-%d"),
                active=True,
                verified=False
            )
            
            print("✅ Scan uploaded to DefectDojo successfully!")
            print(f"   Scan ID: {scan_result.get('scan_id', 'N/A')}")
            print(f"   View results: {DD_HOST}/engagement/{engagement['id']}")
            
            return 0
            
    except Exception as e:
        print(f"❌ Failed to upload scan: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
