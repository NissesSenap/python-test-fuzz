import os
import requests
from defectdojo_api_v2 import defectdojo
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2 import id_token

# === Load environment variables ===
DD_HOST = os.environ["DD_HOST"]  # e.g. https://dojo.example.com
IAP_CLIENT_ID = os.environ["IAP_CLIENT_ID"]  # OAuth client ID for IAP
DEFECTDOJO_API_KEY = os.environ["DEFECTDOJO_API_KEY"]  # From user profile
PRODUCT_NAME = os.environ["DD_PRODUCT_NAME"]
ENGAGEMENT_NAME = os.environ["DD_ENGAGEMENT_NAME"]
USER_ID = int(os.environ["DD_USER_ID"])  # Must be an existing user ID

# === Step 1: Fetch an IAP token ===
print("🔐 Fetching IAP token...")
oidc_token = id_token.fetch_id_token(Request(), IAP_CLIENT_ID)

# === Step 2: Setup session with headers for both IAP + Dojo auth ===
session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {oidc_token}",           # For IAP
    "DD-API-Key": DEFECTDOJO_API_KEY                   # For DefectDojo (if needed, or below)
    # Optionally:
    # "Authorization": f"Token {DEFECTDOJO_API_KEY}"  # Use if Dojo expects this format
})

# === Step 3: Custom API wrapper using IAP session ===
class IAPDojoClient(defectdojo.DefectDojoAPI):
    def __init__(self, host, api_key, user, verify_ssl, session):
        super().__init__(host, api_key, user, verify_ssl)
        self.session = session

    def call_api(self, method, path, **kwargs):
        url = f"{DD_HOST}/api/v2/{path.strip('/')}"
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code >= 400:
            raise Exception(f"[{resp.status_code}] {resp.text}")
        return resp.json()

# === Step 4: Main Logic ===
def main():
    print("🚀 Initializing IAP-aware DefectDojo client...")
    api = IAPDojoClient(
        host=DD_HOST,
        api_key=DEFECTDOJO_API_KEY,
        user="zap",
        verify_ssl=True,
        session=session
    )

    print(f"🔎 Checking for existing product: {PRODUCT_NAME}")
    products = api.list_products(name=PRODUCT_NAME)
    if products["count"] == 0:
        print("📦 Product not found, creating...")
        product = api.create_product(name=PRODUCT_NAME, prod_type=1)
    else:
        product = products["results"][0]

    print(f"📁 Creating engagement: {ENGAGEMENT_NAME}")
    engagement = api.create_engagement(
        name=ENGAGEMENT_NAME,
        product_id=product["id"],
        lead=USER_ID,
        status="In Progress",
        target_start=datetime.now().strftime("%Y-%m-%d"),
        target_end=datetime.now().strftime("%Y-%m-%d")
    )

    print("📤 Uploading ZAP scan...")
    api.import_scan(
        scan_type="ZAP Scan",
        file="zap-report.xml",
        engagement_id=engagement["id"],
        lead=USER_ID,
        scan_date=datetime.now().strftime("%Y-%m-%d"),
        active=True,
        verified=False
    )

    print("✅ Scan uploaded to DefectDojo successfully.")

if __name__ == "__main__":
    main()
