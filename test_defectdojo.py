#!/usr/bin/env python3
"""
Test script for DefectDojo integration
"""
import os
import sys
from pathlib import Path

def test_environment():
    """Test environment setup"""
    print("🧪 Testing DefectDojo integration environment...")
    
    # Check required files
    required_files = [
        "defect.py",
        "reports/zap-report.xml",
        ".env.example"
    ]
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ Found: {file_path}")
        else:
            print(f"❌ Missing: {file_path}")
            if file_path == "reports/zap-report.xml":
                print("   Run 'make zap-scan' to generate ZAP reports")
    
    # Check environment variables
    env_vars = [
        "DD_HOST",
        "DEFECTDOJO_API_KEY", 
        "DD_PRODUCT_NAME",
        "DD_USER_ID"
    ]
    
    print("\n🔧 Environment variables:")
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            # Mask API key for security
            if "API_KEY" in var:
                masked_value = value[:8] + "..." if len(value) > 8 else "***"
                print(f"✅ {var}={masked_value}")
            else:
                print(f"✅ {var}={value}")
        else:
            print(f"⚠️  {var}=<not set>")
    
    # Check if .env file exists
    if Path(".env").exists():
        print("\n📄 Found .env file (will be loaded by defect.py)")
    else:
        print("\n📄 No .env file found (copy from .env.example)")
    
    print("\n🚀 Ready to test DefectDojo integration!")
    print("   Run: make upload-to-defectdojo")

if __name__ == "__main__":
    test_environment()
