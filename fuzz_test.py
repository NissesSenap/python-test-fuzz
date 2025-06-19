#!/usr/bin/env python3
"""
Schemathesis fuzzing script for the Test Fuzzing API
"""

import schemathesis
import requests
import time
import sys

# URL of the running FastAPI application
API_BASE_URL = "http://localhost:8000"

def check_api_health():
    """Check if the API is running and healthy"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def run_basic_fuzz():
    """Run basic schemathesis fuzzing"""
    print("Starting basic schemathesis fuzzing...")
    
    # Load the schema from the running API
    schema = schemathesis.from_uri(f"{API_BASE_URL}/openapi.json")
    
    # Configure test settings
    results = []
    
    @schema.parametrize()
    def test_api(case):
        """Test case for API fuzzing"""
        try:
            # Send the request
            response = case.call()
            
            # Basic checks
            case.validate_response(response)
            
            # Store results
            results.append({
                'method': case.method,
                'path': case.path,
                'status_code': response.status_code,
                'success': True
            })
            
        except Exception as e:
            results.append({
                'method': case.method,
                'path': case.path,
                'error': str(e),
                'success': False
            })
            # Don't raise the exception to continue testing
    
    # Run the test
    test_api()
    
    return results

def run_advanced_fuzz():
    """Run advanced schemathesis fuzzing with more options"""
    print("Starting advanced schemathesis fuzzing...")
    
    # Load schema from file
    schema = schemathesis.from_path("openapi.json", base_url=API_BASE_URL)
    
    # Configure more comprehensive testing
    results = []
    
    @schema.parametrize(
        # Add various data generation strategies
        generation_config=schemathesis.GenerationConfig(
            # Allow nullable values
            allow_none=True,
            # Test boundary values
            phase="generate"
        )
    )
    def test_comprehensive(case):
        """Comprehensive test case"""
        try:
            # Add custom headers if needed
            case.headers = case.headers or {}
            case.headers['User-Agent'] = 'Schemathesis-Fuzzer'
            
            # Send request
            response = case.call()
            
            # Validate response
            case.validate_response(response)
            
            # Additional checks
            if response.status_code not in [200, 201, 204, 404, 422]:
                print(f"Unexpected status code {response.status_code} for {case.method} {case.path}")
            
            results.append({
                'method': case.method,
                'path': case.path,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'success': True
            })
            
        except Exception as e:
            results.append({
                'method': case.method,
                'path': case.path,
                'error': str(e),
                'success': False
            })
            print(f"Error testing {case.method} {case.path}: {e}")
    
    # Run comprehensive tests
    test_comprehensive()
    
    return results

def print_results(results):
    """Print fuzzing results summary"""
    total_tests = len(results)
    successful_tests = len([r for r in results if r['success']])
    failed_tests = total_tests - successful_tests
    
    print(f"\n=== Fuzzing Results Summary ===")
    print(f"Total tests: {total_tests}")
    print(f"Successful: {successful_tests}")
    print(f"Failed: {failed_tests}")
    print(f"Success rate: {(successful_tests/total_tests)*100:.1f}%")
    
    if failed_tests > 0:
        print(f"\n=== Failed Tests ===")
        for result in results:
            if not result['success']:
                print(f"❌ {result['method']} {result['path']}: {result.get('error', 'Unknown error')}")
    
    # Show response time stats for successful tests
    successful_results = [r for r in results if r['success'] and 'response_time' in r]
    if successful_results:
        response_times = [r['response_time'] for r in successful_results]
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        print(f"\n=== Performance Stats ===")
        print(f"Average response time: {avg_time:.3f}s")
        print(f"Max response time: {max_time:.3f}s")

def main():
    """Main fuzzing function"""
    print("🔥 FastAPI Fuzzing Test Suite 🔥")
    print("=" * 40)
    
    # Check if API is running
    if not check_api_health():
        print("❌ API is not running or not healthy!")
        print("Please start the FastAPI server first:")
        print("uvicorn main:app --host 0.0.0.0 --port 8000")
        sys.exit(1)
    
    print("✅ API is healthy and ready for testing")
    
    # Run basic fuzzing
    print("\n" + "=" * 40)
    basic_results = run_basic_fuzz()
    print_results(basic_results)
    
    # Run advanced fuzzing
    print("\n" + "=" * 40)
    advanced_results = run_advanced_fuzz()
    print_results(advanced_results)
    
    print("\n🎉 Fuzzing complete!")

if __name__ == "__main__":
    main()
