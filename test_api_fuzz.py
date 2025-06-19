#!/usr/bin/env python3
"""
Pytest-based API fuzzing tests using schemathesis
"""

import pytest
import requests
from schemathesis.checks import not_a_server_error
from schemathesis.openapi import from_url

# URL of the running FastAPI application
API_BASE_URL = "http://localhost:8000"

# Load the schema once for all tests
schema = from_url(f"{API_BASE_URL}/openapi.json")


@pytest.fixture(scope="session", autouse=True)
def check_api_health():
    """Check if the API is running before running tests"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            pytest.skip("API is not healthy - skipping all tests")
    except requests.RequestException:
        pytest.skip("API is not running - skipping all tests")


class TestAPIFuzzing:
    """API Fuzzing test class"""

    @schema.parametrize()
    def test_api_fuzzing_basic(self, case):
        """Basic API fuzzing test"""
        # Execute the API call
        response = case.call()
        
        # Basic validation - no server errors (5xx)
        case.validate_response(response, checks=(not_a_server_error,))

    @schema.parametrize()
    def test_api_fuzzing_comprehensive(self, case):
        """Comprehensive API fuzzing with all checks"""
        # Add custom headers
        case.headers = case.headers or {}
        case.headers['User-Agent'] = 'Schemathesis-Pytest-Fuzzer'
        
        # Execute the API call
        response = case.call()
        
        # Run comprehensive checks (v4 runs all available checks by default)
        case.validate_response(response)

    @schema.parametrize()
    def test_api_response_times(self, case):
        """Test API response times"""
        # Execute the API call
        response = case.call()
        
        # Check response time (should be under 1 second for local API)
        assert response.elapsed.total_seconds() < 1.0, f"Response too slow: {response.elapsed.total_seconds()}s"
        
        # Basic validation
        case.validate_response(response, checks=(not_a_server_error,))

    @schema.parametrize()
    def test_users_endpoint_specific(self, case):
        """Specific tests for users endpoint"""
        # Only run this test for users endpoints
        if "/users" not in case.path:
            pytest.skip("Not a users endpoint")
            
        response = case.call()
        
        # Users endpoint specific checks
        if case.method == "GET" and response.status_code == 200:
            # Response should be a list for GET /users
            data = response.json()
            if isinstance(data, list):
                # Each user should have required fields
                for user in data:
                    assert 'id' in user
                    assert 'name' in user
                    assert 'email' in user
        
        case.validate_response(response, checks=(not_a_server_error,))

    @schema.parametrize()
    def test_products_endpoint_specific(self, case):
        """Specific tests for products endpoint"""
        # Only run this test for products endpoints
        if "/products" not in case.path:
            pytest.skip("Not a products endpoint")
            
        response = case.call()
        
        # Products endpoint specific checks
        if case.method == "GET" and response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                for product in data:
                    assert 'id' in product
                    assert 'name' in product
                    assert 'price' in product
                    assert isinstance(product['price'], (int, float))
                    assert product['price'] > 0
        
        case.validate_response(response, checks=(not_a_server_error,))

    @schema.parametrize()
    def test_orders_creation(self, case):
        """Specific tests for order creation"""
        # Only run this test for POST requests to orders endpoints
        if "/orders" not in case.path or case.method != "POST":
            pytest.skip("Not a POST request to orders endpoint")
            
        response = case.call()
        
        # Order creation specific checks
        if response.status_code == 201:
            data = response.json()
            assert 'id' in data
            assert 'user_id' in data
            assert 'products' in data
            assert 'total_amount' in data
            assert isinstance(data['total_amount'], (int, float))
            assert data['total_amount'] > 0
        
        # Allow 404 for non-existent users/products and 422 for validation errors
        assert response.status_code in [201, 404, 422, 500], f"Unexpected status code: {response.status_code}"

    def test_root_endpoint(self):
        """Test root endpoint manually"""
        response = requests.get(f"{API_BASE_URL}/")
        assert response.status_code == 200
        data = response.json()
        assert 'message' in data
        assert 'version' in data

    def test_health_endpoint(self):
        """Test health endpoint manually"""
        response = requests.get(f"{API_BASE_URL}/health")
        assert response.status_code == 200
        data = response.json()
        assert 'status' in data
        assert data['status'] == 'healthy'

    @pytest.mark.parametrize("user_id", [1, 2, 999])
    def test_get_user_by_id(self, user_id):
        """Test getting users by specific IDs"""
        response = requests.get(f"{API_BASE_URL}/users/{user_id}")
        
        if user_id in [1, 2]:  # These users exist in the sample data
            assert response.status_code == 200
            data = response.json()
            assert data['id'] == user_id
            assert 'name' in data
            assert 'email' in data
        else:  # Non-existent user
            assert response.status_code == 404

    @pytest.mark.parametrize("product_id", [1, 2, 999])
    def test_get_product_by_id(self, product_id):
        """Test getting products by specific IDs"""
        response = requests.get(f"{API_BASE_URL}/products/{product_id}")
        
        if product_id in [1, 2]:  # These products exist in the sample data
            assert response.status_code == 200
            data = response.json()
            assert data['id'] == product_id
            assert 'name' in data
            assert 'price' in data
        else:  # Non-existent product
            assert response.status_code == 404

    def test_create_valid_user(self):
        """Test creating a valid user"""
        user_data = {
            "name": "Test User",
            "email": "test@example.com",
            "age": 25,
            "role": "user"
        }
        response = requests.post(f"{API_BASE_URL}/users", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert 'id' in data
        assert data['name'] == user_data['name']
        assert data['email'] == user_data['email']

    def test_create_invalid_user(self):
        """Test creating invalid users"""
        invalid_users = [
            {"email": "test@example.com"},  # Missing name
            {"name": "Test User"},  # Missing email
            {"name": "", "email": "test@example.com"},  # Empty name
            {"name": "Test User", "email": "invalid-email"},  # Invalid email format
            {"name": "A" * 101, "email": "test@example.com"},  # Name too long
            {"name": "Test User", "email": "test@example.com", "age": -1},  # Invalid age
            {"name": "Test User", "email": "test@example.com", "age": 151},  # Age too high
        ]
        
        for user_data in invalid_users:
            response = requests.post(f"{API_BASE_URL}/users", json=user_data)
            assert response.status_code == 422, f"Expected 422 for {user_data}, got {response.status_code}"

    def test_create_valid_order(self):
        """Test creating a valid order"""
        order_data = {
            "user_id": 1,
            "product_ids": [1, 2]
        }
        response = requests.post(f"{API_BASE_URL}/orders", json=order_data)
        assert response.status_code == 201
        data = response.json()
        assert 'id' in data
        assert data['user_id'] == order_data['user_id']
        assert data['products'] == order_data['product_ids']
        assert 'total_amount' in data

    def test_create_invalid_order(self):
        """Test creating invalid orders"""
        invalid_orders = [
            {"product_ids": [1]},  # Missing user_id
            {"user_id": 1},  # Missing product_ids
            {"user_id": 999, "product_ids": [1]},  # Non-existent user
            {"user_id": 1, "product_ids": [999]},  # Non-existent product
            {"user_id": -1, "product_ids": [1]},  # Invalid user_id
            {"user_id": 1, "product_ids": []},  # Empty product_ids
        ]
        
        for order_data in invalid_orders:
            response = requests.post(f"{API_BASE_URL}/orders", json=order_data)
            assert response.status_code in [404, 422], f"Expected 404 or 422 for {order_data}, got {response.status_code}"

    @pytest.mark.parametrize("query_params", [
        {},  # No filters
        {"skip": 0, "limit": 10},  # Pagination
        {"role": "user"},  # Role filter
        {"role": "admin"},  # Admin filter
        {"skip": 0, "limit": 1000},  # Max limit
        {"skip": 50, "limit": 10},  # Skip some records
    ])
    def test_get_users_with_filters(self, query_params):
        """Test getting users with various query parameters"""
        response = requests.get(f"{API_BASE_URL}/users", params=query_params)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # Check limit is respected
        if 'limit' in query_params:
            assert len(data) <= query_params['limit']

    @pytest.mark.parametrize("query_params", [
        {},  # No filters
        {"category": "Electronics"},  # Category filter
        {"min_price": 10.0},  # Min price filter
        {"max_price": 100.0},  # Max price filter
        {"in_stock": True},  # Stock filter
        {"category": "Electronics", "min_price": 500.0},  # Combined filters
    ])
    def test_get_products_with_filters(self, query_params):
        """Test getting products with various query parameters"""
        response = requests.get(f"{API_BASE_URL}/products", params=query_params)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # Validate filters are applied correctly
        for product in data:
            if 'category' in query_params:
                assert product['category'].lower() == query_params['category'].lower()
            if 'min_price' in query_params:
                assert product['price'] >= query_params['min_price']
            if 'max_price' in query_params:
                assert product['price'] <= query_params['max_price']
            if 'in_stock' in query_params:
                assert product['in_stock'] == query_params['in_stock']


# Pytest configuration
def pytest_configure(config):
    """Configure pytest for better output"""
    config.addinivalue_line("markers", "slow: marks tests as slow")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers"""
    for item in items:
        # Mark schemathesis tests as potentially slow
        if "schemathesis" in str(item.function):
            item.add_marker(pytest.mark.slow)


if __name__ == "__main__":
    # Run with pytest when executed directly
    import subprocess
    import sys
    
    # Run pytest with nice output
    cmd = [
        sys.executable, "-m", "pytest", 
        __file__, 
        "-v",  # Verbose output
        "--tb=short",  # Short traceback format
        "--durations=10",  # Show 10 slowest tests
    ]
    
    result = subprocess.run(cmd)
    sys.exit(result.returncode)
