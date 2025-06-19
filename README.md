# FastAPI Fuzzing Test Project

## Overview

This project demonstrates how to create a FastAPI application with comprehensive API endpoints and then perform fuzzing tests using multiple approaches to identify potential issues and vulnerabilities.

## Project Structure

```
├── main.py              # FastAPI application with comprehensive endpoints
├── requirements.txt     # Python dependencies
├── openapi.json        # Generated OpenAPI 3.1.0 specification
├── fuzz_test.py        # Original schemathesis-based fuzzing (has compatibility issues)
├── fuzz_test_alt.py    # Alternative approach with manual tests + CLI schemathesis
├── simple_fuzzer.py    # Custom fuzzing implementation that works
└── README.md           # This file
```

## FastAPI Application Features

### Endpoints Implemented

1. **Root & Health**
   - `GET /` - Root endpoint
   - `GET /health` - Health check

2. **User Management**
   - `GET /users` - List users with filtering and pagination
   - `GET /users/{user_id}` - Get specific user
   - `POST /users` - Create new user
   - `PUT /users/{user_id}` - Update user
   - `DELETE /users/{user_id}` - Delete user

3. **Product Management**
   - `GET /products` - List products with filtering
   - `GET /products/{product_id}` - Get specific product

4. **Order Management**
   - `POST /orders` - Create new order
   - `GET /orders/{order_id}` - Get specific order

5. **Complex Testing Endpoint**
   - `POST /complex-endpoint/{path_param}` - Endpoint with various parameter types

### Data Models

- **User**: ID, name, email, age, role, created_at
- **Product**: ID, name, price, category, in_stock, tags
- **Order**: ID, user_id, products, total_amount, status
- **UserRole**: Enum (admin, user, guest)

### Validation Features

- Field length constraints (min/max)
- Numeric range validation
- Email format validation
- Enum validation
- Required field validation
- List size constraints

## Fuzzing Approaches Tested

### 1. Schemathesis (Attempted)

- **Goal**: Use schemathesis library for property-based API testing
- **Issue**: OpenAPI 3.1.0 compatibility problems with current schemathesis version
- **Status**: Not fully functional due to dependency conflicts

### 2. Schemathesis CLI (Partially Working)

- **Goal**: Use schemathesis command-line tool with experimental OpenAPI 3.1 support
- **Issue**: Internal Hypothesis library compatibility issues
- **Status**: Partially working but crashes during test execution

### 3. Custom Fuzzing Implementation (✅ Working)

- **Approach**: Manual implementation of fuzzing concepts
- **Features**:
  - GET endpoint testing with various parameters
  - POST endpoint testing with valid/invalid payloads
  - Edge case testing (boundary values, empty/null values)
  - Error handling validation
  - Response time measurement
  - Comprehensive result reporting

## Test Results Summary

The custom fuzzing script successfully executed **40 tests** with a **97.5% success rate**:

### Status Code Distribution

- **200 OK**: 17 tests (successful operations)
- **201 Created**: 7 tests (successful resource creation)
- **404 Not Found**: 5 tests (expected for non-existent resources)
- **422 Unprocessable Entity**: 10 tests (expected for validation errors)
- **500 Internal Server Error**: 1 test ⚠️ (unexpected - needs investigation)

### Issues Discovered

1. **500 Error in POST /orders**: One test case caused an internal server error, indicating a potential bug in the order creation logic that needs investigation.

### Performance

- **Average Response Time**: 2ms
- **Max Response Time**: 8ms
- **Total Execution Time**: 0.11 seconds

## Running the Project

### 1. Setup Environment

```bash
# Install dependencies
pip install -r requirements.txt

# Or using the virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start FastAPI Server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. View API Documentation

- Swagger UI: <http://localhost:8000/docs>
- ReDoc: <http://localhost:8000/redoc>
- OpenAPI Spec: <http://localhost:8000/openapi.json>

### 4. Run Fuzzing Tests

```bash
# Custom fuzzing implementation (recommended)
python simple_fuzzer.py

# Alternative with manual tests
python fuzz_test_alt.py

# Schemathesis CLI (experimental, may have issues)
schemathesis run http://localhost:8000/openapi.json --base-url http://localhost:8000 --experimental=openapi-3.1
```

## Key Learnings

### 1. OpenAPI 3.1 Compatibility

- Many testing tools still have limited support for OpenAPI 3.1.0
- Consider using OpenAPI 3.0.3 for better tool compatibility
- Experimental features may have stability issues

### 2. Fuzzing Effectiveness

- Custom fuzzing implementations can be more reliable than relying on external tools
- Important to test both valid and invalid inputs
- Edge cases (boundary values, empty inputs) often reveal bugs
- Measuring response times helps identify performance issues

### 3. API Design Best Practices

- Comprehensive input validation prevents many issues
- Proper HTTP status codes improve API usability
- Well-structured error responses aid in debugging
- Documentation generation is invaluable for testing

### 4. Testing Strategy

- Combine multiple testing approaches for comprehensive coverage
- Automated fuzzing should complement, not replace, manual testing
- Monitor both functional correctness and performance metrics
- Regular testing helps catch regressions early

## Next Steps

1. **Investigate 500 Error**: Debug the order creation endpoint to fix the internal server error
2. **Expand Test Coverage**: Add more edge cases and boundary value tests
3. **Performance Testing**: Add load testing to identify performance bottlenecks
4. **Security Testing**: Add tests for common security vulnerabilities (SQL injection, XSS, etc.)
5. **Integration Testing**: Test the API with real database connections
6. **Tool Compatibility**: Monitor schemathesis updates for better OpenAPI 3.1 support
