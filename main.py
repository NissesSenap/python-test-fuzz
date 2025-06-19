from fastapi import FastAPI, HTTPException, Query, Path, Body
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import uvicorn
from datetime import datetime

app = FastAPI(
    title="Test Fuzzing API",
    description="A sample API for testing schemathesis fuzzing",
    version="1.0.0",
)

# Pydantic models for request/response validation
class UserRole(str, Enum):
    admin = "admin"
    user = "user"
    guest = "guest"

class User(BaseModel):
    id: int = Field(..., description="User ID", ge=1)
    name: str = Field(..., description="User name", min_length=1, max_length=100)
    email: str = Field(..., description="User email address")
    age: Optional[int] = Field(None, description="User age", ge=0, le=150)
    role: UserRole = Field(default=UserRole.user, description="User role")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")

class UserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str
    age: Optional[int] = Field(None, ge=0, le=150)
    role: Optional[UserRole] = UserRole.user

class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    email: Optional[str] = None
    age: Optional[int] = Field(None, ge=0, le=150)
    role: Optional[UserRole] = None

class Product(BaseModel):
    id: int = Field(..., ge=1)
    name: str = Field(..., min_length=1, max_length=200)
    price: float = Field(..., gt=0, description="Product price in USD")
    category: str = Field(..., min_length=1, max_length=50)
    in_stock: bool = True
    tags: List[str] = Field(default=[], description="Product tags")

class Order(BaseModel):
    id: int = Field(..., ge=1)
    user_id: int = Field(..., ge=1)
    products: List[int] = Field(..., min_items=1, description="List of product IDs")
    total_amount: float = Field(..., gt=0)
    status: str = Field(default="pending")

# In-memory storage for demo purposes
users: Dict[int, User] = {
    1: User(id=1, name="John Doe", email="john@example.com", age=30, role=UserRole.user),
    2: User(id=2, name="Jane Smith", email="jane@example.com", age=25, role=UserRole.admin),
}

products: Dict[int, Product] = {
    1: Product(id=1, name="Laptop", price=999.99, category="Electronics", tags=["computer", "portable"]),
    2: Product(id=2, name="Book", price=19.99, category="Education", tags=["reading", "knowledge"]),
}

orders: Dict[int, Order] = {}

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint returning API information"""
    return {"message": "Welcome to Test Fuzzing API", "version": "1.0.0"}

# Health check
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now()}

# User endpoints
@app.get("/users", response_model=List[User], tags=["Users"])
async def get_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of users to return"),
    role: Optional[UserRole] = Query(None, description="Filter by user role")
):
    """Get list of users with optional filtering and pagination"""
    user_list = list(users.values())
    
    if role:
        user_list = [user for user in user_list if user.role == role]
    
    return user_list[skip:skip + limit]

@app.get("/users/{user_id}", response_model=User, tags=["Users"])
async def get_user(user_id: int = Path(..., ge=1, description="User ID")):
    """Get a specific user by ID"""
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

@app.post("/users", response_model=User, status_code=201, tags=["Users"])
async def create_user(user: UserCreate):
    """Create a new user"""
    user_id = max(users.keys()) + 1 if users else 1
    new_user = User(
        id=user_id,
        name=user.name,
        email=user.email,
        age=user.age,
        role=user.role,
        created_at=datetime.now()
    )
    users[user_id] = new_user
    return new_user

@app.put("/users/{user_id}", response_model=User, tags=["Users"])
async def update_user(user_id: int = Path(..., ge=1), user_update: UserUpdate = Body(...)):
    """Update an existing user"""
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    existing_user = users[user_id]
    update_data = user_update.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(existing_user, field, value)
    
    return existing_user

@app.delete("/users/{user_id}", tags=["Users"])
async def delete_user(user_id: int = Path(..., ge=1)):
    """Delete a user"""
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    del users[user_id]
    return {"message": f"User {user_id} deleted successfully"}

# Product endpoints
@app.get("/products", response_model=List[Product], tags=["Products"])
async def get_products(
    category: Optional[str] = Query(None, description="Filter by category"),
    min_price: Optional[float] = Query(None, ge=0, description="Minimum price filter"),
    max_price: Optional[float] = Query(None, ge=0, description="Maximum price filter"),
    in_stock: Optional[bool] = Query(None, description="Filter by stock availability")
):
    """Get list of products with optional filtering"""
    product_list = list(products.values())
    
    if category:
        product_list = [p for p in product_list if p.category.lower() == category.lower()]
    if min_price is not None:
        product_list = [p for p in product_list if p.price >= min_price]
    if max_price is not None:
        product_list = [p for p in product_list if p.price <= max_price]
    if in_stock is not None:
        product_list = [p for p in product_list if p.in_stock == in_stock]
    
    return product_list

@app.get("/products/{product_id}", response_model=Product, tags=["Products"])
async def get_product(product_id: int = Path(..., ge=1)):
    """Get a specific product by ID"""
    if product_id not in products:
        raise HTTPException(status_code=404, detail="Product not found")
    return products[product_id]

# Order endpoints
@app.post("/orders", response_model=Order, status_code=201, tags=["Orders"])
async def create_order(
    user_id: int = Body(..., ge=1),
    product_ids: List[int] = Body(..., min_items=1)
):
    """Create a new order"""
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate all products exist
    for product_id in product_ids:
        if product_id not in products:
            raise HTTPException(status_code=404, detail=f"Product {product_id} not found")
    
    # Calculate total amount
    total = sum(products[pid].price for pid in product_ids)
    
    order_id = max(orders.keys()) + 1 if orders else 1
    new_order = Order(
        id=order_id,
        user_id=user_id,
        products=product_ids,
        total_amount=total
    )
    orders[order_id] = new_order
    return new_order

@app.get("/orders/{order_id}", response_model=Order, tags=["Orders"])
async def get_order(order_id: int = Path(..., ge=1)):
    """Get a specific order by ID"""
    if order_id not in orders:
        raise HTTPException(status_code=404, detail="Order not found")
    return orders[order_id]

# Complex endpoint with multiple parameters
@app.post("/complex-endpoint", tags=["Complex"])
async def complex_endpoint(
    string_param: str = Body(..., min_length=1, max_length=100),
    number_param: int = Body(..., ge=1, le=1000),
    optional_param: Optional[str] = Body(None),
    list_param: List[str] = Body(..., min_items=1, max_items=10),
    nested_object: Dict[str, Any] = Body(...),
    query_param: str = Query(..., min_length=1),
    path_param: int = Path(..., ge=1)
):
    """Complex endpoint with various parameter types for comprehensive testing"""
    return {
        "received_data": {
            "string_param": string_param,
            "number_param": number_param,
            "optional_param": optional_param,
            "list_param": list_param,
            "nested_object": nested_object,
            "query_param": query_param,
            "path_param": path_param
        },
        "message": "Complex endpoint processed successfully"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)