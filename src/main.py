import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from fastapi import FastAPI
from src.database import engine, Base
from src.routers import (
    users,
    cars,
    ai_preventive_maintenance,
    orders,
    transactions,
    spare_parts,
    service_requests,
    service_providers,
    order_services,
    order_parts,
    cars_spare_parts,
    user_cars,
    auth,
)

# Initialize FastAPI app
app = FastAPI(
    title="Rapid_Rescue FastAPI Project",
    description="A complete FastAPI backend with multiple routers.",
    version="1.0.0"
)


# Create tables in the database
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Error creating tables: {e}")

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(user_cars.router)
app.include_router(cars.router)
app.include_router(spare_parts.router)
app.include_router(cars_spare_parts.router)
app.include_router(service_requests.router)
app.include_router(order_services.router) # under test
app.include_router(order_parts.router) # under test
app.include_router(orders.router) # under test
app.include_router(service_providers.router) # under test
app.include_router(ai_preventive_maintenance.router) # under test
app.include_router(transactions.router) # under test


# Define the root endpoint
@app.get("/", tags=["Root"])
def read_root():
    return {"message": "Welcome to FastAPI!"}
