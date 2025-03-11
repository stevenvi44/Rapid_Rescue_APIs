from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import OrderCreate, OrderUpdate, OrderResponse
from src.crud.orders import (
    create_order,
    get_order_by_id,
    get_all_orders,
    update_order,
    delete_order,
)
from typing import Dict, Any

router = APIRouter(prefix="/orders", tags=["Orders"])

@router.post("/", response_model=OrderResponse)
def create_new_order(order_data: OrderCreate, db: Session = Depends(get_db)):
    return create_order(db, order_data)

@router.get("/{order_id}", response_model=OrderResponse)
def read_order(order_id: int, db: Session = Depends(get_db)):
    return get_order_by_id(db, order_id)

@router.get("/", response_model=Dict[str, Any])
def read_orders(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all orders with pagination."""
    return get_all_orders(db, skip, limit)

@router.put("/{order_id}", response_model=OrderResponse)
def update_existing_order(order_id: int, order_data: OrderUpdate, db: Session = Depends(get_db)):
    return update_order(db, order_id, order_data)

@router.delete("/{order_id}", response_model=OrderResponse)
def delete_existing_order(order_id: int, db: Session = Depends(get_db)):
    return delete_order(db, order_id)
