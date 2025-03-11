from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import Order
from src.schemas import OrderCreate, OrderUpdate, OrderResponse
from typing import List, Dict, Any

def create_order(db: Session, order_data: OrderCreate) -> OrderResponse:
    """Create a new order."""
    db_order = Order(**order_data.model_dump())
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return OrderResponse.model_validate(db_order)

def get_order_by_id(db: Session, order_id: int) -> OrderResponse:
    """Retrieve an order by ID."""
    order = db.query(Order).filter(Order.order_id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return OrderResponse.model_validate(order)

def get_all_orders(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all orders with optimized pagination."""

    total_count = db.query(Order).count()  # Get total order count
    orders = db.query(Order).order_by(Order.order_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [OrderResponse.model_validate(order) for order in orders]
    }

def update_order(db: Session, order_id: int, order_data: OrderUpdate) -> OrderResponse:
    """Update order details."""
    order = db.query(Order).filter(Order.order_id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    update_data = order_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(order, key, value)
    
    db.commit()
    db.refresh(order)
    return OrderResponse.model_validate(order)

def delete_order(db: Session, order_id: int) -> OrderResponse:
    """Delete an order."""
    order = db.query(Order).filter(Order.order_id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    db.delete(order)
    db.commit()
    return OrderResponse.model_validate(order)

# Dependency function for FastAPI routes
def get_db():
    from src.database import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
