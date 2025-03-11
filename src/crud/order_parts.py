from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import OrderPart
from src.schemas import OrderPartCreate, OrderPartUpdate, OrderPartResponse
from typing import List, Dict, Any

def create_order_part(db: Session, order_part_data: OrderPartCreate) -> OrderPartResponse:
    """Create a new order part."""
    db_order_part = OrderPart(**order_part_data.model_dump())
    db.add(db_order_part)
    db.commit()
    db.refresh(db_order_part)
    return OrderPartResponse.model_validate(db_order_part)

def get_order_part_by_id(db: Session, order_part_id: int) -> OrderPartResponse:
    """Retrieve an order part by ID."""
    order_part = db.query(OrderPart).filter(OrderPart.order_part_id == order_part_id).first()
    if not order_part:
        raise HTTPException(status_code=404, detail="Order part not found")
    return OrderPartResponse.model_validate(order_part)

def get_all_order_parts(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all order parts with optimized pagination."""

    total_count = db.query(OrderPart).count()  # Get total order parts count
    order_parts = db.query(OrderPart).order_by(OrderPart.order_part_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [OrderPartResponse.model_validate(order_part) for order_part in order_parts]
    }

def update_order_part(db: Session, order_part_id: int, order_part_data: OrderPartUpdate) -> OrderPartResponse:
    """Update order part details."""
    order_part = db.query(OrderPart).filter(OrderPart.order_part_id == order_part_id).first()
    if not order_part:
        raise HTTPException(status_code=404, detail="Order part not found")
    
    update_data = order_part_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(order_part, key, value)
    
    db.commit()
    db.refresh(order_part)
    return OrderPartResponse.model_validate(order_part)

def delete_order_part(db: Session, order_part_id: int) -> OrderPartResponse:
    """Delete an order part."""
    order_part = db.query(OrderPart).filter(OrderPart.order_part_id == order_part_id).first()
    if not order_part:
        raise HTTPException(status_code=404, detail="Order part not found")
    
    db.delete(order_part)
    db.commit()
    return OrderPartResponse.model_validate(order_part)
