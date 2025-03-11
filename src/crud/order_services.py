from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import OrderService
from src.schemas import OrderServiceCreate, OrderServiceUpdate, OrderServiceResponse
from typing import List, Dict, Any

def create_order_service(db: Session, order_service_data: OrderServiceCreate) -> OrderServiceResponse:
    """Create a new order service."""
    db_order_service = OrderService(**order_service_data.model_dump())
    db.add(db_order_service)
    db.commit()
    db.refresh(db_order_service)
    return OrderServiceResponse.model_validate(db_order_service)

def get_order_service_by_id(db: Session, order_service_id: int) -> OrderServiceResponse:
    """Retrieve an order service by ID."""
    order_service = db.query(OrderService).filter(OrderService.order_service_id == order_service_id).first()
    if not order_service:
        raise HTTPException(status_code=404, detail="Order service not found")
    return OrderServiceResponse.model_validate(order_service)

def get_all_order_services(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all order services with optimized pagination."""
    
    total_count = db.query(OrderService).count()  # Get total order services count
    order_services = db.query(OrderService).order_by(OrderService.order_service_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [OrderServiceResponse.model_validate(order_service) for order_service in order_services]
    }


def update_order_service(db: Session, order_service_id: int, order_service_data: OrderServiceUpdate) -> OrderServiceResponse:
    """Update order service details."""
    order_service = db.query(OrderService).filter(OrderService.order_service_id == order_service_id).first()
    if not order_service:
        raise HTTPException(status_code=404, detail="Order service not found")
    
    update_data = order_service_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(order_service, key, value)
    
    db.commit()
    db.refresh(order_service)
    return OrderServiceResponse.model_validate(order_service)

def delete_order_service(db: Session, order_service_id: int) -> OrderServiceResponse:
    """Delete an order service."""
    order_service = db.query(OrderService).filter(OrderService.order_service_id == order_service_id).first()
    if not order_service:
        raise HTTPException(status_code=404, detail="Order service not found")
    
    db.delete(order_service)
    db.commit()
    return OrderServiceResponse.model_validate(order_service)
