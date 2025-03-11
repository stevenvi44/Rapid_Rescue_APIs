from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import OrderServiceCreate, OrderServiceUpdate, OrderServiceResponse
from src.crud.order_services import (
    create_order_service,
    get_order_service_by_id,
    get_all_order_services,
    update_order_service,
    delete_order_service,
)
from typing import Dict, Any


router = APIRouter(prefix="/order_services", tags=["Order Services"])

@router.post("/", response_model=OrderServiceResponse)
def create_new_order_service(order_service_data: OrderServiceCreate, db: Session = Depends(get_db)):
    return create_order_service(db, order_service_data)

@router.get("/{order_service_id}", response_model=OrderServiceResponse)
def read_order_service(order_service_id: int, db: Session = Depends(get_db)):
    return get_order_service_by_id(db, order_service_id)

@router.get("/", response_model=Dict[str, Any])
def read_order_services(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all order services with pagination."""
    return get_all_order_services(db, skip, limit)

@router.put("/{order_service_id}", response_model=OrderServiceResponse)
def update_existing_order_service(order_service_id: int, order_service_data: OrderServiceUpdate, db: Session = Depends(get_db)):
    return update_order_service(db, order_service_id, order_service_data)

@router.delete("/{order_service_id}", response_model=OrderServiceResponse)
def delete_existing_order_service(order_service_id: int, db: Session = Depends(get_db)):
    return delete_order_service(db, order_service_id)
