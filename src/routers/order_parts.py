from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import OrderPartCreate, OrderPartUpdate, OrderPartResponse
from src.crud.order_parts import (
    create_order_part,
    get_order_part_by_id,
    get_all_order_parts,
    update_order_part,
    delete_order_part,
)
from typing import Dict, Any

router = APIRouter(prefix="/order_parts", tags=["Order Parts"])

@router.post("/", response_model=OrderPartResponse)
def create_new_order_part(order_part_data: OrderPartCreate, db: Session = Depends(get_db)):
    return create_order_part(db, order_part_data)

@router.get("/{order_part_id}", response_model=OrderPartResponse)
def read_order_part(order_part_id: int, db: Session = Depends(get_db)):
    return get_order_part_by_id(db, order_part_id)

@router.get("/", response_model=Dict[str, Any])
def read_order_parts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all order parts with pagination."""
    return get_all_order_parts(db, skip, limit)

@router.put("/{order_part_id}", response_model=OrderPartResponse)
def update_existing_order_part(order_part_id: int, order_part_data: OrderPartUpdate, db: Session = Depends(get_db)):
    return update_order_part(db, order_part_id, order_part_data)

@router.delete("/{order_part_id}", response_model=OrderPartResponse)
def delete_existing_order_part(order_part_id: int, db: Session = Depends(get_db)):
    return delete_order_part(db, order_part_id)
