from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import SparePartCreate, SparePartUpdate, SparePartResponse
from src.crud.spare_parts import (
    create_spare_part,
    get_spare_part_by_id,
    get_all_spare_parts,
    update_spare_part,
    delete_spare_part,
)
from typing import Dict, Any

router = APIRouter(prefix="/spare_parts", tags=["Spare Parts"])

@router.post("/", response_model=SparePartResponse)
def create_new_spare_part(spare_part_data: SparePartCreate, db: Session = Depends(get_db)):
    return create_spare_part(db, spare_part_data)

@router.get("/{part_id}", response_model=SparePartResponse)
def read_spare_part(part_id: int, db: Session = Depends(get_db)):
    return get_spare_part_by_id(db, part_id)

@router.get("/", response_model=Dict[str, Any])
def read_spare_parts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all spare parts with pagination."""
    return get_all_spare_parts(db, skip, limit)

@router.put("/{part_id}", response_model=SparePartResponse)
def update_existing_spare_part(part_id: int, spare_part_data: SparePartUpdate, db: Session = Depends(get_db)):
    return update_spare_part(db, part_id, spare_part_data)

@router.delete("/{part_id}", response_model=SparePartResponse)
def delete_existing_spare_part(part_id: int, db: Session = Depends(get_db)):
    return delete_spare_part(db, part_id)
