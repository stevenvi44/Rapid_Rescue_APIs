from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import SparePart
from src.schemas import SparePartCreate, SparePartUpdate, SparePartResponse
from typing import List, Dict, Any

def create_spare_part(db: Session, spare_part_data: SparePartCreate) -> SparePartResponse:
    """Create a new spare part."""
    db_spare_part = SparePart(**spare_part_data.model_dump())
    db.add(db_spare_part)
    db.commit()
    db.refresh(db_spare_part)
    return SparePartResponse.model_validate(db_spare_part)

def get_spare_part_by_id(db: Session, part_id: int) -> SparePartResponse:
    """Retrieve a spare part by ID."""
    spare_part = db.query(SparePart).filter(SparePart.part_id == part_id).first()
    if not spare_part:
        raise HTTPException(status_code=404, detail="Spare part not found")
    return SparePartResponse.model_validate(spare_part)

def get_all_spare_parts(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all spare parts with optimized pagination."""
    
    total_count = db.query(SparePart).count()  # Get total spare part count
    spare_parts = db.query(SparePart).order_by(SparePart.part_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [SparePartResponse.model_validate(spare_part) for spare_part in spare_parts]
    }

def update_spare_part(db: Session, part_id: int, spare_part_data: SparePartUpdate) -> SparePartResponse:
    """Update spare part details."""
    spare_part = db.query(SparePart).filter(SparePart.part_id == part_id).first()
    if not spare_part:
        raise HTTPException(status_code=404, detail="Spare part not found")
    
    update_data = spare_part_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(spare_part, key, value)
    
    db.commit()
    db.refresh(spare_part)
    return SparePartResponse.model_validate(spare_part)

def delete_spare_part(db: Session, part_id: int) -> SparePartResponse:
    """Delete a spare part."""
    spare_part = db.query(SparePart).filter(SparePart.part_id == part_id).first()
    if not spare_part:
        raise HTTPException(status_code=404, detail="Spare part not found")
    
    db.delete(spare_part)
    db.commit()
    return SparePartResponse.model_validate(spare_part)
