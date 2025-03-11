from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import CarsSpareParts
from src.schemas import CarsSparePartsCreate, CarsSparePartsUpdate, CarsSparePartsResponse
from typing import List, Dict, Any


def create_cars_spare_parts(db: Session, cars_spare_parts_data: CarsSparePartsCreate) -> CarsSparePartsResponse:
    """Create a new car spare part relation."""
    db_cars_spare_parts = CarsSpareParts(**cars_spare_parts_data.model_dump())
    db.add(db_cars_spare_parts)
    db.commit()
    db.refresh(db_cars_spare_parts)
    return CarsSparePartsResponse.model_validate(db_cars_spare_parts)


def get_cars_spare_parts_by_id(db: Session, car_id: int, part_id: int) -> CarsSparePartsResponse:
    """Retrieve a car spare part relation by IDs."""
    cars_spare_parts = db.query(CarsSpareParts).filter(
        CarsSpareParts.car_id == car_id, CarsSpareParts.part_id == part_id
    ).first()
    if not cars_spare_parts:
        raise HTTPException(status_code=404, detail="Car spare part relation not found")
    return CarsSparePartsResponse.model_validate(cars_spare_parts)

def get_all_cars_spare_parts(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all car spare part relations with optimized pagination."""
    
    total_count = db.query(CarsSpareParts).count()  # Get total count
    cars_spare_parts = (
        db.query(CarsSpareParts)
        .order_by(CarsSpareParts.car_id, CarsSpareParts.part_id)  # Use composite PK
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [CarsSparePartsResponse.model_validate(csp) for csp in cars_spare_parts]
    }



def update_cars_spare_parts(db: Session, car_id: int, part_id: int, cars_spare_parts_data: CarsSparePartsUpdate) -> CarsSparePartsResponse:
    """Update a car spare part relation."""
    cars_spare_parts = db.query(CarsSpareParts).filter(
        CarsSpareParts.car_id == car_id, CarsSpareParts.part_id == part_id
    ).first()
    if not cars_spare_parts:
        raise HTTPException(status_code=404, detail="Car spare part relation not found")
    
    update_data = cars_spare_parts_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(cars_spare_parts, key, value)
    
    db.commit()
    db.refresh(cars_spare_parts)
    return CarsSparePartsResponse.model_validate(cars_spare_parts)


def delete_cars_spare_parts(db: Session, car_id: int, part_id: int) -> CarsSparePartsResponse:
    """Delete a car spare part relation."""
    cars_spare_parts = db.query(CarsSpareParts).filter(
        CarsSpareParts.car_id == car_id, CarsSpareParts.part_id == part_id
    ).first()
    if not cars_spare_parts:
        raise HTTPException(status_code=404, detail="Car spare part relation not found")
    
    db.delete(cars_spare_parts)
    db.commit()
    return CarsSparePartsResponse.model_validate(cars_spare_parts)
