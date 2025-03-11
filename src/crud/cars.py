from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import Car
from src.schemas import CarCreate, CarUpdate, CarResponse
from src.database import SessionLocal
from typing import List, Dict, Any

def create_car(db: Session, car_data: CarCreate) -> CarResponse:
    """Create a new car."""
    db_car = Car(**car_data.model_dump())
    db.add(db_car)
    db.commit()
    db.refresh(db_car)
    return CarResponse.model_validate(db_car)

def get_car_by_id(db: Session, car_id: int) -> CarResponse:
    """Retrieve a car by ID."""
    car = db.query(Car).filter(Car.car_id == car_id).first()
    if not car:
        raise HTTPException(status_code=404, detail="Car not found")
    return CarResponse.model_validate(car)

def get_all_cars(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all cars with optimized pagination."""
    
    total_count = db.query(Car).count()  # Get total car count
    cars = db.query(Car).order_by(Car.car_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [CarResponse.model_validate(car) for car in cars]
    }


def update_car(db: Session, car_id: int, car_data: CarUpdate) -> CarResponse:
    """Update car details."""
    car = db.query(Car).filter(Car.car_id == car_id).first()
    if not car:
        raise HTTPException(status_code=404, detail="Car not found")
    
    update_data = car_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(car, key, value)
    
    db.commit()
    db.refresh(car)
    return CarResponse.model_validate(car)

def delete_car(db: Session, car_id: int) -> CarResponse:
    """Delete a car."""
    car = db.query(Car).filter(Car.car_id == car_id).first()
    if not car:
        raise HTTPException(status_code=404, detail="Car not found")
    
    db.delete(car)
    db.commit()
    return CarResponse.model_validate(car)

# Dependency function for FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
