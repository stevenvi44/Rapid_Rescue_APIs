from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import CarCreate, CarUpdate, CarResponse
from src.crud.cars import create_car, get_car_by_id, get_all_cars, update_car, delete_car
from typing import Dict, Any

router = APIRouter(prefix="/cars", tags=["Cars"])

@router.post("/", response_model=CarResponse)
def create_new_car(car_data: CarCreate, db: Session = Depends(get_db)):
    return create_car(db, car_data)

@router.get("/{car_id}", response_model=CarResponse)
def read_car(car_id: int, db: Session = Depends(get_db)):
    return get_car_by_id(db, car_id)

@router.get("/", response_model=Dict[str, Any])
def read_cars(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all cars with pagination."""
    return get_all_cars(db, skip, limit)

@router.put("/{car_id}", response_model=CarResponse)
def update_existing_car(car_id: int, car_data: CarUpdate, db: Session = Depends(get_db)):
    return update_car(db, car_id, car_data)

@router.delete("/{car_id}", response_model=CarResponse)
def delete_existing_car(car_id: int, db: Session = Depends(get_db)):
    return delete_car(db, car_id)
