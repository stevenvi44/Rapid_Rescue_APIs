from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import CarsSparePartsCreate, CarsSparePartsUpdate, CarsSparePartsResponse
from src.crud.cars_spare_parts import (
    create_cars_spare_parts,
    get_cars_spare_parts_by_id,
    get_all_cars_spare_parts,
    update_cars_spare_parts,
    delete_cars_spare_parts,
)
from typing import Dict, Any


router = APIRouter(prefix="/cars_spare_parts", tags=["Cars Spare Parts"])

@router.post("/", response_model=CarsSparePartsResponse)
def create_new_cars_spare_parts(cars_spare_parts_data: CarsSparePartsCreate, db: Session = Depends(get_db)):
    return create_cars_spare_parts(db, cars_spare_parts_data)

@router.get("/{car_id}/{part_id}", response_model=CarsSparePartsResponse)
def read_cars_spare_parts(car_id: int, part_id: int, db: Session = Depends(get_db)):
    return get_cars_spare_parts_by_id(db, car_id, part_id)

@router.get("/", response_model=Dict[str, Any])
def read_cars_spare_parts_list(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all car spare part relations with pagination."""
    return get_all_cars_spare_parts(db, skip, limit)

@router.put("/{car_id}/{part_id}", response_model=CarsSparePartsResponse)
def update_existing_cars_spare_parts(car_id: int, part_id: int, cars_spare_parts_data: CarsSparePartsUpdate, db: Session = Depends(get_db)):
    return update_cars_spare_parts(db, car_id, part_id, cars_spare_parts_data)

@router.delete("/{car_id}/{part_id}", response_model=CarsSparePartsResponse)
def delete_existing_cars_spare_parts(car_id: int, part_id: int, db: Session = Depends(get_db)):
    return delete_cars_spare_parts(db, car_id, part_id)
