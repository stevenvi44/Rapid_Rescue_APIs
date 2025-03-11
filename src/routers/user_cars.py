from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import UserCarCreate, UserCarUpdate, UserCarResponse
from src.crud.user_cars import create_user_car, get_user_car_by_id, update_user_car, delete_user_car, get_all_user_cars
from typing import Dict, Any

router = APIRouter(prefix="/user_cars", tags=["User Cars"])

@router.post("/", response_model=UserCarResponse)
def create_new_user_car(user_car_data: UserCarCreate, db: Session = Depends(get_db)):
    return create_user_car(db, user_car_data)

@router.get("/{user_car_id}", response_model=UserCarResponse)
def read_user_car(user_car_id: int, db: Session = Depends(get_db)):
    return get_user_car_by_id(db, user_car_id)

@router.get("/", response_model=Dict[str, Any])
def read_all_user_cars(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all user cars with pagination."""
    return get_all_user_cars(db, skip, limit)

@router.put("/{user_car_id}", response_model=UserCarResponse)
def update_existing_user_car(user_car_id: int, user_car_data: UserCarUpdate, db: Session = Depends(get_db)):
    return update_user_car(db, user_car_id, user_car_data)

@router.delete("/{user_car_id}", response_model=UserCarResponse)
def delete_existing_user_car(user_car_id: int, db: Session = Depends(get_db)):
    return delete_user_car(db, user_car_id)
