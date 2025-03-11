from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import UserCar
from src.schemas import UserCarCreate, UserCarUpdate, UserCarResponse
from typing import List, Dict, Any

def create_user_car(db: Session, user_car_data: UserCarCreate) -> UserCarResponse:
    """Create a new user car record."""
    db_user_car = UserCar(**user_car_data.model_dump())
    db.add(db_user_car)
    db.commit()
    db.refresh(db_user_car)
    return UserCarResponse.model_validate(db_user_car)

def get_user_car_by_id(db: Session, user_car_id: int) -> UserCarResponse:
    """Retrieve a user car record by ID."""
    user_car = db.query(UserCar).filter(UserCar.user_car_id == user_car_id).first()
    if not user_car:
        raise HTTPException(status_code=404, detail="User car record not found")
    return UserCarResponse.model_validate(user_car)

def get_all_user_cars(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all user car records with optimized pagination."""
    
    total_count = db.query(UserCar).count()  # Get total user car count
    user_cars = db.query(UserCar).order_by(UserCar.user_car_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [UserCarResponse.model_validate(user_car) for user_car in user_cars]
    }


def update_user_car(db: Session, user_car_id: int, user_car_data: UserCarUpdate) -> UserCarResponse:
    """Update an existing user car record."""
    user_car = db.query(UserCar).filter(UserCar.user_car_id == user_car_id).first()
    if not user_car:
        raise HTTPException(status_code=404, detail="User car record not found")
    
    update_data = user_car_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user_car, key, value)
    
    db.commit()
    db.refresh(user_car)
    return UserCarResponse.model_validate(user_car)

def delete_user_car(db: Session, user_car_id: int) -> UserCarResponse:
    """Delete a user car record."""
    user_car = db.query(UserCar).filter(UserCar.user_car_id == user_car_id).first()
    if not user_car:
        raise HTTPException(status_code=404, detail="User car record not found")
    
    db.delete(user_car)
    db.commit()
    return UserCarResponse.model_validate(user_car)
