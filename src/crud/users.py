from sqlalchemy.orm import Session
from src.models.db_models import User
from src.schemas import UserCreate, UserUpdate, UserResponse
from src.database import SessionLocal
from fastapi import HTTPException
from typing import List, Dict, Any

from src.routers.auth import hash_password  # Ensure hash_password is imported

def create_user(db: Session, user_data: UserCreate):
    """Create a new user with a hashed password."""
    
    # Ensure the password is hashed before storing
    user_data.password = hash_password(user_data.password)

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        phone_number=user_data.phone_number,
        password=user_data.password,  # Store the hashed password
        location=user_data.location,
        is_active=True,
        role=user_data.role or "user"
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def get_user_by_id(db: Session, user_id: int) -> UserResponse:
    """Retrieve a user by ID."""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)

def get_all_users(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all users with optimized pagination."""
    
    total_count = db.query(User).count()  # Get total user count
    users = db.query(User).order_by(User.user_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [UserResponse.model_validate(user) for user in users]
    }

def update_user(db: Session, user_id: int, user_data: UserUpdate) -> UserResponse:
    """Update user details."""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_data = user_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)

def delete_user(db: Session, user_id: int) -> UserResponse:
    """Delete a user."""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return UserResponse.model_validate(user)

# Dependency function for FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()