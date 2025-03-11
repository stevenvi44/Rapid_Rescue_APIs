from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import UserCreate, UserUpdate, UserResponse
from src.crud.users import create_user, get_user_by_id, update_user, get_all_users, delete_user
from src.routers.auth import get_current_user, get_admin_user
from typing import Dict, Any, List
from src.models.db_models import User

router = APIRouter(prefix="/users", tags=["Users"])

@router.post("/", response_model=UserResponse)
def create_new_user(
    user_data: UserCreate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_admin_user)  # Admin only
):
    return create_user(db, user_data)

@router.get("/", response_model=Dict[str, Any])
def read_all_users(
    skip: int = 0, 
    limit: int = 10, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_admin_user)  # Admin only
):
    """Retrieve all users with pagination."""
    return get_all_users(db, skip, limit)

@router.get("/{user_id}", response_model=UserResponse)
def read_user(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)  # Self or Admin
):
    user = get_user_by_id(db, user_id)
    
    # Ensure the user can only access their own data unless they are an admin
    if current_user.role != "admin" and current_user.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    return user

@router.put("/{user_id}", response_model=UserResponse)
def update_existing_user(
    user_id: int, 
    user_data: UserUpdate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)  # Self or Admin
):
    user = get_user_by_id(db, user_id)

    # Ensure the user can only update their own data unless they are an admin
    if current_user.role != "admin" and current_user.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    return update_user(db, user_id, user_data)

@router.delete("/{user_id}", response_model=UserResponse)
def delete_existing_user(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_admin_user)  # Admin only
):
    return delete_user(db, user_id)


# from fastapi import APIRouter, Depends, HTTPException, status
# from sqlalchemy.orm import Session
# from src.database import get_db
# from src.schemas import UserCreate, UserUpdate, UserResponse
# from src.crud.users import create_user, get_user_by_id, update_user, get_all_users, delete_user
# from src.routers.auth import get_current_user, get_admin_user
# from src.models.db_models import User

# router = APIRouter(prefix="/users", tags=["Users"])

# @router.post("/", response_model=UserResponse)
# def create_new_user(user_data: UserCreate, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
#     return create_user(db, user_data)

# @router.get("/", response_model=list[UserResponse])
# def read_all_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
#     return get_all_users(db, skip, limit)

# @router.get("/{user_id}", response_model=UserResponse)
# def read_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
#     user = get_user_by_id(db, user_id)
#     if current_user.role != "admin" and current_user.user_id != user_id:
#         raise HTTPException(status_code=403, detail="Not enough permissions")
#     return user

# @router.put("/{user_id}", response_model=UserResponse)
# def update_existing_user(user_id: int, user_data: UserUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
#     return update_user(db, user_id, user_data)

# @router.delete("/{user_id}", response_model=UserResponse)
# def delete_existing_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
#     return delete_user(db, user_id)
