from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import AIPreventiveMaintenanceCreate, AIPreventiveMaintenanceUpdate, AIPreventiveMaintenanceResponse
from src.crud.ai_preventive_maintenance import (
    create_ai_preventive_maintenance,
    get_ai_preventive_maintenance_by_id,
    get_all_ai_preventive_maintenance,
    update_ai_preventive_maintenance,
    delete_ai_preventive_maintenance,
)
from typing import Dict, Any

router = APIRouter(prefix="/ai_preventive_maintenance", tags=["AI Preventive Maintenance"])

@router.post("/", response_model=AIPreventiveMaintenanceResponse)
def create_new_maintenance(maintenance_data: AIPreventiveMaintenanceCreate, db: Session = Depends(get_db)):
    return create_ai_preventive_maintenance(db, maintenance_data)

@router.get("/{maintenance_id}", response_model=AIPreventiveMaintenanceResponse)
def read_maintenance(maintenance_id: int, db: Session = Depends(get_db)):
    return get_ai_preventive_maintenance_by_id(db, maintenance_id)

@router.get("/", response_model=Dict[str, Any])
def read_all_maintenances(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all AI preventive maintenance records with pagination."""
    return get_all_ai_preventive_maintenance(db, skip, limit)

@router.put("/{maintenance_id}", response_model=AIPreventiveMaintenanceResponse)
def update_existing_maintenance(maintenance_id: int, maintenance_data: AIPreventiveMaintenanceUpdate, db: Session = Depends(get_db)):
    return update_ai_preventive_maintenance(db, maintenance_id, maintenance_data)

@router.delete("/{maintenance_id}", response_model=AIPreventiveMaintenanceResponse)
def delete_existing_maintenance(maintenance_id: int, db: Session = Depends(get_db)):
    return delete_ai_preventive_maintenance(db, maintenance_id)
