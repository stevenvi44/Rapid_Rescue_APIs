from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import AIPreventiveMaintenance
from src.schemas import AIPreventiveMaintenanceCreate, AIPreventiveMaintenanceUpdate, AIPreventiveMaintenanceResponse
from src.database import SessionLocal
from typing import List, Dict, Any

def create_ai_preventive_maintenance(db: Session, maintenance_data: AIPreventiveMaintenanceCreate) -> AIPreventiveMaintenanceResponse:
    """Create a new AI preventive maintenance record."""
    db_maintenance = AIPreventiveMaintenance(**maintenance_data.model_dump())
    db.add(db_maintenance)
    db.commit()
    db.refresh(db_maintenance)
    return AIPreventiveMaintenanceResponse.model_validate(db_maintenance)

def get_ai_preventive_maintenance_by_id(db: Session, maintenance_id: int) -> AIPreventiveMaintenanceResponse:
    """Retrieve an AI preventive maintenance record by ID."""
    maintenance = db.query(AIPreventiveMaintenance).filter(AIPreventiveMaintenance.maintenance_id == maintenance_id).first()
    if not maintenance:
        raise HTTPException(status_code=404, detail="AI preventive maintenance record not found")
    return AIPreventiveMaintenanceResponse.model_validate(maintenance)

def get_all_ai_preventive_maintenance(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all AI preventive maintenance records with optimized pagination."""
    
    total_count = db.query(AIPreventiveMaintenance).count()  # Get total record count
    maintenances = db.query(AIPreventiveMaintenance).order_by(AIPreventiveMaintenance.maintenance_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [AIPreventiveMaintenanceResponse.model_validate(maintenance) for maintenance in maintenances]
    }


def update_ai_preventive_maintenance(db: Session, maintenance_id: int, maintenance_data: AIPreventiveMaintenanceUpdate) -> AIPreventiveMaintenanceResponse:
    """Update AI preventive maintenance record details."""
    maintenance = db.query(AIPreventiveMaintenance).filter(AIPreventiveMaintenance.maintenance_id == maintenance_id).first()
    if not maintenance:
        raise HTTPException(status_code=404, detail="AI preventive maintenance record not found")
    
    update_data = maintenance_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(maintenance, key, value)
    
    db.commit()
    db.refresh(maintenance)
    return AIPreventiveMaintenanceResponse.model_validate(maintenance)

def delete_ai_preventive_maintenance(db: Session, maintenance_id: int) -> AIPreventiveMaintenanceResponse:
    """Delete an AI preventive maintenance record."""
    maintenance = db.query(AIPreventiveMaintenance).filter(AIPreventiveMaintenance.maintenance_id == maintenance_id).first()
    if not maintenance:
        raise HTTPException(status_code=404, detail="AI preventive maintenance record not found")
    
    db.delete(maintenance)
    db.commit()
    return AIPreventiveMaintenanceResponse.model_validate(maintenance)

# Dependency function for FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
