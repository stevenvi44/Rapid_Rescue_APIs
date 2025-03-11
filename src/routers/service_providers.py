from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import ServiceProviderCreate, ServiceProviderUpdate, ServiceProviderResponse
from src.crud.service_providers import (
    create_service_provider,
    get_service_provider_by_id,
    get_all_service_providers,
    update_service_provider,
    delete_service_provider,
)
from typing import Dict, Any

router = APIRouter(prefix="/service_providers", tags=["Service Providers"])

@router.post("/", response_model=ServiceProviderResponse)
def create_new_service_provider(service_provider_data: ServiceProviderCreate, db: Session = Depends(get_db)):
    return create_service_provider(db, service_provider_data)

@router.get("/{service_provider_id}", response_model=ServiceProviderResponse)
def read_service_provider(service_provider_id: int, db: Session = Depends(get_db)):
    return get_service_provider_by_id(db, service_provider_id)

@router.get("/", response_model=Dict[str, Any])
def read_service_providers(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all service providers with pagination."""
    return get_all_service_providers(db, skip, limit)

@router.put("/{service_provider_id}", response_model=ServiceProviderResponse)
def update_existing_service_provider(service_provider_id: int, service_provider_data: ServiceProviderUpdate, db: Session = Depends(get_db)):
    return update_service_provider(db, service_provider_id, service_provider_data)

@router.delete("/{service_provider_id}", response_model=ServiceProviderResponse)
def delete_existing_service_provider(service_provider_id: int, db: Session = Depends(get_db)):
    return delete_service_provider(db, service_provider_id)
