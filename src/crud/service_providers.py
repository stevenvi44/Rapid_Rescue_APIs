from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import ServiceProvider
from src.schemas import ServiceProviderCreate, ServiceProviderUpdate, ServiceProviderResponse
from typing import List, Dict, Any

def create_service_provider(db: Session, service_provider_data: ServiceProviderCreate) -> ServiceProviderResponse:
    """Create a new service provider."""
    db_service_provider = ServiceProvider(**service_provider_data.model_dump())
    db.add(db_service_provider)
    db.commit()
    db.refresh(db_service_provider)
    return ServiceProviderResponse.model_validate(db_service_provider)

def get_service_provider_by_id(db: Session, service_provider_id: int) -> ServiceProviderResponse:
    """Retrieve a service provider by ID."""
    service_provider = db.query(ServiceProvider).filter(ServiceProvider.service_provider_id == service_provider_id).first()
    if not service_provider:
        raise HTTPException(status_code=404, detail="Service provider not found")
    return ServiceProviderResponse.model_validate(service_provider)

def get_all_service_providers(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all service providers with optimized pagination."""
    
    total_count = db.query(ServiceProvider).count()  # Get total count of service providers
    service_providers = db.query(ServiceProvider).order_by(ServiceProvider.service_provider_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [ServiceProviderResponse.model_validate(sp) for sp in service_providers]
    }

def update_service_provider(db: Session, service_provider_id: int, service_provider_data: ServiceProviderUpdate) -> ServiceProviderResponse:
    """Update service provider details."""
    service_provider = db.query(ServiceProvider).filter(ServiceProvider.service_provider_id == service_provider_id).first()
    if not service_provider:
        raise HTTPException(status_code=404, detail="Service provider not found")
    
    update_data = service_provider_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(service_provider, key, value)
    
    db.commit()
    db.refresh(service_provider)
    return ServiceProviderResponse.model_validate(service_provider)

def delete_service_provider(db: Session, service_provider_id: int) -> ServiceProviderResponse:
    """Delete a service provider."""
    service_provider = db.query(ServiceProvider).filter(ServiceProvider.service_provider_id == service_provider_id).first()
    if not service_provider:
        raise HTTPException(status_code=404, detail="Service provider not found")
    
    db.delete(service_provider)
    db.commit()
    return ServiceProviderResponse.model_validate(service_provider)
