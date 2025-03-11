from sqlalchemy.orm import Session
from fastapi import HTTPException
from src.models.db_models import ServiceRequest
from src.schemas import ServiceRequestCreate, ServiceRequestUpdate, ServiceRequestResponse
from typing import List, Dict, Any

def create_service_request(db: Session, service_request_data: ServiceRequestCreate) -> ServiceRequestResponse:
    """Create a new service request."""
    db_service_request = ServiceRequest(**service_request_data.model_dump())
    db.add(db_service_request)
    db.commit()
    db.refresh(db_service_request)
    return ServiceRequestResponse.model_validate(db_service_request)

def get_service_request_by_id(db: Session, request_id: int) -> ServiceRequestResponse:
    """Retrieve a service request by ID."""
    service_request = db.query(ServiceRequest).filter(ServiceRequest.request_id == request_id).first()
    if not service_request:
        raise HTTPException(status_code=404, detail="Service request not found")
    return ServiceRequestResponse.model_validate(service_request)

def get_all_service_requests(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all service requests with optimized pagination."""

    total_count = db.query(ServiceRequest).count()  # Get total service request count
    service_requests = db.query(ServiceRequest).order_by(ServiceRequest.request_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [ServiceRequestResponse.model_validate(service_request) for service_request in service_requests]
    }


def update_service_request(db: Session, request_id: int, service_request_data: ServiceRequestUpdate) -> ServiceRequestResponse:
    """Update service request details."""
    service_request = db.query(ServiceRequest).filter(ServiceRequest.request_id == request_id).first()
    if not service_request:
        raise HTTPException(status_code=404, detail="Service request not found")
    
    update_data = service_request_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(service_request, key, value)
    
    db.commit()
    db.refresh(service_request)
    return ServiceRequestResponse.model_validate(service_request)

def delete_service_request(db: Session, request_id: int) -> ServiceRequestResponse:
    """Delete a service request."""
    service_request = db.query(ServiceRequest).filter(ServiceRequest.request_id == request_id).first()
    if not service_request:
        raise HTTPException(status_code=404, detail="Service request not found")
    
    db.delete(service_request)
    db.commit()
    return ServiceRequestResponse.model_validate(service_request)
