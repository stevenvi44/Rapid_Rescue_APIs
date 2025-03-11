from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import ServiceRequestCreate, ServiceRequestUpdate, ServiceRequestResponse
from src.crud.service_requests import (
    create_service_request,
    get_service_request_by_id,
    get_all_service_requests,
    update_service_request,
    delete_service_request,
)
from typing import List, Dict, Any

router = APIRouter(prefix="/service_requests", tags=["Service Requests"])

@router.post("/", response_model=ServiceRequestResponse)
def create_new_service_request(service_request_data: ServiceRequestCreate, db: Session = Depends(get_db)):
    return create_service_request(db, service_request_data)

@router.get("/{request_id}", response_model=ServiceRequestResponse)
def read_service_request(request_id: int, db: Session = Depends(get_db)):
    return get_service_request_by_id(db, request_id)

@router.get("/", response_model=Dict[str, Any])
def read_service_requests(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all service requests with pagination."""
    return get_all_service_requests(db, skip, limit)

@router.put("/{request_id}", response_model=ServiceRequestResponse)
def update_existing_service_request(request_id: int, service_request_data: ServiceRequestUpdate, db: Session = Depends(get_db)):
    return update_service_request(db, request_id, service_request_data)

@router.delete("/{request_id}", response_model=ServiceRequestResponse)
def delete_existing_service_request(request_id: int, db: Session = Depends(get_db)):
    return delete_service_request(db, request_id)
