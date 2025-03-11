from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import TransactionCreate, TransactionUpdate, TransactionResponse
from src.crud.transactions import (
    create_transaction, 
    get_all_transactions, 
    get_transaction_by_id, 
    update_transaction, 
    delete_transaction
)
from typing import Dict, Any

router = APIRouter(
    prefix="/transactions",
    tags=["Transactions"]
)

@router.post("/", response_model=TransactionResponse)
def create_new_transaction(transaction_data: TransactionCreate, db: Session = Depends(get_db)):
    return create_transaction(db, transaction_data)

@router.get("/{transaction_id}", response_model=TransactionResponse)
def read_transaction(transaction_id: int, db: Session = Depends(get_db)):
    transaction = get_transaction_by_id(db, transaction_id)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return transaction

@router.get("/", response_model=Dict[str, Any])
def read_all_transactions(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve all transactions with pagination."""
    return get_all_transactions(db, skip, limit)

@router.put("/{transaction_id}", response_model=TransactionResponse)
def update_existing_transaction(transaction_id: int, transaction_data: TransactionUpdate, db: Session = Depends(get_db)):
    transaction = update_transaction(db, transaction_id, transaction_data)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return transaction

@router.delete("/{transaction_id}", response_model=TransactionResponse)
def delete_existing_transaction(transaction_id: int, db: Session = Depends(get_db)):
    transaction = delete_transaction(db, transaction_id)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return transaction
