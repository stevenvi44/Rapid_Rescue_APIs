from sqlalchemy.orm import Session
from src.models.db_models import Transaction
from src.schemas import TransactionCreate, TransactionUpdate, TransactionResponse
from typing import List, Dict, Any

def create_transaction(db: Session, transaction_data: TransactionCreate):
    new_transaction = Transaction(**transaction_data.model_dump())
    db.add(new_transaction)
    db.commit()
    db.refresh(new_transaction)
    return new_transaction

def get_transactions(db: Session):
    return db.query(Transaction).all()

def get_transaction_by_id(db: Session, transaction_id: int):
    return db.query(Transaction).filter(Transaction.transaction_id == transaction_id).first()

def get_all_transactions(db: Session, skip: int = 0, limit: int = 10) -> Dict[str, Any]:
    """Retrieve all transactions with optimized pagination."""
    
    total_count = db.query(Transaction).count()  # Get total transaction count
    transactions = db.query(Transaction).order_by(Transaction.transaction_id).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "has_next": (skip + limit) < total_count,
        "data": [TransactionResponse.model_validate(transaction) for transaction in transactions]
    }


def update_transaction(db: Session, transaction_id: int, transaction_data: TransactionUpdate):
    transaction = db.query(Transaction).filter(Transaction.transaction_id == transaction_id).first()
    if transaction:
        for key, value in transaction_data.model_dump(exclude_unset=True).items():
            setattr(transaction, key, value)
        db.commit()
        db.refresh(transaction)
    return transaction

def delete_transaction(db: Session, transaction_id: int):
    transaction = db.query(Transaction).filter(Transaction.transaction_id == transaction_id).first()
    if transaction:
        db.delete(transaction)
        db.commit()
    return transaction
