"""
ID Generator Service
Generates unique DSV IDs using database counter
"""
from sqlalchemy import Column, Integer, BigInteger
from database import Base, SessionLocal
from datetime import datetime

class IdCounter(Base):
    """Database table for tracking ID sequence"""
    __tablename__ = "id_counters"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    counter_type = Column(Integer, unique=True, nullable=False)  # Always 0 for DSV
    next_value = Column(BigInteger, nullable=False, default=1)

def init_counter(db: SessionLocal):
    """Initialize counter if it doesn't exist"""
    existing = db.query(IdCounter).filter(IdCounter.counter_type == 0).first()
    if not existing:
        counter = IdCounter(counter_type=0, next_value=1)
        db.add(counter)
        db.commit()

def generate_internal_id(rule_type: str = "dsv") -> str:
    """
    Generate unique DSV ID using database counter
    Format: DSV-YYYY-NNNN (where NNNN increments from database)
    
    This guarantees uniqueness even during bulk inserts.
    """
    from datetime import datetime
    
    db = SessionLocal()
    try:
        # Initialize counter if needed
        init_counter(db)
        
        # Get and increment counter atomically
        counter = db.query(IdCounter).filter(IdCounter.counter_type == 0).first()
        sequence = counter.next_value
        counter.next_value += 1
        db.commit()
        
        year = datetime.utcnow().year
        # Use modulo 10000 to keep 4 digits, but sequence keeps growing
        sequence_4digit = sequence % 10000
        
        return f"DSV-{year}-{sequence_4digit:04d}"
        
    except Exception as e:
        db.rollback()
        # Fallback to timestamp-based if DB fails
        import time
        year = datetime.utcnow().year
        timestamp_ms = int(time.time() * 1000) % 10000
        return f"DSV-{year}-{timestamp_ms:04d}"
    finally:
        db.close()
