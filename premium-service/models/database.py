"""
Database connection and session management
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator, Any

from config.settings import settings

# Create database engine
engine = create_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_timeout=settings.database_pool_timeout,  # Added for autoscaling
    echo=settings.environment == "development",
    pool_pre_ping=True,  # Test connections before using
    pool_recycle=3600,  # Recycle connections after 1 hour
    connect_args={"connect_timeout": 10, "application_name": "vexxy-premium-service"},
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base: Any = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for getting database session

    Usage in FastAPI:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    # Import all models here to ensure they're registered
    from models import analysis  # noqa
    from models import billing  # noqa

    Base.metadata.create_all(bind=engine)
