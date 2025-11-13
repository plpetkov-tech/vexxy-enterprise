"""
Premium VEX Service Configuration

Environment-based configuration using pydantic-settings
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )

    # Service Info
    service_name: str = "premium-vex-service"
    version: str = "0.1.0"
    environment: str = "development"

    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8001
    api_prefix: str = "/api/v1"

    # Database
    database_url: str = "postgresql://vexxy:vexxy@localhost:5432/vexxy_premium"
    database_pool_size: int = 5
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"
    celery_task_time_limit: int = 1800  # 30 minutes
    celery_task_soft_time_limit: int = 1500  # 25 minutes

    # Kubernetes
    k8s_sandbox_namespace: str = "vexxy-sandbox"
    k8s_job_ttl_seconds: int = 600  # 10 minutes after completion
    k8s_in_cluster: bool = False  # Set True when running in K8s

    # Sandbox Resources
    sandbox_cpu_limit: str = "2"
    sandbox_memory_limit: str = "4Gi"
    sandbox_cpu_request: str = "1"
    sandbox_memory_request: str = "2Gi"

    # Analysis Settings
    default_analysis_timeout: int = 900  # 15 minutes
    max_analysis_timeout: int = 1800  # 30 minutes

    # Storage
    storage_backend: str = "local"  # local, s3, gcs, minio
    storage_path: str = "/tmp/vexxy-premium"

    # S3 (if using)
    s3_bucket: Optional[str] = None
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None
    s3_endpoint: Optional[str] = None

    # Authentication
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"

    # VEXxy Core Integration
    vexxy_backend_url: str = "http://localhost:8000"
    vexxy_api_key: Optional[str] = None

    # Monitoring
    enable_metrics: bool = True
    metrics_port: int = 9090

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text


# Global settings instance
settings = Settings()
