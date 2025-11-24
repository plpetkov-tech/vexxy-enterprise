"""
Billing and subscription models
"""
from sqlalchemy import Column, String, Integer, DateTime, Enum, Text, Boolean, Float, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from .database import Base


class SubscriptionTier(str, enum.Enum):
    """Subscription tier levels"""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, enum.Enum):
    """Subscription status"""
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"


class BillingEventType(str, enum.Enum):
    """Types of billing events"""
    ANALYSIS_COMPLETED = "analysis_completed"
    CREDIT_PURCHASED = "credit_purchased"
    CREDIT_DEDUCTED = "credit_deducted"
    SUBSCRIPTION_CREATED = "subscription_created"
    SUBSCRIPTION_UPDATED = "subscription_updated"
    SUBSCRIPTION_CANCELED = "subscription_canceled"
    PAYMENT_SUCCEEDED = "payment_succeeded"
    PAYMENT_FAILED = "payment_failed"


class Organization(Base):
    """Organization/Company entity"""
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)

    # Stripe integration
    stripe_customer_id = Column(String(255), unique=True, nullable=True, index=True)

    # Billing
    credit_balance = Column(Integer, default=0, nullable=False)  # Available credits

    # Settings
    settings = Column(String, nullable=True)  # JSON serialized settings

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)  # Soft delete

    def __repr__(self):
        return f"<Organization {self.id} - {self.name}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "name": self.name,
            "slug": self.slug,
            "credit_balance": self.credit_balance,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class User(Base):
    """User entity"""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # User details
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)  # Org admin
    email_verified = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)  # Soft delete

    def __repr__(self):
        return f"<User {self.id} - {self.email}>"

    def to_dict(self):
        """Convert to dictionary (exclude password)"""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "email": self.email,
            "name": self.name,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "email_verified": self.email_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }


class Subscription(Base):
    """Subscription plan for an organization"""
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True  # One active subscription per organization
    )

    # Subscription details
    tier = Column(Enum(SubscriptionTier), nullable=False, default=SubscriptionTier.FREE, index=True)
    status = Column(Enum(SubscriptionStatus), nullable=False, default=SubscriptionStatus.ACTIVE, index=True)

    # Stripe integration
    stripe_subscription_id = Column(String(255), unique=True, nullable=True, index=True)
    stripe_price_id = Column(String(255), nullable=True)

    # Limits (null means unlimited for enterprise)
    monthly_analysis_limit = Column(Integer, nullable=True)  # Max analyses per month
    monthly_credit_limit = Column(Integer, nullable=True)  # Max credits per month

    # Usage tracking for current period
    current_period_analyses = Column(Integer, default=0, nullable=False)
    current_period_credits_used = Column(Integer, default=0, nullable=False)

    # Period tracking
    current_period_start = Column(DateTime, nullable=False, default=datetime.utcnow)
    current_period_end = Column(DateTime, nullable=False)

    # Trial
    trial_start = Column(DateTime, nullable=True)
    trial_end = Column(DateTime, nullable=True)

    # Cancellation
    cancel_at_period_end = Column(Boolean, default=False, nullable=False)
    canceled_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<Subscription {self.id} - {self.tier.value} ({self.status.value})>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "tier": self.tier.value,
            "status": self.status.value,
            "monthly_analysis_limit": self.monthly_analysis_limit,
            "monthly_credit_limit": self.monthly_credit_limit,
            "current_period_analyses": self.current_period_analyses,
            "current_period_credits_used": self.current_period_credits_used,
            "current_period_start": self.current_period_start.isoformat() if self.current_period_start else None,
            "current_period_end": self.current_period_end.isoformat() if self.current_period_end else None,
            "trial_end": self.trial_end.isoformat() if self.trial_end else None,
            "cancel_at_period_end": self.cancel_at_period_end,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class BillingEvent(Base):
    """Billing event ledger for audit trail"""
    __tablename__ = "billing_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Event details
    event_type = Column(Enum(BillingEventType), nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Related entities
    analysis_job_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    subscription_id = Column(UUID(as_uuid=True), nullable=True)

    # Financial details
    credits_amount = Column(Integer, nullable=True)  # Credits added/deducted
    balance_after = Column(Integer, nullable=True)  # Credit balance after event

    # Stripe reference
    stripe_event_id = Column(String(255), unique=True, nullable=True, index=True)
    stripe_payment_intent_id = Column(String(255), nullable=True)

    # Metadata
    event_metadata = Column(String, nullable=True)  # JSON serialized additional data

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<BillingEvent {self.id} - {self.event_type.value}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "event_type": self.event_type.value,
            "description": self.description,
            "analysis_job_id": str(self.analysis_job_id) if self.analysis_job_id else None,
            "credits_amount": self.credits_amount,
            "balance_after": self.balance_after,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class APIKey(Base):
    """API keys for programmatic access"""
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Key details
    name = Column(String(255), nullable=False)
    key_prefix = Column(String(20), nullable=False)  # First few chars for display
    hashed_key = Column(String(255), unique=True, nullable=False, index=True)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)

    # Usage tracking
    last_used_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<APIKey {self.id} - {self.name}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "name": self.name,
            "key_prefix": self.key_prefix,
            "is_active": self.is_active,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
