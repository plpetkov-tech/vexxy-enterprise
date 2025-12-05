"""
Billing API Endpoints

Provides REST API endpoints for billing, subscriptions, and credit management.
"""

from typing import List, Optional
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import (
    get_db,
    Organization,
    Subscription,
    BillingEvent,
    SubscriptionTier,
    SubscriptionStatus,
)
from middleware.authentication import get_current_user, AuthContext, require_admin
from services.billing import BillingService, QuotaService
from exceptions import ResourceNotFoundError

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])


# ============================================================================
# Pydantic Schemas
# ============================================================================


class SubscriptionResponse(BaseModel):
    """Subscription information response"""

    id: UUID
    organization_id: UUID
    tier: str
    status: str
    monthly_analysis_limit: Optional[int]
    monthly_credit_limit: Optional[int]
    current_period_analyses: int
    current_period_credits_used: int
    current_period_start: datetime
    current_period_end: datetime
    trial_end: Optional[datetime]
    cancel_at_period_end: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class CreditBalanceResponse(BaseModel):
    """Credit balance information"""

    organization_id: UUID
    credit_balance: int
    organization_name: str


class UsageResponse(BaseModel):
    """Usage statistics response"""

    organization_id: UUID
    current_period_analyses: int
    current_period_credits_used: int
    monthly_analysis_limit: Optional[int]
    monthly_credit_limit: Optional[int]
    current_period_start: str
    current_period_end: str
    utilization_percent: float


class BillingEventResponse(BaseModel):
    """Billing event response"""

    id: UUID
    organization_id: UUID
    event_type: str
    description: Optional[str]
    analysis_job_id: Optional[UUID]
    credits_amount: Optional[int]
    balance_after: Optional[int]
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateSubscriptionRequest(BaseModel):
    """Request to create or upgrade subscription"""

    tier: str = Field(
        ..., description="Subscription tier: starter, professional, enterprise"
    )
    payment_method_id: Optional[str] = Field(
        None, description="Stripe payment method ID"
    )


class PurchaseCreditsRequest(BaseModel):
    """Request to purchase credits"""

    amount: int = Field(
        ..., ge=100, description="Number of credits to purchase (minimum 100)"
    )
    payment_method_id: str = Field(..., description="Stripe payment method ID")


class TierInfo(BaseModel):
    """Subscription tier information"""

    tier: str
    monthly_analysis_limit: Optional[int]
    monthly_credit_limit: Optional[int]
    priority: int
    features: List[str]


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    auth: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get current subscription information for the authenticated user's organization

    Returns subscription details including tier, limits, and current usage.
    """
    subscription = (
        db.query(Subscription)
        .filter(Subscription.organization_id == auth.organization_id)
        .first()
    )

    if not subscription:
        raise ResourceNotFoundError("Subscription", str(auth.organization_id))

    return subscription


@router.get("/credits", response_model=CreditBalanceResponse)
async def get_credit_balance(
    auth: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get current credit balance for the authenticated user's organization
    """
    org = db.query(Organization).filter(Organization.id == auth.organization_id).first()

    if not org:
        raise ResourceNotFoundError("Organization", str(auth.organization_id))

    return CreditBalanceResponse(
        organization_id=org.id,
        credit_balance=org.credit_balance,
        organization_name=org.name,
    )


@router.get("/usage", response_model=UsageResponse)
async def get_usage_stats(
    auth: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get usage statistics for the current billing period
    """
    billing_service = BillingService(db)

    usage = billing_service.get_usage_stats(auth.organization_id)

    # Calculate utilization percentage
    utilization = 0.0
    if usage.get("monthly_credit_limit"):
        utilization = (
            usage["current_period_credits_used"] / usage["monthly_credit_limit"]
        ) * 100

    return UsageResponse(
        organization_id=auth.organization_id,
        current_period_analyses=usage["current_period_analyses"],
        current_period_credits_used=usage["current_period_credits_used"],
        monthly_analysis_limit=usage["monthly_analysis_limit"],
        monthly_credit_limit=usage["monthly_credit_limit"],
        current_period_start=usage["current_period_start"],
        current_period_end=usage["current_period_end"],
        utilization_percent=round(utilization, 2),
    )


@router.get("/events", response_model=List[BillingEventResponse])
async def get_billing_events(
    limit: int = 50,
    offset: int = 0,
    auth: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get billing event history for the authenticated user's organization

    Returns a paginated list of billing events (credits purchased, analysis costs, etc.)
    """
    events = (
        db.query(BillingEvent)
        .filter(BillingEvent.organization_id == auth.organization_id)
        .order_by(BillingEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )

    return events


@router.post("/subscription", response_model=SubscriptionResponse)
async def create_or_upgrade_subscription(
    request: CreateSubscriptionRequest,
    auth: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Create or upgrade subscription (admin only)

    Creates a new paid subscription or upgrades an existing subscription to a higher tier.
    Requires admin privileges.
    """
    quota_service = QuotaService(db)

    # Validate tier
    try:
        tier = SubscriptionTier[request.tier.upper()]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier: {request.tier}. Valid tiers: starter, professional, enterprise",
        )

    # Get or create organization
    org = db.query(Organization).filter(Organization.id == auth.organization_id).first()
    if not org:
        raise ResourceNotFoundError("Organization", str(auth.organization_id))

    # Get tier configuration
    tier_config = quota_service.get_tier_limits(tier)

    # Get existing subscription
    subscription = (
        db.query(Subscription)
        .filter(Subscription.organization_id == auth.organization_id)
        .first()
    )

    if subscription:
        # Upgrade existing subscription
        subscription.tier = tier
        subscription.monthly_analysis_limit = tier_config["monthly_analysis_limit"]
        subscription.monthly_credit_limit = tier_config["monthly_credit_limit"]
        db.commit()
        db.refresh(subscription)

        # TODO: Create/update Stripe subscription if payment_method_id provided

    else:
        # Create new subscription
        from datetime import timedelta

        now = datetime.utcnow()

        subscription = Subscription(
            organization_id=auth.organization_id,
            tier=tier,
            status=SubscriptionStatus.ACTIVE,
            monthly_analysis_limit=tier_config["monthly_analysis_limit"],
            monthly_credit_limit=tier_config["monthly_credit_limit"],
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)

        # TODO: Create Stripe subscription if payment_method_id provided

    return subscription


@router.post("/credits/purchase")
async def purchase_credits(
    request: PurchaseCreditsRequest,
    auth: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Purchase additional credits (admin only)

    Allows purchasing additional credits beyond the monthly subscription limit.
    Requires admin privileges.
    """
    billing_service = BillingService(db)

    # TODO: Process payment with Stripe using payment_method_id
    # For now, just add credits

    # Calculate cost (e.g., $0.10 per credit)
    cost_usd = request.amount * 0.10

    # Add credits
    new_balance = billing_service.add_credits(
        auth.organization_id,
        request.amount,
        description=f"Purchased {request.amount} credits for ${cost_usd:.2f}",
    )

    return {
        "success": True,
        "credits_purchased": request.amount,
        "cost_usd": cost_usd,
        "new_balance": new_balance,
    }


@router.get("/tiers", response_model=List[TierInfo])
async def get_subscription_tiers():
    """
    Get information about available subscription tiers

    Public endpoint that returns pricing and feature information for all tiers.
    """
    quota_service = QuotaService(None)  # No DB needed for tier info

    tiers = []
    for tier in SubscriptionTier:
        tier_config = quota_service.get_tier_limits(tier)
        tiers.append(
            TierInfo(
                tier=tier.value,
                monthly_analysis_limit=tier_config["monthly_analysis_limit"],
                monthly_credit_limit=tier_config["monthly_credit_limit"],
                priority=tier_config["priority"],
                features=tier_config["features"],
            )
        )

    return tiers


@router.delete("/subscription")
async def cancel_subscription(
    at_period_end: bool = True,
    auth: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Cancel subscription (admin only)

    Cancels the organization's subscription. By default, cancels at the end of the
    current billing period. Set at_period_end=false to cancel immediately.
    """
    subscription = (
        db.query(Subscription)
        .filter(Subscription.organization_id == auth.organization_id)
        .first()
    )

    if not subscription:
        raise ResourceNotFoundError("Subscription", str(auth.organization_id))

    if at_period_end:
        subscription.cancel_at_period_end = True
        db.commit()
        message = "Subscription will be canceled at the end of the current period"
    else:
        subscription.status = SubscriptionStatus.CANCELED
        subscription.canceled_at = datetime.utcnow()
        db.commit()
        message = "Subscription canceled immediately"

        # TODO: Cancel Stripe subscription

    return {
        "success": True,
        "message": message,
        "canceled_at": (
            subscription.canceled_at.isoformat() if subscription.canceled_at else None
        ),
    }
