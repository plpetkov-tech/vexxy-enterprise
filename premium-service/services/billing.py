"""
Billing and Stripe Integration Services

Manages Stripe integration, subscription management, and quota enforcement.
"""

from typing import Dict, Optional, Tuple, Any
import logging
from datetime import datetime, timedelta
from uuid import UUID
import json

import stripe
from sqlalchemy.orm import Session

from config.settings import settings
from models import (
    Organization,
    Subscription,
    BillingEvent,
    SubscriptionTier,
    SubscriptionStatus,
    BillingEventType,
    PremiumAnalysisJob,
)
from utils.exceptions import QuotaExceededError

logger = logging.getLogger(__name__)


class StripeService:
    """
    Stripe API integration service

    Handles all interactions with Stripe API for payments, subscriptions, and customer management.
    """

    def __init__(self):
        """Initialize Stripe with API key"""
        stripe.api_key = settings.stripe_secret_key
        logger.info("Stripe service initialized")

    def create_customer(self, organization: Organization, email: str) -> str:
        """
        Create a Stripe customer for an organization

        Args:
            organization: Organization entity
            email: Customer email

        Returns:
            Stripe customer ID
        """
        try:
            customer = stripe.Customer.create(
                email=email,
                name=organization.name,
                metadata={
                    "organization_id": str(organization.id),
                    "organization_slug": organization.slug,
                },
            )
            logger.info(
                f"Created Stripe customer {customer.id} for org {organization.id}"
            )
            return customer.id

        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe customer: {e}", exc_info=True)
            raise

    def create_subscription(
        self, customer_id: str, price_id: str, trial_days: Optional[int] = None
    ) -> Dict:
        """
        Create a Stripe subscription

        Args:
            customer_id: Stripe customer ID
            price_id: Stripe price ID for the plan
            trial_days: Optional trial period in days

        Returns:
            Subscription data dictionary
        """
        try:
            params: Dict[str, Any] = {
                "customer": customer_id,
                "items": [{"price": price_id}],
                "payment_behavior": "default_incomplete",
                "expand": ["latest_invoice.payment_intent"],
            }

            if trial_days:
                params["trial_period_days"] = trial_days

            subscription = stripe.Subscription.create(**params)
            logger.info(
                f"Created Stripe subscription {subscription.id} for customer {customer_id}"
            )

            return {
                "subscription_id": subscription.id,
                "status": subscription.status,
                "current_period_start": datetime.fromtimestamp(
                    subscription.current_period_start
                ),
                "current_period_end": datetime.fromtimestamp(
                    subscription.current_period_end
                ),
                "trial_end": (
                    datetime.fromtimestamp(subscription.trial_end)
                    if subscription.trial_end
                    else None
                ),
                "client_secret": (
                    subscription.latest_invoice.payment_intent.client_secret
                    if subscription.latest_invoice
                    else None
                ),
            }

        except stripe.error.StripeError as e:
            logger.error(f"Failed to create subscription: {e}", exc_info=True)
            raise

    def cancel_subscription(
        self, subscription_id: str, at_period_end: bool = True
    ) -> Dict:
        """
        Cancel a Stripe subscription

        Args:
            subscription_id: Stripe subscription ID
            at_period_end: If True, cancel at period end; if False, cancel immediately

        Returns:
            Updated subscription data
        """
        try:
            if at_period_end:
                subscription = stripe.Subscription.modify(
                    subscription_id, cancel_at_period_end=True
                )
            else:
                subscription = stripe.Subscription.delete(subscription_id)

            logger.info(
                f"Canceled subscription {subscription_id} (at_period_end={at_period_end})"
            )

            return {
                "subscription_id": subscription.id,
                "status": subscription.status,
                "cancel_at_period_end": subscription.cancel_at_period_end,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Failed to cancel subscription: {e}", exc_info=True)
            raise

    def get_subscription(self, subscription_id: str) -> Dict:
        """
        Retrieve subscription details from Stripe

        Args:
            subscription_id: Stripe subscription ID

        Returns:
            Subscription data dictionary
        """
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            return {
                "subscription_id": subscription.id,
                "status": subscription.status,
                "current_period_start": datetime.fromtimestamp(
                    subscription.current_period_start
                ),
                "current_period_end": datetime.fromtimestamp(
                    subscription.current_period_end
                ),
                "cancel_at_period_end": subscription.cancel_at_period_end,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Failed to retrieve subscription: {e}", exc_info=True)
            raise

    def create_payment_intent(
        self, customer_id: str, amount: int, currency: str = "usd"
    ) -> Dict:
        """
        Create a payment intent for one-time credit purchases

        Args:
            customer_id: Stripe customer ID
            amount: Amount in cents
            currency: Currency code (default: USD)

        Returns:
            Payment intent data
        """
        try:
            intent = stripe.PaymentIntent.create(
                customer=customer_id,
                amount=amount,
                currency=currency,
                automatic_payment_methods={"enabled": True},
            )

            logger.info(f"Created payment intent {intent.id} for ${amount/100:.2f}")

            return {
                "payment_intent_id": intent.id,
                "client_secret": intent.client_secret,
                "amount": amount,
                "currency": currency,
                "status": intent.status,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Failed to create payment intent: {e}", exc_info=True)
            raise


class BillingService:
    """
    Billing logic and event tracking service

    Manages credits, billing events, and subscription lifecycle.
    """

    def __init__(self, db: Session):
        """
        Initialize billing service

        Args:
            db: Database session
        """
        self.db = db
        self.stripe_service = StripeService()

    def get_or_create_organization(
        self, org_id: UUID, name: str, slug: str, email: str
    ) -> Organization:
        """
        Get or create an organization

        Args:
            org_id: Organization UUID
            name: Organization name
            slug: Organization slug
            email: Contact email

        Returns:
            Organization entity
        """
        org = self.db.query(Organization).filter(Organization.id == org_id).first()

        if not org:
            org = Organization(id=org_id, name=name, slug=slug, credit_balance=0)

            # Create Stripe customer
            try:
                stripe_customer_id = self.stripe_service.create_customer(org, email)
                org.stripe_customer_id = stripe_customer_id
            except Exception as e:
                logger.warning(f"Failed to create Stripe customer: {e}")

            self.db.add(org)
            self.db.commit()
            self.db.refresh(org)

            logger.info(f"Created organization {org.id}")

            # Create default free subscription
            self._create_default_subscription(org)

        return org

    def _create_default_subscription(self, org: Organization):
        """
        Create a default free tier subscription for a new organization

        Args:
            org: Organization entity
        """
        now = datetime.utcnow()
        subscription = Subscription(
            organization_id=org.id,
            tier=SubscriptionTier.FREE,
            status=SubscriptionStatus.ACTIVE,
            monthly_analysis_limit=10,  # Free tier: 10 analyses per month
            monthly_credit_limit=100,  # Free tier: 100 credits per month
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
        )
        self.db.add(subscription)
        self.db.commit()

        # Log event
        self._log_billing_event(
            org.id,
            BillingEventType.SUBSCRIPTION_CREATED,
            f"Free tier subscription created for {org.name}",
            subscription_id=subscription.id,
        )

        logger.info(f"Created free subscription for org {org.id}")

    def deduct_credits(
        self,
        org_id: UUID,
        amount: int,
        analysis_job_id: Optional[UUID] = None,
        description: Optional[str] = None,
    ) -> int:
        """
        Deduct credits from organization balance

        Args:
            org_id: Organization ID
            amount: Number of credits to deduct
            analysis_job_id: Optional analysis job ID
            description: Optional description

        Returns:
            New balance after deduction

        Raises:
            QuotaExceededError: If insufficient credits
        """
        org = self.db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise ValueError(f"Organization {org_id} not found")

        if org.credit_balance < amount:
            raise QuotaExceededError(
                quota_type="credits",
                limit=amount,
                current=org.credit_balance
            )

        # Deduct credits
        org.credit_balance -= amount
        self.db.commit()

        # Log event
        self._log_billing_event(
            org_id,
            BillingEventType.CREDIT_DEDUCTED,
            description or f"Deducted {amount} credits",
            analysis_job_id=analysis_job_id,
            credits_amount=-amount,
            balance_after=org.credit_balance,
        )

        logger.info(
            f"Deducted {amount} credits from org {org_id}, new balance: {org.credit_balance}"
        )

        return org.credit_balance

    def add_credits(
        self,
        org_id: UUID,
        amount: int,
        description: Optional[str] = None,
        stripe_payment_intent_id: Optional[str] = None,
    ) -> int:
        """
        Add credits to organization balance

        Args:
            org_id: Organization ID
            amount: Number of credits to add
            description: Optional description
            stripe_payment_intent_id: Stripe payment intent ID if purchased

        Returns:
            New balance after addition
        """
        org = self.db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise ValueError(f"Organization {org_id} not found")

        org.credit_balance += amount
        self.db.commit()

        # Log event
        self._log_billing_event(
            org_id,
            (
                BillingEventType.CREDIT_PURCHASED
                if stripe_payment_intent_id
                else BillingEventType.CREDIT_DEDUCTED
            ),
            description or f"Added {amount} credits",
            credits_amount=amount,
            balance_after=org.credit_balance,
            stripe_payment_intent_id=stripe_payment_intent_id,
        )

        logger.info(
            f"Added {amount} credits to org {org_id}, new balance: {org.credit_balance}"
        )

        return org.credit_balance

    def record_analysis_cost(self, job_id: UUID, cost_credits: int):
        """
        Record the cost of an analysis job and deduct credits

        Args:
            job_id: Analysis job ID
            cost_credits: Cost in credits
        """
        job = (
            self.db.query(PremiumAnalysisJob)
            .filter(PremiumAnalysisJob.id == job_id)
            .first()
        )
        if not job:
            logger.error(f"Analysis job {job_id} not found")
            return

        # Update job cost
        job.cost_credits = cost_credits
        job.billed_at = datetime.utcnow()
        self.db.commit()

        # Deduct credits from organization
        try:
            self.deduct_credits(
                job.organization_id,
                cost_credits,
                analysis_job_id=job_id,
                description=f"Analysis job {job_id} completed",
            )
        except QuotaExceededError:
            logger.warning(
                f"Organization {job.organization_id} has insufficient credits for job {job_id}"
            )

        # Log billing event
        self._log_billing_event(
            job.organization_id,
            BillingEventType.ANALYSIS_COMPLETED,
            f"Analysis job {job_id} completed with cost {cost_credits} credits",
            analysis_job_id=job_id,
            credits_amount=-cost_credits,
        )

    def _log_billing_event(
        self,
        org_id: UUID,
        event_type: BillingEventType,
        description: str,
        analysis_job_id: Optional[UUID] = None,
        subscription_id: Optional[UUID] = None,
        credits_amount: Optional[int] = None,
        balance_after: Optional[int] = None,
        stripe_event_id: Optional[str] = None,
        stripe_payment_intent_id: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> BillingEvent:
        """
        Log a billing event

        Args:
            org_id: Organization ID
            event_type: Type of billing event
            description: Event description
            analysis_job_id: Optional analysis job ID
            subscription_id: Optional subscription ID
            credits_amount: Optional credits amount (positive for add, negative for deduct)
            balance_after: Optional balance after transaction
            stripe_event_id: Optional Stripe event ID
            stripe_payment_intent_id: Optional Stripe payment intent ID
            metadata: Optional metadata dictionary

        Returns:
            Created billing event
        """
        event = BillingEvent(
            organization_id=org_id,
            event_type=event_type,
            description=description,
            analysis_job_id=analysis_job_id,
            subscription_id=subscription_id,
            credits_amount=credits_amount,
            balance_after=balance_after,
            stripe_event_id=stripe_event_id,
            stripe_payment_intent_id=stripe_payment_intent_id,
            metadata=json.dumps(metadata) if metadata else None,
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        return event

    def get_usage_stats(self, org_id: UUID) -> Dict:
        """
        Get usage statistics for an organization

        Args:
            org_id: Organization ID

        Returns:
            Dictionary with usage statistics
        """
        subscription = (
            self.db.query(Subscription)
            .filter(Subscription.organization_id == org_id)
            .first()
        )

        if not subscription:
            return {
                "current_period_analyses": 0,
                "current_period_credits_used": 0,
                "monthly_analysis_limit": 0,
                "monthly_credit_limit": 0,
            }

        return {
            "current_period_analyses": subscription.current_period_analyses,
            "current_period_credits_used": subscription.current_period_credits_used,
            "monthly_analysis_limit": subscription.monthly_analysis_limit,
            "monthly_credit_limit": subscription.monthly_credit_limit,
            "current_period_start": subscription.current_period_start.isoformat(),
            "current_period_end": subscription.current_period_end.isoformat(),
        }


class QuotaService:
    """
    Quota checking and enforcement service

    Validates that organizations have sufficient quota before executing operations.
    """

    def __init__(self, db: Session):
        """
        Initialize quota service

        Args:
            db: Database session
        """
        self.db = db

    def check_analysis_quota(self, org_id: UUID) -> Tuple[bool, Optional[str]]:
        """
        Check if organization has quota for a new analysis

        Args:
            org_id: Organization ID

        Returns:
            Tuple of (allowed: bool, error_message: Optional[str])
        """
        # Get organization
        org = self.db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            return False, "Organization not found"

        # Get subscription
        subscription = (
            self.db.query(Subscription)
            .filter(Subscription.organization_id == org_id)
            .first()
        )

        if not subscription:
            return False, "No active subscription found"

        # Check subscription status
        if subscription.status not in [
            SubscriptionStatus.ACTIVE,
            SubscriptionStatus.TRIALING,
        ]:
            return False, f"Subscription is {subscription.status.value}"

        # Check if we're in the current period
        now = datetime.utcnow()
        if now > subscription.current_period_end:
            # Period has ended, need to reset or renew
            return False, "Subscription period has ended"

        # Check monthly analysis limit
        if subscription.monthly_analysis_limit is not None:
            if (
                subscription.current_period_analyses
                >= subscription.monthly_analysis_limit
            ):
                return (
                    False,
                    f"Monthly analysis limit reached ({subscription.monthly_analysis_limit})",
                )

        # Check credit balance (basic check, actual cost calculated later)
        if org.credit_balance <= 0:
            return False, "Insufficient credits"

        logger.info(f"Quota check passed for org {org_id}")
        return True, None

    def increment_usage(self, org_id: UUID):
        """
        Increment usage counters after an analysis is submitted

        Args:
            org_id: Organization ID
        """
        subscription = (
            self.db.query(Subscription)
            .filter(Subscription.organization_id == org_id)
            .first()
        )

        if subscription:
            subscription.current_period_analyses += 1
            self.db.commit()
            logger.info(
                f"Incremented analysis count for org {org_id} to {subscription.current_period_analyses}"
            )

    def get_tier_limits(self, tier: SubscriptionTier) -> Dict[str, Any]:
        """
        Get limits for a subscription tier

        Args:
            tier: Subscription tier

        Returns:
            Dictionary with tier limits
        """
        tier_config: Dict[SubscriptionTier, Dict[str, Any]] = {
            SubscriptionTier.FREE: {
                "monthly_analysis_limit": 10,
                "monthly_credit_limit": 100,
                "priority": 0,
                "features": ["basic_analysis", "vex_generation"],
            },
            SubscriptionTier.STARTER: {
                "monthly_analysis_limit": 100,
                "monthly_credit_limit": 1000,
                "priority": 1,
                "features": [
                    "basic_analysis",
                    "vex_generation",
                    "reachability_analysis",
                ],
            },
            SubscriptionTier.PROFESSIONAL: {
                "monthly_analysis_limit": 500,
                "monthly_credit_limit": 5000,
                "priority": 2,
                "features": [
                    "basic_analysis",
                    "vex_generation",
                    "reachability_analysis",
                    "security_fuzzing",
                    "priority_support",
                ],
            },
            SubscriptionTier.ENTERPRISE: {
                "monthly_analysis_limit": None,  # Unlimited
                "monthly_credit_limit": None,  # Unlimited
                "priority": 3,
                "features": [
                    "basic_analysis",
                    "vex_generation",
                    "reachability_analysis",
                    "security_fuzzing",
                    "priority_support",
                    "dedicated_support",
                    "custom_integrations",
                ],
            },
        }

        return tier_config.get(tier, tier_config[SubscriptionTier.FREE])
