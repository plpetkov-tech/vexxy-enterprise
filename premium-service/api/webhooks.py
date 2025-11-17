"""
Stripe Webhook Handler

Handles incoming webhook events from Stripe for payment and subscription updates.
"""
import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
import stripe

from config.settings import settings
from models import (
    get_db,
    Organization,
    Subscription,
    BillingEvent,
    SubscriptionStatus,
    BillingEventType
)
from services.billing import BillingService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


@router.post("/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handle Stripe webhook events

    This endpoint receives webhook events from Stripe for:
    - Payment succeeded/failed
    - Subscription created/updated/deleted
    - Invoice payment succeeded/failed
    - Customer updated

    Stripe webhooks are signed and must be verified using the webhook secret.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        logger.error("Missing stripe-signature header")
        raise HTTPException(status_code=400, detail="Missing signature")

    # Verify webhook signature
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    logger.info(f"Received Stripe webhook: {event['type']}")

    # Handle the event
    event_type = event["type"]
    event_data = event["data"]["object"]

    try:
        if event_type == "payment_intent.succeeded":
            await handle_payment_succeeded(event_data, db, event["id"])

        elif event_type == "payment_intent.payment_failed":
            await handle_payment_failed(event_data, db, event["id"])

        elif event_type == "customer.subscription.created":
            await handle_subscription_created(event_data, db, event["id"])

        elif event_type == "customer.subscription.updated":
            await handle_subscription_updated(event_data, db, event["id"])

        elif event_type == "customer.subscription.deleted":
            await handle_subscription_deleted(event_data, db, event["id"])

        elif event_type == "invoice.payment_succeeded":
            await handle_invoice_payment_succeeded(event_data, db, event["id"])

        elif event_type == "invoice.payment_failed":
            await handle_invoice_payment_failed(event_data, db, event["id"])

        else:
            logger.info(f"Unhandled event type: {event_type}")

    except Exception as e:
        logger.error(f"Error processing webhook {event_type}: {e}", exc_info=True)
        # Return 200 to acknowledge receipt even if processing failed
        # Stripe will retry if we return an error
        return {"status": "error", "message": str(e)}

    return {"status": "success"}


async def handle_payment_succeeded(payment_intent: Dict[str, Any], db: Session, event_id: str):
    """Handle successful payment"""
    customer_id = payment_intent.get("customer")
    amount = payment_intent.get("amount")  # Amount in cents

    if not customer_id:
        logger.warning(f"Payment intent {payment_intent['id']} has no customer")
        return

    # Find organization by Stripe customer ID
    org = db.query(Organization).filter(
        Organization.stripe_customer_id == customer_id
    ).first()

    if not org:
        logger.warning(f"Organization not found for Stripe customer {customer_id}")
        return

    billing_service = BillingService(db)

    # Calculate credits (e.g., $0.10 per credit, so amount/10)
    credits = amount // 10  # Integer division for credits

    # Add credits to organization
    billing_service.add_credits(
        org.id,
        credits,
        description=f"Credit purchase via Stripe - ${amount/100:.2f}",
        stripe_payment_intent_id=payment_intent["id"]
    )

    # Log billing event
    billing_service._log_billing_event(
        org.id,
        BillingEventType.PAYMENT_SUCCEEDED,
        f"Payment succeeded for ${amount/100:.2f} - {credits} credits added",
        stripe_event_id=event_id,
        stripe_payment_intent_id=payment_intent["id"],
        credits_amount=credits,
        balance_after=org.credit_balance
    )

    logger.info(f"Payment succeeded for org {org.id}: ${amount/100:.2f} = {credits} credits")


async def handle_payment_failed(payment_intent: Dict[str, Any], db: Session, event_id: str):
    """Handle failed payment"""
    customer_id = payment_intent.get("customer")
    amount = payment_intent.get("amount")

    if not customer_id:
        return

    org = db.query(Organization).filter(
        Organization.stripe_customer_id == customer_id
    ).first()

    if not org:
        return

    billing_service = BillingService(db)

    # Log billing event
    billing_service._log_billing_event(
        org.id,
        BillingEventType.PAYMENT_FAILED,
        f"Payment failed for ${amount/100:.2f}",
        stripe_event_id=event_id,
        stripe_payment_intent_id=payment_intent["id"]
    )

    logger.warning(f"Payment failed for org {org.id}: ${amount/100:.2f}")


async def handle_subscription_created(subscription: Dict[str, Any], db: Session, event_id: str):
    """Handle subscription creation"""
    customer_id = subscription.get("customer")
    subscription_id = subscription["id"]

    org = db.query(Organization).filter(
        Organization.stripe_customer_id == customer_id
    ).first()

    if not org:
        logger.warning(f"Organization not found for Stripe customer {customer_id}")
        return

    # Get or create subscription record
    db_subscription = db.query(Subscription).filter(
        Subscription.organization_id == org.id
    ).first()

    if not db_subscription:
        # Create new subscription
        from models import SubscriptionTier
        from datetime import datetime

        db_subscription = Subscription(
            organization_id=org.id,
            tier=SubscriptionTier.STARTER,  # Default, should be updated based on price
            status=SubscriptionStatus.ACTIVE,
            stripe_subscription_id=subscription_id,
            stripe_price_id=subscription["items"]["data"][0]["price"]["id"],
            current_period_start=datetime.fromtimestamp(subscription["current_period_start"]),
            current_period_end=datetime.fromtimestamp(subscription["current_period_end"]),
        )
        db.add(db_subscription)
    else:
        # Update existing subscription
        db_subscription.stripe_subscription_id = subscription_id
        db_subscription.stripe_price_id = subscription["items"]["data"][0]["price"]["id"]
        db_subscription.status = SubscriptionStatus.ACTIVE
        db_subscription.current_period_start = datetime.fromtimestamp(subscription["current_period_start"])
        db_subscription.current_period_end = datetime.fromtimestamp(subscription["current_period_end"])

    db.commit()

    billing_service = BillingService(db)
    billing_service._log_billing_event(
        org.id,
        BillingEventType.SUBSCRIPTION_CREATED,
        f"Subscription created: {subscription_id}",
        subscription_id=db_subscription.id,
        stripe_event_id=event_id
    )

    logger.info(f"Subscription created for org {org.id}: {subscription_id}")


async def handle_subscription_updated(subscription: Dict[str, Any], db: Session, event_id: str):
    """Handle subscription update"""
    subscription_id = subscription["id"]

    db_subscription = db.query(Subscription).filter(
        Subscription.stripe_subscription_id == subscription_id
    ).first()

    if not db_subscription:
        logger.warning(f"Subscription not found: {subscription_id}")
        return

    # Map Stripe status to our status
    status_mapping = {
        "active": SubscriptionStatus.ACTIVE,
        "trialing": SubscriptionStatus.TRIALING,
        "past_due": SubscriptionStatus.PAST_DUE,
        "canceled": SubscriptionStatus.CANCELED,
        "unpaid": SubscriptionStatus.UNPAID,
    }

    stripe_status = subscription.get("status")
    db_subscription.status = status_mapping.get(stripe_status, SubscriptionStatus.ACTIVE)
    db_subscription.current_period_start = datetime.fromtimestamp(subscription["current_period_start"])
    db_subscription.current_period_end = datetime.fromtimestamp(subscription["current_period_end"])
    db_subscription.cancel_at_period_end = subscription.get("cancel_at_period_end", False)

    if subscription.get("canceled_at"):
        db_subscription.canceled_at = datetime.fromtimestamp(subscription["canceled_at"])

    db.commit()

    billing_service = BillingService(db)
    billing_service._log_billing_event(
        db_subscription.organization_id,
        BillingEventType.SUBSCRIPTION_UPDATED,
        f"Subscription updated: {subscription_id} - status: {stripe_status}",
        subscription_id=db_subscription.id,
        stripe_event_id=event_id
    )

    logger.info(f"Subscription updated: {subscription_id} - status: {stripe_status}")


async def handle_subscription_deleted(subscription: Dict[str, Any], db: Session, event_id: str):
    """Handle subscription deletion"""
    subscription_id = subscription["id"]

    db_subscription = db.query(Subscription).filter(
        Subscription.stripe_subscription_id == subscription_id
    ).first()

    if not db_subscription:
        logger.warning(f"Subscription not found: {subscription_id}")
        return

    db_subscription.status = SubscriptionStatus.CANCELED
    db_subscription.canceled_at = datetime.utcnow()
    db.commit()

    billing_service = BillingService(db)
    billing_service._log_billing_event(
        db_subscription.organization_id,
        BillingEventType.SUBSCRIPTION_CANCELED,
        f"Subscription canceled: {subscription_id}",
        subscription_id=db_subscription.id,
        stripe_event_id=event_id
    )

    logger.info(f"Subscription deleted: {subscription_id}")


async def handle_invoice_payment_succeeded(invoice: Dict[str, Any], db: Session, event_id: str):
    """Handle successful invoice payment"""
    customer_id = invoice.get("customer")
    subscription_id = invoice.get("subscription")

    if not customer_id:
        return

    org = db.query(Organization).filter(
        Organization.stripe_customer_id == customer_id
    ).first()

    if not org:
        return

    billing_service = BillingService(db)

    # Log the event
    billing_service._log_billing_event(
        org.id,
        BillingEventType.PAYMENT_SUCCEEDED,
        f"Invoice payment succeeded: ${invoice['amount_paid']/100:.2f}",
        stripe_event_id=event_id
    )

    logger.info(f"Invoice payment succeeded for org {org.id}: ${invoice['amount_paid']/100:.2f}")


async def handle_invoice_payment_failed(invoice: Dict[str, Any], db: Session, event_id: str):
    """Handle failed invoice payment"""
    customer_id = invoice.get("customer")
    subscription_id = invoice.get("subscription")

    if not customer_id:
        return

    org = db.query(Organization).filter(
        Organization.stripe_customer_id == customer_id
    ).first()

    if not org:
        return

    # Update subscription status to past_due
    if subscription_id:
        db_subscription = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == subscription_id
        ).first()

        if db_subscription:
            db_subscription.status = SubscriptionStatus.PAST_DUE
            db.commit()

    billing_service = BillingService(db)

    # Log the event
    billing_service._log_billing_event(
        org.id,
        BillingEventType.PAYMENT_FAILED,
        f"Invoice payment failed: ${invoice['amount_due']/100:.2f}",
        stripe_event_id=event_id
    )

    logger.warning(f"Invoice payment failed for org {org.id}: ${invoice['amount_due']/100:.2f}")
