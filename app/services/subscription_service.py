"""Subscription orchestration: plans, capacity, and payment flows."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, Optional, Tuple

from flask import current_app, url_for

from ..extensions import db
from ..models import (
    Organization,
    OrganizationSubscription,
    PaymentProvider,
    PaymentStatus,
    PaymentTransaction,
    SubscriptionPlan,
    SubscriptionStatus,
    User,
)


def _ensure_plan(currency: str) -> SubscriptionPlan:
    cfg = current_app.config
    plan = (
        SubscriptionPlan.query.filter_by(currency=currency, is_active=True)
        .order_by(SubscriptionPlan.id.asc())
        .first()
    )
    if plan:
        return plan

    plan = SubscriptionPlan(
        name=f"Standard-{currency}",
        currency=currency,
        base_fee=cfg.get("SUBSCRIPTION_BASE_FEE", 50),
        per_member_fee=cfg.get("SUBSCRIPTION_PER_MEMBER_FEE", 5),
        description="Base fee plus per-member licensing",
        is_active=True,
    )
    db.session.add(plan)
    db.session.commit()
    return plan


def ensure_subscription(org: Organization) -> OrganizationSubscription:
    """Guarantee a subscription row for an organization with trial defaults."""
    cfg = current_app.config
    sub = OrganizationSubscription.query.filter_by(organization_id=org.id).first()
    if sub:
        return sub

    plan = _ensure_plan(cfg.get("SUBSCRIPTION_DEFAULT_CURRENCY", "USD"))
    sub = OrganizationSubscription(
        organization=org,
        plan=plan,
        currency=plan.currency,
    )
    sub.set_trial_defaults(
        trial_days=cfg.get("SUBSCRIPTION_TRIAL_DAYS", 14),
        trial_limit=cfg.get("SUBSCRIPTION_TRIAL_LIMIT", 5),
        currency=plan.currency,
    )
    db.session.add(sub)
    db.session.commit()
    return sub


def sync_member_usage(org: Organization, commit: bool = True) -> OrganizationSubscription:
    """Recalculate active member usage and persist on the subscription."""
    sub = ensure_subscription(org)
    active_users = User.query.filter_by(organization_id=org.id, is_active=True).count()
    sub.current_member_count = active_users
    if commit:
        db.session.commit()
    return sub


def capacity_remaining(org: Organization) -> Tuple[int, OrganizationSubscription]:
    """Return remaining seats and subscription."""
    sub = sync_member_usage(org, commit=False)
    remaining = max(sub.allowed_member_limit - (sub.current_member_count or 0), 0)
    return remaining, sub


def calculate_total(plan: SubscriptionPlan, member_limit: int) -> float:
    """Compute total charge using base fee plus per-seat pricing."""
    return float(plan.base_fee) + float(plan.per_member_fee) * member_limit


def create_pending_transaction(
    *,
    org: Organization,
    subscription: OrganizationSubscription,
    provider: PaymentProvider,
    member_limit: int,
    created_by_id: Optional[int],
    description: str,
) -> PaymentTransaction:
    plan = subscription.plan or _ensure_plan(subscription.currency)
    amount = calculate_total(plan, member_limit)
    txn = PaymentTransaction(
        organization_id=org.id,
        subscription=subscription,
        provider=provider,
        status=PaymentStatus.PENDING,
        amount=amount,
        currency=subscription.currency,
        member_limit=member_limit,
        base_fee=plan.base_fee,
        per_member_fee=plan.per_member_fee,
        description=description,
        created_by_id=created_by_id,
    )
    db.session.add(txn)
    db.session.flush()
    return txn


def choose_provider(country: Optional[str]) -> PaymentProvider:
    """Select a payment provider based on country preference."""
    if country and country.strip().upper() == "IN":
        return PaymentProvider.RAZORPAY
    return PaymentProvider.STRIPE


def stripe_checkout_session(
    *,
    org: Organization,
    subscription: OrganizationSubscription,
    member_limit: int,
    created_by_id: Optional[int],
) -> Dict[str, str]:
    """Create a Stripe Checkout session with real pricing logic."""
    import stripe  # type: ignore

    secret = current_app.config.get("STRIPE_SECRET_KEY")
    if not secret:
        raise RuntimeError("Stripe is not configured. Provide STRIPE_SECRET_KEY.")

    stripe.api_key = secret
    plan = subscription.plan or _ensure_plan(subscription.currency)
    amount_total = calculate_total(plan, member_limit)
    success_url = url_for("main.subscription", _external=True) + "?provider=stripe&status=success"
    cancel_url = url_for("main.subscription", _external=True) + "?provider=stripe&status=cancelled"

    txn = create_pending_transaction(
        org=org,
        subscription=subscription,
        provider=PaymentProvider.STRIPE,
        member_limit=member_limit,
        created_by_id=created_by_id,
        description=f"Subscription for {member_limit} members",
    )

    session = stripe.checkout.Session.create(
        mode="payment",
        payment_method_types=["card"],
        line_items=[
            {
                "price_data": {
                    "currency": subscription.currency.lower(),
                    "product_data": {"name": "Base subscription fee"},
                    "unit_amount": int(float(plan.base_fee) * 100),
                },
                "quantity": 1,
            },
            {
                "price_data": {
                    "currency": subscription.currency.lower(),
                    "product_data": {"name": f"Member licenses ({member_limit})"},
                    "unit_amount": int(float(plan.per_member_fee) * 100),
                },
                "quantity": member_limit,
            },
        ],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "organization_id": str(org.id),
            "subscription_id": str(subscription.id),
            "member_limit": str(member_limit),
            "transaction_id": str(txn.id),
        },
    )

    txn.provider_order_id = session.id
    txn.provider_payment_id = session.payment_intent if hasattr(session, "payment_intent") else None
    txn.raw_details = json.dumps({"checkout_session": session.id, "amount": amount_total})
    db.session.commit()

    return {"checkout_url": session.url, "transaction_id": txn.id}


def razorpay_order(
    *,
    org: Organization,
    subscription: OrganizationSubscription,
    member_limit: int,
    created_by_id: Optional[int],
) -> Dict[str, str]:
    """Create a Razorpay order for card/UPI flows."""
    import razorpay  # type: ignore

    key_id = current_app.config.get("RAZORPAY_KEY_ID")
    key_secret = current_app.config.get("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        raise RuntimeError("Razorpay is not configured. Provide RAZORPAY_KEY_ID/SECRET.")

    client = razorpay.Client(auth=(key_id, key_secret))
    plan = subscription.plan or _ensure_plan(subscription.currency)
    amount_total = calculate_total(plan, member_limit)
    txn = create_pending_transaction(
        org=org,
        subscription=subscription,
        provider=PaymentProvider.RAZORPAY,
        member_limit=member_limit,
        created_by_id=created_by_id,
        description=f"Subscription for {member_limit} members",
    )

    order_payload = {
        "amount": int(amount_total * 100),
        "currency": subscription.currency,
        "payment_capture": 1,
        "notes": {
            "organization_id": org.id,
            "subscription_id": subscription.id,
            "member_limit": member_limit,
            "transaction_id": txn.id,
        },
        "receipt": f"sub-{org.id}-{txn.id}-{datetime.utcnow().timestamp()}",
    }
    order = client.order.create(data=order_payload)
    txn.provider_order_id = order.get("id")
    txn.raw_details = json.dumps(order)
    db.session.commit()

    return {
        "order_id": order.get("id"),
        "key_id": key_id,
        "amount": order_payload["amount"],
        "currency": subscription.currency,
        "transaction_id": txn.id,
    }


def apply_payment_success(
    *,
    subscription: OrganizationSubscription,
    transaction: PaymentTransaction,
    provider: PaymentProvider,
    member_limit: int,
    payment_id: Optional[str],
    signature: Optional[str],
) -> None:
    """Mark subscription active and transaction successful."""
    transaction.mark_success(payment_id=payment_id, signature=signature)
    subscription.mark_paid(member_limit=member_limit, provider=provider, currency=subscription.currency)
    subscription.current_member_count = User.query.filter_by(
        organization_id=subscription.organization_id,
        is_active=True,
    ).count()
    db.session.commit()


def handle_stripe_webhook(payload: bytes, sig_header: str) -> Tuple[bool, str]:
    import stripe  # type: ignore

    secret = current_app.config.get("STRIPE_WEBHOOK_SECRET")
    if not secret:
        return False, "Stripe webhook secret not configured"

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Invalid webhook: {exc}"

    if event.get("type") not in {"checkout.session.completed", "payment_intent.succeeded"}:
        return True, "Event ignored"

    data_object = event["data"]["object"]
    metadata = data_object.get("metadata", {}) if isinstance(data_object, dict) else {}
    subscription_id = metadata.get("subscription_id")
    member_limit_value = metadata.get("member_limit")
    txn_id = metadata.get("transaction_id")
    if not subscription_id or not member_limit_value:
        return False, "Missing subscription metadata"

    subscription = OrganizationSubscription.query.filter_by(id=int(subscription_id)).first()
    if not subscription:
        return False, "Subscription not found"

    transaction = None
    if txn_id:
        transaction = PaymentTransaction.query.filter_by(id=int(txn_id)).first()
    if not transaction:
        transaction = (
            PaymentTransaction.query.filter_by(
                subscription_id=subscription.id,
                provider_order_id=data_object.get("id"),
            ).first()
        )
    if not transaction:
        transaction = create_pending_transaction(
            org=subscription.organization,
            subscription=subscription,
            provider=PaymentProvider.STRIPE,
            member_limit=int(member_limit_value),
            created_by_id=None,
            description="Stripe payment callback",
        )

    apply_payment_success(
        subscription=subscription,
        transaction=transaction,
        provider=PaymentProvider.STRIPE,
        member_limit=int(member_limit_value),
        payment_id=data_object.get("payment_intent") or data_object.get("id"),
        signature=None,
    )
    return True, "Subscription activated"


def verify_razorpay_payment(*, order_id: str, payment_id: str, signature: str) -> Tuple[bool, str]:
    import razorpay  # type: ignore

    key_secret = current_app.config.get("RAZORPAY_KEY_SECRET")
    if not key_secret:
        return False, "Razorpay secret missing"

    client = razorpay.Client(auth=(current_app.config.get("RAZORPAY_KEY_ID"), key_secret))
    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        })
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Signature verification failed: {exc}"

    txn = PaymentTransaction.query.filter_by(
        provider=PaymentProvider.RAZORPAY,
        provider_order_id=order_id,
    ).first()
    if not txn:
        return False, "Transaction not found"

    subscription = txn.subscription or OrganizationSubscription.query.filter_by(id=txn.subscription_id).first()
    if not subscription:
        return False, "Subscription missing"

    apply_payment_success(
        subscription=subscription,
        transaction=txn,
        provider=PaymentProvider.RAZORPAY,
        member_limit=txn.member_limit,
        payment_id=payment_id,
        signature=signature,
    )
    return True, "Payment verified"
