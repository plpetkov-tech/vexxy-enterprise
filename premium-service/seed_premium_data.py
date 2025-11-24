#!/usr/bin/env python3
"""
Seed premium database with test users and organizations
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4, UUID

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session


def seed_premium_data():
    """Seed the premium database with test data"""

    # Get database URL from environment
    database_url = os.getenv("DATABASE_URL", "postgresql://vexxy:vexxy@premium-postgres:5432/vexxy_premium")
    # Convert asyncpg URL to psycopg2 for sync operations
    sync_url = database_url.replace("postgresql+asyncpg://", "postgresql://")

    engine = create_engine(sync_url)

    # Initialize database schema
    print("Initializing database schema...")
    try:
        from models.database import init_db
        init_db()
        print("✓ Database schema initialized")
    except Exception as e:
        print(f"Note: Could not initialize schema via init_db: {e}")
        print("Assuming tables already exist...")

    with Session(engine) as session:
        print("=" * 60)
        print("Premium Database Seeding")
        print("=" * 60)

        # Check if organizations already exist
        result = session.execute(text("SELECT COUNT(*) FROM organizations"))
        org_count = result.scalar()

        if org_count > 0:
            print(f"Found {org_count} existing organizations, skipping seeding...")
            return

        # Create organization with fixed UUID that matches main API
        # This must match the premium_org_id in main API seed data
        org_id = UUID("550e8400-e29b-41d4-a716-446655440000")  # Fixed UUID matching main API
        now = datetime.utcnow()

        session.execute(text("""
            INSERT INTO organizations (id, name, slug, credit_balance, created_at, updated_at)
            VALUES (:id, :name, :slug, :credit_balance, :created_at, :updated_at)
        """), {
            "id": org_id,
            "name": "VEXxy Demo Organization",
            "slug": "vexxy-demo",
            "credit_balance": 10000,
            "created_at": now,
            "updated_at": now
        })
        print(f"✓ Created organization: VEXxy Demo Organization")

        # Create users for each role
        users = [
            {
                "email": "admin@vexxy.com",
                "name": "Admin User",
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYCZz8nnY4i"  # Admin123!
            },
            {
                "email": "analyst@vexxy.com",
                "name": "Analyst User",
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYCZz8nnY4i"  # Analyst123!
            },
            {
                "email": "developer@vexxy.com",
                "name": "Developer User",
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYCZz8nnY4i"  # Developer123!
            },
            {
                "email": "viewer@vexxy.com",
                "name": "Viewer User",
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYCZz8nnY4i"  # Viewer123!
            }
        ]

        # Create users with deterministic UUIDs based on integer IDs (1-4)
        # This ensures the JWT sub (integer) can be mapped to premium service UUIDs
        user_id_mapping = {
            "admin@vexxy.com": 1,
            "analyst@vexxy.com": 2, 
            "developer@vexxy.com": 3,
            "viewer@vexxy.com": 4
        }
        
        for user_data in users:
            # Create deterministic UUID based on integer ID
            user_int_id = user_id_mapping[user_data["email"]]
            user_uuid = UUID(f"00000000-0000-0000-0000-{user_int_id:012d}")
            
            session.execute(text("""
                INSERT INTO users (
                    id, organization_id, email, name, hashed_password,
                    is_active, is_admin, email_verified, created_at, updated_at
                )
                VALUES (
                    :id, :org_id, :email, :name, :password,
                    :is_active, :is_admin, :email_verified, :created_at, :updated_at
                )
            """), {
                "id": user_uuid,
                "org_id": org_id,
                "email": user_data["email"],
                "name": user_data["name"],
                "password": user_data["password"],
                "is_active": True,
                "is_admin": user_data["email"] == "admin@vexxy.com",
                "email_verified": True,
                "created_at": now,
                "updated_at": now
            })
            print(f"✓ Created user: {user_data['email']} (ID: {user_int_id} -> UUID: {user_uuid})")

        # Create premium subscription for the organization
        subscription_id = uuid4()
        session.execute(text("""
            INSERT INTO subscriptions (
                id, organization_id, stripe_subscription_id, tier, status,
                current_period_analyses, current_period_credits_used,
                current_period_start, current_period_end,
                cancel_at_period_end, created_at, updated_at
            )
            VALUES (
                :id, :org_id, :stripe_id, 'ENTERPRISE', 'ACTIVE',
                0, 0,
                :period_start, :period_end,
                false, :created_at, :updated_at
            )
        """), {
            "id": subscription_id,
            "org_id": org_id,
            "stripe_id": "sub_demo_premium",
            "period_start": now,
            "period_end": now + timedelta(days=365),
            "created_at": now,
            "updated_at": now
        })
        print(f"✓ Created ENTERPRISE subscription for organization")

        session.commit()

        print("\n" + "=" * 60)
        print("Premium database seeding completed!")
        print("=" * 60)
        print("\nAll users have premium access via organization subscription:")
        for user_data in users:
            print(f"  • {user_data['email']}")


if __name__ == "__main__":
    try:
        seed_premium_data()
    except Exception as e:
        print(f"Error seeding database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
