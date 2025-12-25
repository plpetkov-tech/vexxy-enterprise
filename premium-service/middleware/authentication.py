"""
JWT Authentication Middleware

Handles JWT token validation and user/organization context extraction.
"""

from typing import Optional
import logging
from datetime import datetime, timedelta

import jwt
from fastapi import Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from uuid import UUID

from config.settings import settings
from models import get_db, Organization, User
from exceptions import UnauthorizedError, ForbiddenError

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token security
security = HTTPBearer()


class AuthContext:
    """
    Authentication context containing user and organization info

    Attributes:
        user_id: Authenticated user ID
        organization_id: User's organization ID
        email: User's email
        is_admin: Whether user is an organization admin
    """

    def __init__(
        self, user_id: UUID, organization_id: UUID, email: str, is_admin: bool = False
    ):
        self.user_id = user_id
        self.organization_id = organization_id
        self.email = email
        self.is_admin = is_admin

    def __repr__(self):
        return f"<AuthContext user={self.user_id} org={self.organization_id}>"


class AuthService:
    """
    Authentication service for JWT and API key handling
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password

        Args:
            password: Plain text password

        Returns:
            Hashed password
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against a hash

        Args:
            plain_password: Plain text password
            hashed_password: Hashed password

        Returns:
            True if password matches
        """
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(
        user_id: UUID,
        organization_id: UUID,
        email: str,
        is_admin: bool = False,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Create a JWT access token

        Args:
            user_id: User ID
            organization_id: Organization ID
            email: User email
            is_admin: Whether user is admin
            expires_delta: Token expiration time (default: 24 hours)

        Returns:
            JWT token string
        """
        if expires_delta is None:
            expires_delta = timedelta(hours=24)

        expire = datetime.utcnow() + expires_delta

        payload = {
            "sub": str(user_id),
            "org_id": str(organization_id),
            "email": email,
            "is_admin": is_admin,
            "exp": expire,
            "iat": datetime.utcnow(),
        }

        token = jwt.encode(
            payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )

        return token

    @staticmethod
    def decode_token(token: str) -> dict:
        """
        Decode and verify a JWT token

        Args:
            token: JWT token string

        Returns:
            Decoded payload

        Raises:
            UnauthorizedError: If token is invalid or expired
        """
        try:
            # Use RS256 (asymmetric) or HS256 (symmetric) based on configuration
            if settings.jwt_algorithm == "RS256":
                key = settings.jwt_public_key
                if not key:
                    raise UnauthorizedError("JWT public key not available for RS256 verification")
            else:
                key = settings.jwt_secret_key

            payload = jwt.decode(
                token, key, algorithms=[settings.jwt_algorithm]
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise UnauthorizedError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise UnauthorizedError(f"Invalid token: {str(e)}")

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with email and password

        Args:
            db: Database session
            email: User email
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise
        """
        user = db.query(User).filter(User.email == email).first()

        if not user:
            return None

        if not AuthService.verify_password(password, user.hashed_password):
            return None

        if not user.is_active:
            return None

        # Update last login
        user.last_login_at = datetime.utcnow()
        db.commit()

        return user


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> AuthContext:
    """
    FastAPI dependency for getting current authenticated user

    Args:
        credentials: Bearer token from Authorization header
        db: Database session

    Returns:
        AuthContext with user and organization info

    Raises:
        UnauthorizedError: If authentication fails
    """
    token = credentials.credentials

    # Decode token
    payload = AuthService.decode_token(token)

    # Extract claims
    user_id_str = payload.get("sub")
    org_id_str = payload.get("org_id")
    email = payload.get("email")
    is_admin = payload.get("is_admin", False)

    if not user_id_str or not org_id_str or not email:
        raise UnauthorizedError("Invalid token payload")

    try:
        user_id = UUID(user_id_str)
        org_id = UUID(org_id_str)
    except ValueError:
        raise UnauthorizedError("Invalid token payload")

    # Verify user still exists and is active
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise UnauthorizedError("User not found or inactive")

    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise UnauthorizedError("Organization not found")

    logger.info(f"Authenticated user {email} for org {org_id}")

    return AuthContext(
        user_id=user_id, organization_id=org_id, email=email, is_admin=is_admin
    )


async def get_optional_user(
    authorization: Optional[str] = Header(None), db: Session = Depends(get_db)
) -> Optional[AuthContext]:
    """
    FastAPI dependency for optional authentication

    Similar to get_current_user but returns None if no auth provided
    instead of raising an error.

    Args:
        authorization: Optional Authorization header
        db: Database session

    Returns:
        AuthContext if authenticated, None otherwise
    """
    if not authorization:
        return None

    if not authorization.startswith("Bearer "):
        return None

    token = authorization[7:]  # Remove "Bearer " prefix

    try:
        payload = AuthService.decode_token(token)

        user_id_str = payload.get("sub")
        org_id_str = payload.get("org_id")
        email = payload.get("email")
        is_admin = payload.get("is_admin", False)

        if not user_id_str or not org_id_str or not email:
            return None

        user_id = UUID(user_id_str)
        org_id = UUID(org_id_str)

        # Verify user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            return None

        return AuthContext(
            user_id=user_id, organization_id=org_id, email=email, is_admin=is_admin
        )

    except Exception as e:
        logger.warning(f"Optional auth failed: {e}")
        return None


def require_admin(auth: AuthContext = Depends(get_current_user)) -> AuthContext:
    """
    FastAPI dependency that requires admin privileges

    Args:
        auth: Current auth context

    Returns:
        AuthContext if user is admin

    Raises:
        ForbiddenError: If user is not admin
    """
    if not auth.is_admin:
        raise ForbiddenError("Admin privileges required")

    return auth
