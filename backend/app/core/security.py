"""
MAP — JWT Authentication & Security

Handles JWT token creation, validation, password hashing, and auth dependencies.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_async_session

settings = get_settings()

# ---------- Password Hashing ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- Bearer Token Scheme ----------
bearer_scheme = HTTPBearer(auto_error=False)


# ---------- Token Models ----------
class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # user id
    exp: datetime
    iat: datetime
    role: str = "analyst"


class TokenResponse(BaseModel):
    """Token response returned to client."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    """User registration request."""

    username: str
    email: str
    password: str
    full_name: str | None = None
    role: str = "analyst"


class UserResponse(BaseModel):
    """User data returned in responses."""

    id: UUID
    username: str
    email: str
    full_name: str | None
    role: str
    is_active: bool


# ---------- Password Utilities ----------
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ---------- JWT Token Utilities ----------
def create_access_token(
    user_id: str,
    role: str = "analyst",
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token."""
    now = datetime.now(UTC)
    expire = now + (
        expires_delta
        or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "role": role,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> TokenPayload:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return TokenPayload(**payload)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------- Auth Dependencies ----------
async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_async_session),
) -> dict:
    """
    FastAPI dependency: extract and validate JWT from Authorization header.
    Returns user dict with id, role, username.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = decode_access_token(credentials.credentials)

    # Import here to avoid circular imports
    from app.auth.models import User

    result = await db.execute(
        select(User).where(User.id == token_data.sub, User.is_active.is_(True))
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name,
    }


async def require_role(required_role: str):
    """Factory for role-based access control dependency."""

    async def _check_role(current_user: dict = Depends(get_current_user)) -> dict:
        role_hierarchy = {"admin": 3, "engineer": 2, "analyst": 1, "viewer": 0}
        user_level = role_hierarchy.get(current_user["role"], 0)
        required_level = role_hierarchy.get(required_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' or higher required",
            )
        return current_user

    return _check_role
