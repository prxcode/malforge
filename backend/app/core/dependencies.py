"""
MAP — FastAPI Dependencies

Shared dependency injection for database sessions, storage, and auth.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_async_session
from app.core.security import get_current_user
from app.core.storage import StorageService, storage_service


async def get_db(session: AsyncSession = Depends(get_async_session)) -> AsyncSession:
    """Provide an async database session."""
    return session


def get_storage() -> StorageService:
    """Provide the storage service singleton."""
    return storage_service


async def get_authenticated_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Provide the authenticated user context."""
    return current_user
