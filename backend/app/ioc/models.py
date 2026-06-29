"""
MAP — IOC Models

Database model for Indicators of Compromise.
"""

import enum
import uuid

from sqlalchemy import Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin


class IndicatorType(str, enum.Enum):
    """Types of indicators of compromise."""

    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    MUTEX = "mutex"
    SERVICE_NAME = "service_name"
    SCHEDULED_TASK = "scheduled_task"
    USER_AGENT = "user_agent"
    PIPE_NAME = "pipe_name"


class IOCEntry(Base, TimestampMixin):
    """Individual indicator of compromise linked to a sample."""

    __tablename__ = "ioc_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Indicator data
    indicator_type: Mapped[str] = mapped_column(Enum(IndicatorType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    source: Mapped[str] = mapped_column(
        String(100), nullable=True
    )  # e.g., "static_strings", "memory_netscan"
    context: Mapped[str] = mapped_column(Text, nullable=True)  # where the IOC was found

    # Relationship
    sample = relationship("Sample", back_populates="ioc_entries")

    def __repr__(self) -> str:
        return f"<IOCEntry(type={self.indicator_type}, value={self.value[:30]})>"
