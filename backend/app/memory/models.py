"""
MAP — Memory Analysis Models

Database model for memory forensics analysis results.
"""

import uuid

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin


class MemoryAnalysisResult(Base, TimestampMixin):
    """Memory forensics analysis results for a sample."""

    __tablename__ = "memory_analysis_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"),
        unique=True, nullable=False
    )

    # Process analysis
    processes: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    process_tree: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)

    # Module analysis
    modules: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Registry
    registry: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Services
    services: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Network
    network_connections: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Handles
    handles: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Command history
    command_history: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Injected memory
    injected_memory: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Timeline
    timeline: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Analysis metadata
    os_profile: Mapped[str] = mapped_column(Text, nullable=True)
    analysis_status: Mapped[str] = mapped_column(Text, nullable=True, default="pending")
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationship
    sample = relationship("Sample", back_populates="memory_analysis")

    def __repr__(self) -> str:
        return f"<MemoryAnalysisResult(sample_id={self.sample_id})>"
