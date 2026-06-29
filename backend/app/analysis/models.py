"""
MAP — Static Analysis Models

Database model for static analysis results.
"""

import uuid

from sqlalchemy import Float, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin


class StaticAnalysisResult(Base, TimestampMixin):
    """Static analysis results for a sample."""

    __tablename__ = "static_analysis_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"),
        unique=True, nullable=False
    )

    # PE Structure
    headers: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)
    sections: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    imports: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    exports: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    resources: Mapped[list] = mapped_column(JSON, nullable=True, default=list)

    # Strings
    strings: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)

    # Analysis
    compiler: Mapped[str] = mapped_column(Text, nullable=True)
    entropy_score: Mapped[float] = mapped_column(Float, nullable=True)
    suspicious_apis: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    heuristic_flags: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    heuristic_score: Mapped[float] = mapped_column(Float, nullable=True, default=0.0)

    # Entry point
    entry_point: Mapped[str] = mapped_column(Text, nullable=True)
    image_base: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationship
    sample = relationship("Sample", back_populates="static_analysis")

    def __repr__(self) -> str:
        return f"<StaticAnalysisResult(sample_id={self.sample_id})>"
