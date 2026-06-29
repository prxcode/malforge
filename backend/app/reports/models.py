# models.py

import uuid

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin


class ThreatReport(Base, TimestampMixin):
    """Generated threat intelligence report for a sample."""

    __tablename__ = "threat_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"),
        unique=True, nullable=False
    )

    # Report sections
    executive_summary: Mapped[str] = mapped_column(Text, nullable=True)
    file_metadata: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)
    malware_characteristics: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)
    attack_mapping: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    observed_indicators: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    detection_opportunities: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    rule_references: Mapped[list] = mapped_column(JSON, nullable=True, default=list)
    ioc_summary: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)

    # Report quality
    confidence_level: Mapped[str] = mapped_column(Text, nullable=True, default="medium")

    # Relationship
    sample = relationship("Sample", back_populates="threat_report")

    def __repr__(self) -> str:
        return f"<ThreatReport(sample_id={self.sample_id})>"
