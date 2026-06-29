"""
MAP — Detection Rule Models

Database models for YARA rules, Sigma rules, and validation results.
"""

import enum
import uuid

from sqlalchemy import Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin


class RuleType(str, enum.Enum):
    """Detection rule types."""

    YARA = "yara"
    SIGMA = "sigma"


class DetectionRule(Base, TimestampMixin):
    """Generated detection rule (YARA or Sigma)."""

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Rule metadata
    rule_type: Mapped[str] = mapped_column(Enum(RuleType), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    rule_text: Mapped[str] = mapped_column(Text, nullable=False)

    # Rule metadata (tags, description, references, etc.)
    rule_metadata: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)

    # Relationships
    sample = relationship("Sample", back_populates="detection_rules")
    validation_results = relationship(
        "ValidationResult", back_populates="rule", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<DetectionRule(name={self.rule_name}, type={self.rule_type})>"


class ValidationResult(Base, TimestampMixin):
    """Validation metrics for a detection rule."""

    __tablename__ = "validation_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detection_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Metrics
    true_positive_rate: Mapped[float] = mapped_column(Float, nullable=True)
    false_positive_rate: Mapped[float] = mapped_column(Float, nullable=True)
    coverage: Mapped[float] = mapped_column(Float, nullable=True)
    precision: Mapped[float] = mapped_column(Float, nullable=True)
    recall: Mapped[float] = mapped_column(Float, nullable=True)
    score: Mapped[float] = mapped_column(Float, nullable=True)

    # Details
    test_samples_count: Mapped[int] = mapped_column(Integer, nullable=True, default=0)
    matches_count: Mapped[int] = mapped_column(Integer, nullable=True, default=0)
    details: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)

    # Relationship
    rule = relationship("DetectionRule", back_populates="validation_results")

    def __repr__(self) -> str:
        return f"<ValidationResult(rule_id={self.rule_id}, score={self.score})>"
