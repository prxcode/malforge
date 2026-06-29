"""
MAP — Sample Models

Database models for uploaded malware samples and metadata.
"""

import enum

from sqlalchemy import BigInteger, Enum, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDMixin


class SampleStatus(str, enum.Enum):
    """Sample processing status."""

    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class FileType(str, enum.Enum):
    """Known file types for analysis."""

    PE_EXE = "pe_exe"
    PE_DLL = "pe_dll"
    ELF = "elf"
    MEMORY_DUMP = "memory_dump"
    ZIP_ARCHIVE = "zip_archive"
    UNKNOWN = "unknown"


class Sample(Base, UUIDMixin, TimestampMixin):
    """Uploaded malware sample or memory image."""

    __tablename__ = "samples"

    # File identity
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)

    # File metadata
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    entropy: Mapped[float] = mapped_column(Float, nullable=True)
    file_type: Mapped[str] = mapped_column(
        Enum(FileType), default=FileType.UNKNOWN, nullable=False
    )
    mime_type: Mapped[str] = mapped_column(String(100), nullable=True)

    # Analysis metadata
    compiler_info: Mapped[str] = mapped_column(Text, nullable=True)
    signature_status: Mapped[str] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(
        Enum(SampleStatus), default=SampleStatus.PENDING, nullable=False
    )

    # Storage
    storage_path: Mapped[str] = mapped_column(String(500), nullable=True)

    # Tags / notes
    tags: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array as text
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Uploader
    uploaded_by: Mapped[str] = mapped_column(String(100), nullable=True)

    # Relationships
    static_analysis = relationship(
        "StaticAnalysisResult", back_populates="sample", uselist=False, cascade="all, delete-orphan"
    )
    memory_analysis = relationship(
        "MemoryAnalysisResult", back_populates="sample", uselist=False, cascade="all, delete-orphan"
    )
    ioc_entries = relationship(
        "IOCEntry", back_populates="sample", cascade="all, delete-orphan"
    )
    detection_rules = relationship(
        "DetectionRule", back_populates="sample", cascade="all, delete-orphan"
    )
    threat_report = relationship(
        "ThreatReport", back_populates="sample", uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Sample(filename={self.filename}, sha256={self.sha256[:16]}...)>"
