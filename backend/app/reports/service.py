# MAP — Threat Report Service
# Orchestrates generation of threat reports.

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.models import StaticAnalysisResult
from app.detection.models import DetectionRule
from app.ioc.models import IOCEntry
from app.memory.models import MemoryAnalysisResult
from app.reports.generator import ThreatReportGenerator
from app.reports.models import ThreatReport
from app.samples.models import Sample


class ThreatReportService:
    """Service for managing threat reports."""

    def __init__(self):
        self.generator = ThreatReportGenerator()

    async def get_report_by_sample_id(
        self, db: AsyncSession, sample_id: UUID
    ) -> ThreatReport | None:
        """Retrieve threat report for a sample."""
        result = await db.execute(select(ThreatReport).where(ThreatReport.sample_id == sample_id))
        return result.scalar_one_or_none()

    async def list_reports(
        self, db: AsyncSession, skip: int = 0, limit: int = 20
    ) -> tuple[list[ThreatReport], int]:
        """List all threat reports."""
        query = select(ThreatReport)

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        query = query.order_by(ThreatReport.created_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)

        return list(result.scalars().all()), total

    async def generate_report(self, db: AsyncSession, sample: Sample) -> ThreatReport:
        """Generate a threat report for a sample by aggregating all related data."""

        # 1. Gather Sample Meta
        sample_meta = {
            "filename": sample.filename,
            "sha256": sample.sha256,
            "md5": sample.md5,
            "file_size": sample.file_size,
            "file_type": sample.file_type.value if sample.file_type else "unknown",
        }

        # 2. Gather Static Analysis
        static_result = await db.execute(
            select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample.id)
        )
        static = static_result.scalar_one_or_none()
        static_dict = (
            {
                "entropy_score": static.entropy_score,
                "compiler": static.compiler,
                "heuristic_score": static.heuristic_score,
                "heuristic_flags": static.heuristic_flags,
            }
            if static
            else None
        )

        # 3. Gather Memory Analysis
        mem_result = await db.execute(
            select(MemoryAnalysisResult).where(MemoryAnalysisResult.sample_id == sample.id)
        )
        mem = mem_result.scalar_one_or_none()
        mem_dict = {"os_profile": mem.os_profile} if mem else None

        # 4. Gather IOCs
        ioc_result = await db.execute(
            select(IOCEntry)
            .where(IOCEntry.sample_id == sample.id)
            .order_by(IOCEntry.confidence.desc())
        )
        iocs = [
            {
                "indicator_type": ioc.indicator_type.value,
                "value": ioc.value,
                "confidence": ioc.confidence,
            }
            for ioc in ioc_result.scalars().all()
        ]

        # 5. Gather Rules
        rule_result = await db.execute(
            select(DetectionRule).where(DetectionRule.sample_id == sample.id)
        )
        rules = [
            {"rule_name": r.rule_name, "rule_type": r.rule_type.value}
            for r in rule_result.scalars().all()
        ]

        # 6. Generate Report
        report_data = self.generator.generate(sample_meta, static_dict, mem_dict, iocs, rules)

        report = ThreatReport(
            sample_id=sample.id,
            executive_summary=report_data["executive_summary"],
            confidence_level=report_data["confidence_level"],
            file_metadata=report_data["file_metadata"],
            malware_characteristics=report_data["malware_characteristics"],
            attack_mapping=report_data["attack_mapping"],
            observed_indicators=report_data["observed_indicators"],
            ioc_summary=report_data["ioc_summary"],
            detection_opportunities=report_data["detection_opportunities"],
            recommendations=report_data["recommendations"],
            rule_references=report_data["rule_references"],
        )

        # Delete existing if any
        existing = await self.get_report_by_sample_id(db, sample.id)
        if existing:
            await db.delete(existing)
            await db.flush()

        db.add(report)
        await db.commit()
        await db.refresh(report)

        return report


report_service = ThreatReportService()
