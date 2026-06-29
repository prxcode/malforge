import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.reports.models import ThreatReport
from app.reports.generator import report_generator
from app.samples.models import Sample
from app.ioc.models import IOCEntry
from app.detection.models import DetectionRule
from app.analysis.models import StaticAnalysisResult

class ReportService:
    @staticmethod
    async def generate_report(sample_id: str, session: AsyncSession) -> ThreatReport:
        sample_uuid = uuid.UUID(sample_id)
        
        # 1. Fetch sample
        sample_res = await session.execute(select(Sample).where(Sample.id == sample_uuid))
        sample = sample_res.scalars().first()
        if not sample:
            raise ValueError("Sample not found")

        # 2. Fetch IOCs
        ioc_res = await session.execute(select(IOCEntry).where(IOCEntry.sample_id == sample_uuid))
        iocs = ioc_res.scalars().all()
        
        # 3. Fetch Rules
        rules_res = await session.execute(select(DetectionRule).where(DetectionRule.sample_id == sample_uuid))
        rules = rules_res.scalars().all()
        
        # 4. Fetch Analysis
        analysis_res = await session.execute(select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample_uuid))
        analysis = analysis_res.scalars().first()
        
        heuristics = analysis.heuristic_flags if analysis else []
        
        # Generate content
        exec_summary = report_generator.generate_executive_summary(sample.filename, len(iocs), len(rules))
        attack_mapping = report_generator.generate_attack_mapping(heuristics)
        recommendations = report_generator.generate_recommendations()
        
        # Calculate IOC summary
        ioc_summary = {}
        for ioc in iocs:
            ioc_summary[ioc.indicator_type] = ioc_summary.get(ioc.indicator_type, 0) + 1
            
        report = ThreatReport(
            sample_id=sample_uuid,
            executive_summary=exec_summary,
            file_metadata={"filename": sample.filename, "size": sample.size, "sha256": sample.sha256},
            malware_characteristics={"entropy": getattr(analysis, 'entropy_score', None)},
            attack_mapping=attack_mapping,
            observed_indicators=[{"type": i.indicator_type, "value": i.value} for i in iocs[:10]],
            detection_opportunities=[{"rule_type": r.rule_type, "name": r.rule_name} for r in rules],
            recommendations=recommendations,
            ioc_summary=ioc_summary,
            rule_references=[r.rule_name for r in rules],
            confidence_level="high" if heuristics else "medium"
        )
        
        session.add(report)
        await session.commit()
        await session.refresh(report)
        return report

report_service = ReportService()
