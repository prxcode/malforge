# MAP — Detection Service
# Orchestrates rule generation, validation, and storage.

from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.models import StaticAnalysisResult
from app.core.storage import storage_service
from app.detection.models import DetectionRule, RuleType, ValidationResult
from app.detection.sigma_generator import SigmaGenerator
from app.detection.validator import DetectionValidator
from app.detection.yara_generator import YaraGenerator
from app.ioc.models import IOCEntry
from app.samples.models import Sample

logger = structlog.get_logger()


class DetectionService:
    """Service for managing detection rules."""

    def __init__(self):
        self.yara_generator = YaraGenerator()
        self.sigma_generator = SigmaGenerator()
        self.validator = DetectionValidator()

    async def list_rules_for_sample(
        self, db: AsyncSession, sample_id: UUID
    ) -> tuple[list[DetectionRule], int]:
        """List all rules generated for a specific sample."""
        query = select(DetectionRule).where(DetectionRule.sample_id == sample_id)

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        result = await db.execute(query.order_by(DetectionRule.created_at.desc()))
        items = list(result.scalars().all())

        # load validation results implicitly due to relationship
        return items, total

    async def generate_rules(self, db: AsyncSession, sample: Sample) -> list[DetectionRule]:
        """Generate YARA and Sigma rules for a sample."""
        rules = []

        # 1. Generate YARA if static analysis exists
        static_result = await db.execute(
            select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample.id)
        )
        static_analysis = static_result.scalar_one_or_none()

        if static_analysis:
            # Prepare analysis data for generator
            analysis_data = {
                "suspicious_apis": static_analysis.suspicious_apis,
                "sections": static_analysis.sections,
                "strings": static_analysis.strings.get("suspicious", [])
            }

            yara_text = self.yara_generator.generate(sample.sha256, analysis_data)

            yara_rule = DetectionRule(
                sample_id=sample.id,
                rule_type=RuleType.YARA,
                rule_name=f"MAP_YARA_{sample.sha256[:8]}",
                rule_text=yara_text,
                metadata={"auto_generated": True}
            )
            db.add(yara_rule)
            rules.append(yara_rule)

        # 2. Generate Sigma if IOCs exist
        ioc_result = await db.execute(
            select(IOCEntry).where(IOCEntry.sample_id == sample.id)
        )
        iocs = list(ioc_result.scalars().all())

        if iocs:
            # Convert to dicts for generator
            ioc_dicts = [{"indicator_type": ioc.indicator_type.value, "value": ioc.value} for ioc in iocs]
            sigma_text = self.sigma_generator.generate(sample.sha256, ioc_dicts)

            sigma_rule = DetectionRule(
                sample_id=sample.id,
                rule_type=RuleType.SIGMA,
                rule_name=f"MAP_SIGMA_{sample.sha256[:8]}",
                rule_text=sigma_text,
                metadata={"auto_generated": True}
            )
            db.add(sigma_rule)
            rules.append(sigma_rule)

        await db.commit()
        return rules

    async def validate_rule(self, db: AsyncSession, rule: DetectionRule) -> ValidationResult | None:
        """Run validation pipeline for a rule."""
        if rule.rule_type != RuleType.YARA:
            # Only YARA validation implemented for now
            return None

        # Get sample data
        sample_result = await db.execute(
            select(Sample).where(Sample.id == rule.sample_id)
        )
        sample = sample_result.scalar_one_or_none()

        if not sample:
            return None

        file_data = await storage_service.get_file(sample.sha256, sample.filename)
        if not file_data:
            return None

        # Run validation
        val_data = self.validator.validate_yara(rule.rule_text, file_data)

        # Calculate scores
        tp_rate = 1.0 if val_data["true_positive"] else 0.0
        # Dummy values for false positive testing (would require a goodware dataset in reality)
        fp_rate = 0.0 if val_data["is_valid"] else 1.0

        score = (tp_rate * 100) - (fp_rate * 50)
        score = max(0, min(100, score))

        val_result = ValidationResult(
            rule_id=rule.id,
            true_positive_rate=tp_rate,
            false_positive_rate=fp_rate,
            coverage=tp_rate,
            precision=1.0 if tp_rate > 0 else 0.0,
            recall=tp_rate,
            score=score,
            test_samples_count=1,
            matches_count=len(val_data["matches"]),
            details=val_data
        )

        db.add(val_result)
        await db.commit()
        await db.refresh(val_result)

        return val_result


detection_service = DetectionService()
