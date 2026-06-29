import uuid
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.detection.models import DetectionRule
from app.detection.yara_generator import yara_generator
from app.detection.sigma_generator import sigma_generator
from app.analysis.models import StaticAnalysisResult

class DetectionService:
    @staticmethod
    async def generate_rules(sample_id: str, session: AsyncSession) -> List[DetectionRule]:
        """Generate YARA and Sigma rules for a sample."""
        
        sample_uuid = uuid.UUID(sample_id)
        
        # Get static analysis results
        result = await session.execute(
            select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample_uuid)
        )
        analysis = result.scalars().first()
        
        if not analysis:
            raise ValueError(f"Analysis for sample {sample_id} not found")
            
        rules = []
        
        # Generate YARA
        pe_data = {
            "sections": analysis.sections,
            "imports": analysis.imports,
            "exports": analysis.exports,
            "headers": analysis.headers
        }
        strings_data = analysis.strings if isinstance(analysis.strings, dict) else {}
        
        yara_text = yara_generator.generate_from_analysis(sample_id, pe_data, strings_data)
        
        yara_rule = DetectionRule(
            sample_id=sample_uuid,
            rule_type="YARA",
            rule_name=f"YARA_{sample_id[:8]}",
            version=1,
            rule_text=yara_text,
            rule_metadata={}
        )
        session.add(yara_rule)
        rules.append(yara_rule)
        
        # Generate Sigma
        sigma_text = sigma_generator.generate_from_analysis(sample_id, strings_data)
        
        sigma_rule = DetectionRule(
            sample_id=sample_uuid,
            rule_type="SIGMA",
            rule_name=f"SIGMA_{sample_id[:8]}",
            version=1,
            rule_text=sigma_text,
            rule_metadata={}
        )
        session.add(sigma_rule)
        rules.append(sigma_rule)
        
        await session.commit()
        return rules

detection_service = DetectionService()
