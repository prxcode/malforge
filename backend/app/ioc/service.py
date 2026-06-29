import uuid
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.ioc.models import IOCEntry
from app.ioc.extractors import ioc_extractor
from app.analysis.models import StaticAnalysisResult

class IOCService:
    @staticmethod
    async def extract_and_store_iocs(sample_id: str, session: AsyncSession) -> List[IOCEntry]:
        """Extract IOCs from analysis results and store them."""
        
        sample_uuid = uuid.UUID(sample_id)
        
        # Get static analysis strings
        result = await session.execute(
            select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample_uuid)
        )
        analysis = result.scalars().first()
        
        if not analysis or not analysis.strings:
            return []
            
        # Combine all strings
        all_strings = []
        if isinstance(analysis.strings, dict):
            # If strings were already categorized by string_extractor.py
            for cat, strings_list in analysis.strings.items():
                if isinstance(strings_list, list):
                    all_strings.extend(strings_list)
        else:
            all_strings = analysis.strings
            
        # Extract IOCs
        extracted = ioc_extractor.extract_from_strings(all_strings)
        
        ioc_entries = []
        for item in extracted:
            entry = IOCEntry(
                sample_id=sample_uuid,
                indicator_type=item["indicator_type"],
                value=item["value"],
                confidence=item["confidence"],
                source="Static Analysis Strings"
            )
            session.add(entry)
            ioc_entries.append(entry)
            
        await session.commit()
        return ioc_entries

ioc_service = IOCService()
