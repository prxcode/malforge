import hashlib
import os
import uuid
from pathlib import Path

import aiofiles
from fastapi import UploadFile

from app.core.config import get_settings
from app.core.storage import storage_service
from app.samples.models import Sample

settings = get_settings()

class SampleService:
    @staticmethod
    async def process_upload(file: UploadFile, session) -> Sample:
        # Read file into memory (for small files) or chunks
        content = await file.read()
        
        # Calculate hashes
        sha256 = hashlib.sha256(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        
        # Check if already exists
        # This is a simplified check for a student project
        from sqlalchemy import select
        result = await session.execute(select(Sample).where(Sample.sha256 == sha256))
        existing_sample = result.scalars().first()
        
        if existing_sample:
            return existing_sample
            
        # Save file via storage service
        await storage_service.save_file(sha256, content)
        
        # Create DB record
        sample = Sample(
            filename=file.filename,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            size=len(content),
            status="pending",
        )
        
        session.add(sample)
        await session.commit()
        await session.refresh(sample)
        
        # In a real app, we'd trigger a Celery task here
        # run_static_analysis.delay(str(sample.id))
        
        return sample

sample_service = SampleService()
