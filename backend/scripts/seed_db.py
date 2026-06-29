import asyncio
import uuid
import sys
from pathlib import Path
from datetime import datetime

# Add backend directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import text

from app.core.config import get_settings
from app.samples.models import Sample
from app.analysis.models import StaticAnalysisResult
from app.detection.models import DetectionRule, RuleType

settings = get_settings()

engine = create_async_engine(settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"))
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def seed_data():
    """Seed the database with synthetic data for testing and UI demonstration."""
    async with AsyncSessionLocal() as session:
        # Check if we already have data
        result = await session.execute(text("SELECT COUNT(*) FROM samples"))
        count = result.scalar()
        if count > 0:
            print("Database already contains data. Skipping seed.")
            return

        print("Seeding database with synthetic malware samples...")

        # Create Sample 1
        sample1 = Sample(
            id=uuid.uuid4(),
            filename="invoice_updated_2024.exe",
            original_filename="invoice_updated_2024.exe",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size=2450000,
            mime_type="application/x-dosexec",
            status="completed"
        )
        session.add(sample1)

        # Create Analysis for Sample 1
        analysis1 = StaticAnalysisResult(
            id=uuid.uuid4(),
            sample_id=sample1.id,
            headers={"Machine": "IMAGE_FILE_MACHINE_I386", "Magic": "PE32"},
            sections=[
                {"name": ".text", "entropy": 6.42, "virtual_size": 17000},
                {"name": ".UPX0", "entropy": 7.99, "virtual_size": 73728}
            ],
            imports=[{"dll": "kernel32.dll", "functions": ["VirtualAlloc", "CreateRemoteThread"]}],
            exports=[],
            strings=["http://malicious-c2.example.com/drop", "powershell.exe -ExecutionPolicy Bypass"],
            heuristic_flags=[{"description": "High entropy section (.UPX0) detected", "severity": "high"}]
        )
        session.add(analysis1)

        # Create Detection Rule for Sample 1
        yara1 = DetectionRule(
            id=uuid.uuid4(),
            sample_id=sample1.id,
            rule_type=RuleType.YARA,
            rule_name="Auto_Generated_invoice_updated",
            rule_text="rule Auto_Generated {\n  strings:\n    $s1 = \"powershell.exe\"\n  condition:\n    uint16(0) == 0x5A4D and all of them\n}",
            rule_metadata={"author": "MAP Pipeline"}
        )
        session.add(yara1)

        # Create Sample 2
        sample2 = Sample(
            id=uuid.uuid4(),
            filename="setup_v2.1.msi",
            original_filename="setup_v2.1.msi",
            sha256="8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            file_size=4100000,
            mime_type="application/x-msi",
            status="completed"
        )
        session.add(sample2)

        await session.commit()
        print("Successfully seeded synthetic data.")

if __name__ == "__main__":
    asyncio.run(seed_data())
