from pathlib import Path

import pytest

from malforge.analyzer import Analyzer
from tests.pe_builder import build_pe


@pytest.fixture
def pe_bytes() -> bytes:
    return build_pe()


@pytest.fixture
def pe_file(pe_bytes: bytes, tmp_path: Path) -> Path:
    path = tmp_path / "test_sample.exe"
    path.write_bytes(pe_bytes)
    return path


@pytest.fixture
def analyzer() -> Analyzer:
    return Analyzer(plugins=[])
