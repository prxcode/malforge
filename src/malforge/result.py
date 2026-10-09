from dataclasses import dataclass, field
from typing import Any

from malforge.analysis.heuristics import HeuristicFlag
from malforge.analysis.string_extractor import ExtractedStrings
from malforge.detection.validator import ValidationResult
from malforge.ioc.extractor import IOC
from malforge.mitre.mapper import AttackMapping


@dataclass
class AnalysisResult:
    """Everything the pipeline produced for one file."""

    file_metadata: dict[str, Any] = field(default_factory=dict)
    pe_data: dict[str, Any] | None = None
    strings: ExtractedStrings = field(default_factory=ExtractedStrings)
    heuristic_flags: list[HeuristicFlag] = field(default_factory=list)
    heuristic_score: float = 0.0
    suspicious_apis: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    attack_mappings: list[AttackMapping] = field(default_factory=list)
    yara_rule: str | None = None
    yara_validation: ValidationResult | None = None
    sigma_rule: str | None = None
    report: dict[str, Any] = field(default_factory=dict)
