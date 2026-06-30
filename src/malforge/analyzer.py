import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from malforge.analysis.heuristics import HeuristicsEngine
from malforge.analysis.pe_analyzer import PEAnalyzer
from malforge.analysis.string_extractor import StringExtractor
from malforge.detection.sigma_generator import SigmaGenerator
from malforge.detection.validator import DetectionValidator, ValidationResult
from malforge.detection.yara_generator import YaraGenerator
from malforge.ioc.extractor import IOC, IOCExtractor
from malforge.mitre.mapper import AttackMapping, MitreMapper
from malforge.plugins import load_plugins
from malforge.report.generator import ReportGenerator
from malforge.report.html_report import HtmlReportRenderer

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Complete result of analyzing a file."""

    file_metadata: dict[str, Any] = field(default_factory=dict)
    pe_data: dict[str, Any] | None = None
    strings_data: dict[str, list[str]] = field(default_factory=dict)
    heuristic_flags: list[dict[str, Any]] = field(default_factory=list)
    heuristic_score: float = 0.0
    suspicious_apis: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    attack_mappings: list[AttackMapping] = field(default_factory=list)
    yara_rule: str | None = None
    sigma_rule: str | None = None
    yara_validation: ValidationResult | None = None
    report: dict[str, Any] = field(default_factory=dict)


class Analyzer:
    """Runs the full malforge analysis pipeline on a file."""

    def __init__(self) -> None:
        self.ioc_extractor = IOCExtractor()
        self.yara_generator = YaraGenerator()
        self.sigma_generator = SigmaGenerator()
        self.validator = DetectionValidator()
        self.mitre_mapper = MitreMapper()
        self.report_generator = ReportGenerator()
        self.html_renderer = HtmlReportRenderer()

    def analyze(self, file_path: Path) -> AnalysisResult:
        """Run the full analysis pipeline on a file."""
        result = AnalysisResult()

        # 1. Read file and compute hashes
        file_data = file_path.read_bytes()
        result.file_metadata = self._compute_file_metadata(file_path, file_data)
        logger.info("Analyzing: %s (%s bytes)", file_path.name, len(file_data))

        # 2. String extraction
        str_extractor = StringExtractor(file_data)
        result.strings_data = str_extractor.extract()
        logger.info("Extracted %d strings", len(result.strings_data.get("all", [])))

        # 3. PE analysis
        pe_analyzer = PEAnalyzer(file_data)
        pe_data = pe_analyzer.analyze()

        if "error" not in pe_data:
            result.pe_data = pe_data

            # 4. Heuristic analysis
            heuristics = HeuristicsEngine(pe_data, result.strings_data)
            result.heuristic_flags, result.heuristic_score = heuristics.analyze()

            # Extract suspicious APIs from imports
            all_funcs: set[str] = set()
            for imp in pe_data.get("imports", []):
                all_funcs.update([f.lower() for f in imp.get("functions", [])])

            suspicious_keywords = [
                "virtualalloc",
                "writeprocessmemory",
                "createremotethread",
                "setwindowshook",
                "isdebuggerpresent",
            ]
            for func in all_funcs:
                for keyword in suspicious_keywords:
                    if keyword in func:
                        result.suspicious_apis.append(func)
            result.suspicious_apis = list(set(result.suspicious_apis))
            logger.info(
                "Heuristic score: %.1f, flags: %d",
                result.heuristic_score,
                len(result.heuristic_flags),
            )
        else:
            logger.warning("Not a valid PE file, skipping PE-specific analysis")

        # 5. IOC extraction
        all_strings = result.strings_data.get("all", [])
        result.iocs = self.ioc_extractor.extract_from_strings(all_strings)

        # Add file hashes as IOCs
        result.iocs.extend(self._hash_iocs(result.file_metadata))
        logger.info("Extracted %d IOCs", len(result.iocs))

        # 6. MITRE ATT&CK mapping
        result.attack_mappings = self.mitre_mapper.map(
            result.heuristic_flags,
            result.strings_data.get("suspicious", []),
            result.iocs,
        )
        logger.info("Mapped %d ATT&CK techniques", len(result.attack_mappings))

        # 7. YARA rule generation
        analysis_data = {"suspicious_apis": result.suspicious_apis}
        result.yara_rule = self.yara_generator.generate(
            result.file_metadata["sha256"],
            analysis_data,
            result.iocs,
        )

        # 8. YARA validation
        result.yara_validation = self.validator.validate_yara(
            result.yara_rule, file_data
        )
        logger.info("YARA rule validated: %s", result.yara_validation.is_valid)

        # 9. Sigma rule generation
        result.sigma_rule = self.sigma_generator.generate(
            result.file_metadata["sha256"],
            result.iocs,
        )

        # 10. Generate report
        result.report = self.report_generator.generate(
            file_metadata=result.file_metadata,
            pe_data=result.pe_data,
            strings_data=result.strings_data,
            heuristic_flags=result.heuristic_flags,
            heuristic_score=result.heuristic_score,
            iocs=result.iocs,
            attack_mappings=result.attack_mappings,
            yara_rule=result.yara_rule,
            sigma_rule=result.sigma_rule,
            yara_validated=(
                result.yara_validation.is_valid if result.yara_validation else False
            ),
        )

        # 11. Run plugins
        plugins = load_plugins()
        for plugin in plugins:
            try:
                result.report = plugin.on_analysis_complete(result.report)
                logger.info("Plugin %s executed", plugin.name)
            except Exception as e:
                logger.error("Plugin %s failed: %s", plugin.name, e)

        return result

    def write_outputs(
        self, result: AnalysisResult, output_dir: Path
    ) -> dict[str, Path]:
        """Write all analysis outputs to the given directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        rules_dir = output_dir / "rules"
        rules_dir.mkdir(exist_ok=True)

        outputs: dict[str, Path] = {}

        # JSON report
        report_json_path = output_dir / "report.json"
        report_json_path.write_text(
            json.dumps(result.report, indent=2, default=str), encoding="utf-8"
        )
        outputs["report_json"] = report_json_path

        # HTML report
        report_html_path = output_dir / "report.html"
        self.html_renderer.render_to_file(result.report, report_html_path)
        outputs["report_html"] = report_html_path

        # IOCs JSON
        iocs_path = output_dir / "iocs.json"
        iocs_data = [
            {
                "type": ioc.indicator_type.value,
                "value": ioc.value,
                "confidence": ioc.confidence,
                "source": ioc.source,
            }
            for ioc in result.iocs
        ]
        iocs_path.write_text(json.dumps(iocs_data, indent=2), encoding="utf-8")
        outputs["iocs"] = iocs_path

        # MITRE mapping JSON
        mitre_path = output_dir / "mitre_mapping.json"
        mitre_data = [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "evidence": m.evidence,
            }
            for m in result.attack_mappings
        ]
        mitre_path.write_text(json.dumps(mitre_data, indent=2), encoding="utf-8")
        outputs["mitre"] = mitre_path

        # YARA rule
        if result.yara_rule:
            yara_path = rules_dir / "yara_rule.yar"
            yara_path.write_text(result.yara_rule, encoding="utf-8")
            outputs["yara"] = yara_path

        # Sigma rule
        if result.sigma_rule:
            sigma_path = rules_dir / "sigma_rule.yml"
            sigma_path.write_text(result.sigma_rule, encoding="utf-8")
            outputs["sigma"] = sigma_path

        return outputs

    def _compute_file_metadata(
        self, file_path: Path, file_data: bytes
    ) -> dict[str, Any]:
        """Compute file hashes and metadata."""
        return {
            "filename": file_path.name,
            "file_path": str(file_path.resolve()),
            "file_size": len(file_data),
            "sha256": hashlib.sha256(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "md5": hashlib.md5(file_data).hexdigest(),
            "entropy": round(self._compute_entropy(file_data), 4),
        }

    def _compute_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data."""
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in counts:
            if count > 0:
                freq = count / length
                entropy -= freq * math.log2(freq)
        return entropy

    def _hash_iocs(self, file_metadata: dict[str, Any]) -> list[IOC]:
        """Create IOC entries for the file's own hashes."""
        from malforge.ioc.extractor import IndicatorType

        hash_iocs = []
        for hash_type, ioc_type in [
            ("md5", IndicatorType.FILE_HASH_MD5),
            ("sha1", IndicatorType.FILE_HASH_SHA1),
            ("sha256", IndicatorType.FILE_HASH_SHA256),
        ]:
            hash_iocs.append(
                IOC(
                    indicator_type=ioc_type,
                    value=file_metadata[hash_type],
                    confidence=1.0,
                    source="file_hash",
                    context=f"Hash of analyzed file: {file_metadata['filename']}",
                )
            )
        return hash_iocs
