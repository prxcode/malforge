import json
import logging
from collections.abc import Iterable
from pathlib import Path

from malforge.analysis.file_info import file_metadata
from malforge.analysis.heuristics import HeuristicsEngine
from malforge.analysis.pe_analyzer import PEAnalyzer
from malforge.analysis.string_extractor import StringExtractor
from malforge.detection.sigma_generator import SigmaGenerator
from malforge.detection.validator import DetectionValidator
from malforge.detection.yara_generator import YaraGenerator
from malforge.ioc.extractor import IOC, IndicatorType, IOCExtractor
from malforge.mitre.mapper import MitreMapper
from malforge.plugins import MalforgePlugin, load_plugins
from malforge.report.generator import ReportGenerator
from malforge.report.html_report import HtmlReportRenderer
from malforge.result import AnalysisResult

logger = logging.getLogger(__name__)

REPORT_FORMATS = frozenset({"json", "html"})


class Analyzer:
    """Runs the static analysis pipeline on a file and writes its outputs."""

    def __init__(
        self,
        *,
        yara: bool = True,
        sigma: bool = True,
        plugins: list[MalforgePlugin] | None = None,
    ) -> None:
        self.yara_enabled = yara
        self.sigma_enabled = sigma
        self.plugins = load_plugins() if plugins is None else plugins

        self.ioc_extractor = IOCExtractor()
        self.mitre_mapper = MitreMapper()
        self.yara_generator = YaraGenerator()
        self.sigma_generator = SigmaGenerator()
        self.validator = DetectionValidator()
        self.report_generator = ReportGenerator()
        self.html_renderer = HtmlReportRenderer()

    def analyze(self, file_path: Path) -> AnalysisResult:
        data = file_path.read_bytes()
        result = AnalysisResult(file_metadata=file_metadata(file_path, data))
        logger.info("Analyzing %s (%d bytes)", file_path.name, len(data))

        result.strings = StringExtractor(data).extract()
        logger.info("Extracted %d strings", len(result.strings.all))

        result.pe_data = PEAnalyzer(data).analyze()
        if result.pe_data is None:
            logger.warning("%s is not a PE file; skipping PE heuristics", file_path.name)
        else:
            heuristics = HeuristicsEngine(result.pe_data).analyze()
            result.heuristic_flags = heuristics.flags
            result.heuristic_score = heuristics.score
            result.suspicious_apis = heuristics.suspicious_apis
            logger.info(
                "Heuristic score %.1f from %d flags", heuristics.score, len(heuristics.flags)
            )

        result.iocs = self.ioc_extractor.extract_from_strings(result.strings.all)
        result.iocs.extend(_hash_iocs(result.file_metadata))
        logger.info("Extracted %d IOCs", len(result.iocs))

        result.attack_mappings = self.mitre_mapper.map(
            result.heuristic_flags, result.strings.suspicious, result.iocs
        )
        logger.info("Mapped %d ATT&CK techniques", len(result.attack_mappings))

        sha256 = result.file_metadata["sha256"]
        if self.yara_enabled:
            result.yara_rule = self.yara_generator.generate(
                sha256, result.suspicious_apis, result.iocs
            )
            if result.yara_rule:
                result.yara_validation = self.validator.validate_yara(result.yara_rule, data)
        if self.sigma_enabled:
            result.sigma_rule = self.sigma_generator.generate(sha256, result.iocs)

        result.report = self.report_generator.generate(result)

        for plugin in self.plugins:
            try:
                result.report = plugin.on_analysis_complete(result.report)
            except Exception:
                logger.exception("Plugin %s failed", plugin.name)

        return result

    def write_outputs(
        self,
        result: AnalysisResult,
        output_dir: Path,
        formats: Iterable[str] = REPORT_FORMATS,
    ) -> dict[str, Path]:
        """Write reports, IOCs, ATT&CK mappings and rules; return the paths by output kind."""
        formats = set(formats)
        unknown = formats - REPORT_FORMATS
        if unknown:
            raise ValueError(f"Unknown report format(s): {', '.join(sorted(unknown))}")

        output_dir.mkdir(parents=True, exist_ok=True)
        outputs: dict[str, Path] = {}

        def write(kind: str, relative: str, content: str) -> None:
            path = output_dir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            outputs[kind] = path

        if "html" in formats:
            write("report_html", "report.html", self.html_renderer.render(result.report))
        if "json" in formats:
            write("report_json", "report.json", _to_json(result.report))
        write("iocs", "iocs.json", _to_json([ioc.to_dict() for ioc in result.iocs]))
        write(
            "mitre", "mitre_mapping.json", _to_json([m.to_dict() for m in result.attack_mappings])
        )
        if result.yara_rule:
            write("yara", "rules/yara_rule.yar", result.yara_rule)
        if result.sigma_rule:
            write("sigma", "rules/sigma_rule.yml", result.sigma_rule)

        return outputs


def _to_json(data: object) -> str:
    return json.dumps(data, indent=2, default=str) + "\n"


def _hash_iocs(metadata: dict[str, str]) -> list[IOC]:
    return [
        IOC(
            indicator_type=ioc_type,
            value=metadata[key],
            confidence=1.0,
            source="file_hash",
            context=f"Hash of analyzed file {metadata['filename']}",
        )
        for key, ioc_type in (
            ("md5", IndicatorType.FILE_HASH_MD5),
            ("sha1", IndicatorType.FILE_HASH_SHA1),
            ("sha256", IndicatorType.FILE_HASH_SHA256),
        )
    ]
