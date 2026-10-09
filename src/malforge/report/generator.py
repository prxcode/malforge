from collections import Counter
from typing import Any

from malforge.analysis.heuristics import MAX_SCORE
from malforge.ioc.extractor import NETWORK_TYPES
from malforge.result import AnalysisResult

HEURISTIC_POINTS = 60.0
POINTS_PER_TECHNIQUE = 6.0
MAX_TECHNIQUE_POINTS = 30.0
POINTS_PER_NETWORK_IOC = 5.0
MAX_NETWORK_IOC_POINTS = 10.0

MALICIOUS_THRESHOLD = 60.0
SUSPICIOUS_THRESHOLD = 25.0


def risk_score(heuristic_score: float, technique_count: int, network_ioc_count: int) -> float:
    """Combine the evidence into a 0-100 score.

    Heuristics contribute up to 60 points, ATT&CK techniques up to 30 and
    network IOCs up to 10. The sample's own hashes are not evidence and are
    not counted.
    """
    score = (
        heuristic_score / MAX_SCORE * HEURISTIC_POINTS
        + min(technique_count * POINTS_PER_TECHNIQUE, MAX_TECHNIQUE_POINTS)
        + min(network_ioc_count * POINTS_PER_NETWORK_IOC, MAX_NETWORK_IOC_POINTS)
    )
    return round(min(score, 100.0), 1)


def classify(score: float) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "BENIGN"


class ReportGenerator:
    """Builds the JSON-serialisable report that feeds every output format and plugin."""

    def generate(self, data: AnalysisResult) -> dict[str, Any]:
        network_iocs = sum(1 for ioc in data.iocs if ioc.indicator_type in NETWORK_TYPES)
        score = risk_score(data.heuristic_score, len(data.attack_mappings), network_iocs)
        classification = classify(score)

        summary = (
            f"Static analysis of {data.file_metadata['filename']} rates it "
            f"{classification.lower()} with a risk score of {score:.0f}/100."
        )
        tactics = sorted({m.tactic for m in data.attack_mappings})
        if tactics:
            summary += f" Observed ATT&CK tactics: {', '.join(tactics)}."

        validation = data.yara_validation
        return {
            "executive_summary": summary,
            "risk_score": score,
            "classification": classification,
            "file_metadata": data.file_metadata,
            "heuristic_score": data.heuristic_score,
            "heuristic_flags": [f.to_dict() for f in data.heuristic_flags],
            "attack_mapping": [m.to_dict() for m in data.attack_mappings],
            "iocs": [ioc.to_dict() for ioc in data.iocs],
            "ioc_summary": dict(Counter(ioc.indicator_type.value for ioc in data.iocs)),
            "pe_analysis": data.pe_data,
            "strings": {
                "total_count": len(data.strings.all),
                "suspicious": data.strings.suspicious,
            },
            "detection_rules": {
                "yara": data.yara_rule,
                "yara_compiles": bool(validation and validation.is_valid),
                "yara_matches_sample": bool(validation and validation.true_positive),
                "sigma": data.sigma_rule,
            },
        }
