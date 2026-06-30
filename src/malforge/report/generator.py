

from typing import Any

from malforge.ioc.extractor import IOC
from malforge.mitre.mapper import AttackMapping


class ReportGenerator:
    """Generates structured threat intelligence reports."""

    def generate(
        self,
        file_metadata: dict[str, Any],
        pe_data: dict[str, Any] | None,
        strings_data: dict[str, list[str]],
        heuristic_flags: list[dict[str, Any]],
        heuristic_score: float,
        iocs: list[IOC],
        attack_mappings: list[AttackMapping],
        yara_rule: str | None,
        sigma_rule: str | None,
        yara_validated: bool,
    ) -> dict[str, Any]:
        """Aggregate analysis data into a structured threat report."""

        # IOC summary counts
        ioc_counts: dict[str, int] = {}
        for ioc in iocs:
            itype = ioc.indicator_type.value
            ioc_counts[itype] = ioc_counts.get(itype, 0) + 1

        # Risk classification
        risk_score = 0.0
        if heuristic_flags:
            risk_score += len(heuristic_flags) * 15.0
        if iocs:
            risk_score += len(iocs) * 5.0
        risk_score = min(100.0, risk_score)

        if risk_score > 60:
            classification = "MALICIOUS"
        elif risk_score > 30:
            classification = "SUSPICIOUS"
        else:
            classification = "BENIGN"

        # Executive summary
        summary = (
            f"Analysis of {file_metadata['filename']} "
            f"(SHA256: {file_metadata['sha256'][:16]}...) "
            f"indicates a {classification.lower()} threat level "
            f"(score: {risk_score:.0f}/100)."
        )
        if attack_mappings:
            tactics = list({m.tactic for m in attack_mappings})
            summary += f" Observed ATT&CK tactics: {', '.join(tactics)}."

        # Build full report
        report: dict[str, Any] = {
            "executive_summary": summary,
            "risk_score": risk_score,
            "classification": classification,
            "file_metadata": file_metadata,
            "heuristic_score": heuristic_score,
            "heuristic_flags": heuristic_flags,
            "attack_mapping": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "evidence": m.evidence,
                }
                for m in attack_mappings
            ],
            "iocs": [
                {
                    "type": ioc.indicator_type.value,
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                }
                for ioc in iocs
            ],
            "ioc_summary": ioc_counts,
            "pe_analysis": pe_data,
            "strings": {
                "urls": strings_data.get("urls", []),
                "ips": strings_data.get("ips", []),
                "registry": strings_data.get("registry", []),
                "paths": strings_data.get("paths", []),
                "suspicious": strings_data.get("suspicious", []),
                "total_count": len(strings_data.get("all", [])),
            },
            "detection_rules": {
                "yara": yara_rule,
                "yara_validated": yara_validated,
                "sigma": sigma_rule,
            },
        }

        return report
