import datetime
from typing import Any

from malforge.ioc.extractor import IOC, IndicatorType


class YaraGenerator:
    """Generates YARA rules from analysis artifacts."""

    def generate(
        self,
        sample_hash: str,
        analysis_data: dict[str, Any],
        iocs: list[IOC] | None = None,
    ) -> str:
        """Generate a complete YARA rule."""
        rule_name = f"Malforge_{sample_hash[:8]}"

        meta = self._generate_meta(sample_hash)
        strings_list, conditions = self._generate_strings_and_conditions(
            analysis_data, iocs or []
        )

        # Format the rule
        rule_lines = [f"rule {rule_name} {{", "    meta:"]

        for k, v in meta.items():
            rule_lines.append(f'        {k} = "{v}"')

        if strings_list:
            rule_lines.append("")
            rule_lines.append("    strings:")
            for s in strings_list:
                rule_lines.append(f"        {s}")

        rule_lines.append("")
        rule_lines.append("    condition:")

        for i, c in enumerate(conditions):
            if i == 0:
                rule_lines.append(f"        {c}")
            else:
                rule_lines.append(f"        and {c}")

        rule_lines.append("}")

        return "\n".join(rule_lines)

    def _generate_meta(self, sample_hash: str) -> dict[str, str]:
        """Generate standard YARA metadata."""
        return {
            "author": "Malforge",
            "description": "Auto-generated detection rule from static analysis.",
            "date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d"),
            "hash": sample_hash,
            "tlp": "WHITE",
            "version": "1.0",
        }

    def _generate_strings_and_conditions(
        self,
        analysis_data: dict[str, Any],
        iocs: list[IOC],
    ) -> tuple[list[str], list[str]]:
        """Generate YARA strings and corresponding conditions."""
        strings = []
        conditions = []

        # Basic PE condition
        conditions.append("uint16(0) == 0x5a4d")  # MZ signature

        str_count = 0

        # Use suspicious API strings
        suspicious = analysis_data.get("suspicious_apis", [])
        for s in suspicious:
            s_escaped = s.replace('"', '\\"')
            strings.append(f'$s{str_count} = "{s_escaped}" ascii wide nocase')
            str_count += 1

        # Add network IOCs as YARA strings
        ioc_count = 0
        for ioc in iocs:
            if ioc.indicator_type == IndicatorType.URL:
                url_escaped = ioc.value.replace('"', '\\"')
                strings.append(f'$ioc_url{ioc_count} = "{url_escaped}" ascii wide')
                ioc_count += 1
            elif ioc.indicator_type == IndicatorType.IPV4:
                strings.append(f'$ioc_ip{ioc_count} = "{ioc.value}" ascii wide')
                ioc_count += 1
            elif ioc.indicator_type == IndicatorType.DOMAIN:
                strings.append(f'$ioc_dom{ioc_count} = "{ioc.value}" ascii wide')
                ioc_count += 1

        # Build conditions based on string counts
        if str_count > 0:
            if str_count > 3:
                conditions.append("3 of ($s*)")
            else:
                conditions.append("all of ($s*)")

        if ioc_count > 0:
            if ioc_count > 3:
                conditions.append("2 of ($ioc_*)")
            else:
                conditions.append("any of ($ioc_*)")

        return strings, conditions
