# MAP — YARA Generator
# Programmatically generates YARA rules based on sample metadata and analysis.

import datetime
from typing import Any


class YaraGenerator:
    """Generates YARA rules from analysis artifacts."""

    def generate(self, sample_hash: str, analysis_data: dict[str, Any]) -> str:
        """Generate a complete YARA rule."""
        rule_name = f"MAP_Generated_{sample_hash[:8]}"

        # Metadata
        meta = self._generate_meta(sample_hash)

        # Strings
        strings_list, conditions = self._generate_strings_and_conditions(analysis_data)

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
            "author": "MAP_Automated_Engine",
            "description": "Auto-generated rule based on static analysis.",
            "date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d"),
            "hash": sample_hash,
            "tlp": "WHITE",
            "version": "1.0",
        }

    def _generate_strings_and_conditions(
        self, analysis_data: dict[str, Any]
    ) -> tuple[list[str], list[str]]:
        """Generate YARA strings and corresponding conditions."""
        strings = []
        conditions = []

        # Basic PE condition
        conditions.append("uint16(0) == 0x5a4d")  # MZ signature

        # Use suspicious strings
        suspicious = analysis_data.get("suspicious_apis", [])

        str_count = 0
        for s in suspicious:
            # We add simple text strings, properly escaped
            s_escaped = s.replace('"', '\\"')
            strings.append(f'$s{str_count} = "{s_escaped}" ascii wide nocase')
            str_count += 1

        if str_count > 0:
            if str_count > 3:
                conditions.append("3 of ($s*)")
            else:
                conditions.append("all of ($s*)")

        return strings, conditions
