# MAP — Sigma Generator
# Programmatically generates Sigma rules based on extracted IOCs and behaviors.

import datetime
from typing import Any


class SigmaGenerator:
    """Generates Sigma rules from analysis artifacts."""

    def generate(self, sample_hash: str, iocs: list[dict[str, Any]]) -> str:
        """Generate a basic Sigma rule based on file paths and registry keys."""

        title = f"Suspicious Activity associated with {sample_hash[:8]}"
        date = datetime.datetime.now(datetime.UTC).strftime("%Y/%m/%d")

        # Filter IOCs
        file_paths = [ioc["value"] for ioc in iocs if ioc["indicator_type"] == "file_path"]
        reg_keys = [ioc["value"] for ioc in iocs if ioc["indicator_type"] == "registry_key"]

        # Build YAML structure manually to ensure proper Sigma formatting
        yaml_lines = [
            f"title: {title}",
            f"id: {self._generate_uuid(sample_hash)}",
            "status: experimental",
            "description: Auto-generated Sigma rule from MAP platform.",
            "author: MAP_Automated_Engine",
            f"date: {date}",
            "logsource:",
            "    category: process_creation",
            "    product: windows",
            "detection:",
        ]

        has_selection = False

        if file_paths:
            has_selection = True
            yaml_lines.append("    selection_files:")
            yaml_lines.append("        Image|endswith:")
            for path in file_paths[:5]:  # Take top 5 to avoid massive rules
                # extract just the filename part for matching if possible
                filename = path.split("\\")[-1]
                if filename:
                    yaml_lines.append(f"            - '\\{filename}'")

        if reg_keys:
            has_selection = True
            yaml_lines.append("    selection_registry:")
            yaml_lines.append("        TargetObject|contains:")
            for key in reg_keys[:5]:
                yaml_lines.append(f"            - '{key}'")

        if not has_selection:
            # Fallback dummy rule if no useful IOCs found
            yaml_lines.append("    selection:")
            yaml_lines.append(f"        Hashes|contains: 'SHA256={sample_hash}'")
            yaml_lines.append("    condition: selection")
        else:
            # Simpler condition builder
            selections = []
            if file_paths:
                selections.append("selection_files")
            if reg_keys:
                selections.append("selection_registry")

            yaml_lines.append(f"    condition: {' or '.join(selections)}")

        yaml_lines.extend(["falsepositives:", "    - Unknown", "level: medium"])

        return "\n".join(yaml_lines)

    def _generate_uuid(self, hash_str: str) -> str:
        """Generate a stable pseudo-UUID based on the hash."""
        import uuid

        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"map.local.{hash_str}"))
