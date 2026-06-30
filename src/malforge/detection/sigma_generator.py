
import datetime
import uuid

from malforge.ioc.extractor import IOC, IndicatorType


class SigmaGenerator:
    """Generates Sigma rules from analysis artifacts."""

    def generate(self, sample_hash: str, iocs: list[IOC]) -> str | None:
        """Generate Sigma rules based on IOCs. Returns None if no useful IOCs found."""
        file_paths = [ioc.value for ioc in iocs if ioc.indicator_type == IndicatorType.FILE_PATH]
        reg_keys = [ioc.value for ioc in iocs if ioc.indicator_type == IndicatorType.REGISTRY_KEY]
        domains = [ioc.value for ioc in iocs if ioc.indicator_type == IndicatorType.DOMAIN]
        ips = [ioc.value for ioc in iocs if ioc.indicator_type == IndicatorType.IPV4]

        if not file_paths and not reg_keys and not domains and not ips:
            return None

        title = f"Suspicious Activity — Malforge {sample_hash[:8]}"
        date = datetime.datetime.now(datetime.UTC).strftime("%Y/%m/%d")

        yaml_lines = [
            f"title: {title}",
            f"id: {self._generate_uuid(sample_hash)}",
            "status: experimental",
            f"description: Auto-generated Sigma rule for sample {sample_hash}.",
            "author: Malforge",
            f"date: {date}",
            "logsource:",
            "    category: process_creation",
            "    product: windows",
            "detection:",
        ]

        selections = []

        if file_paths:
            selections.append("selection_files")
            yaml_lines.append("    selection_files:")
            yaml_lines.append("        Image|endswith:")
            for path in file_paths[:5]:
                filename = path.split("\\")[-1]
                if filename:
                    yaml_lines.append(f"            - '\\{filename}'")

        if reg_keys:
            selections.append("selection_registry")
            yaml_lines.append("    selection_registry:")
            yaml_lines.append("        TargetObject|contains:")
            for key in reg_keys[:5]:
                yaml_lines.append(f"            - '{key}'")

        if domains:
            selections.append("selection_dns")
            yaml_lines.append("    selection_dns:")
            yaml_lines.append("        QueryName|endswith:")
            for domain in domains[:5]:
                yaml_lines.append(f"            - '{domain}'")

        if ips:
            selections.append("selection_network")
            yaml_lines.append("    selection_network:")
            yaml_lines.append("        DestinationIp:")
            for ip in ips[:5]:
                yaml_lines.append(f"            - '{ip}'")

        yaml_lines.append(f"    condition: {' or '.join(selections)}")
        yaml_lines.extend(["falsepositives:", "    - Unknown", "level: medium"])

        return "\n".join(yaml_lines)

    def _generate_uuid(self, hash_str: str) -> str:
        """Generate a stable pseudo-UUID based on the hash."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"malforge.{hash_str}"))
