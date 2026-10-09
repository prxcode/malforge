import datetime
import uuid
from dataclasses import dataclass

from malforge.ioc.extractor import IOC, IndicatorType

MAX_VALUES_PER_RULE = 10


@dataclass(frozen=True)
class SigmaTemplate:
    category: str
    title: str
    field: str


TEMPLATES = {
    IndicatorType.FILE_PATH: SigmaTemplate("process_creation", "Process Image", "Image|endswith"),
    IndicatorType.REGISTRY_KEY: SigmaTemplate(
        "registry_set", "Registry Key", "TargetObject|contains"
    ),
    IndicatorType.DOMAIN: SigmaTemplate("dns_query", "DNS Query", "QueryName"),
    IndicatorType.IPV4: SigmaTemplate("network_connection", "Network Connection", "DestinationIp"),
}


def quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _process_image(path: str) -> str | None:
    name = path.rsplit("\\", 1)[-1]
    return "\\" + name if name.lower().endswith(".exe") else None


def _registry_subkey(key: str) -> str:
    """Drop the hive so the value matches both HKLM\\... and HKEY_LOCAL_MACHINE\\... forms."""
    return key.split("\\", 1)[1] if "\\" in key else key


class SigmaGenerator:
    """Generates Sigma rules from extracted IOCs, one rule per log source."""

    def generate(self, sample_hash: str, iocs: list[IOC]) -> str | None:
        """Return a multi-document YAML rule collection, or None if no IOC is usable."""
        rules = []
        for ind_type, template in TEMPLATES.items():
            values = self._values(ind_type, iocs)
            if values:
                rules.append(self._render(sample_hash, template, values))
        return "---\n".join(rules) if rules else None

    @staticmethod
    def _values(ind_type: IndicatorType, iocs: list[IOC]) -> list[str]:
        values: list[str] = []
        for ioc in iocs:
            if ioc.indicator_type != ind_type:
                continue
            if ind_type == IndicatorType.FILE_PATH:
                value = _process_image(ioc.value)
            elif ind_type == IndicatorType.REGISTRY_KEY:
                value = _registry_subkey(ioc.value)
            else:
                value = ioc.value
            if value and value not in values:
                values.append(value)
        return values[:MAX_VALUES_PER_RULE]

    @staticmethod
    def _render(sample_hash: str, template: SigmaTemplate, values: list[str]) -> str:
        rule_id = uuid.uuid5(uuid.NAMESPACE_URL, f"malforge:{sample_hash}:{template.category}")
        date = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
        lines = [
            f"title: Malforge {sample_hash[:8]} - Suspicious {template.title}",
            f"id: {rule_id}",
            "status: experimental",
            f"description: Auto-generated from static analysis of sample {sample_hash}",
            "author: Malforge",
            f"date: {date}",
            "logsource:",
            f"    category: {template.category}",
            "    product: windows",
            "detection:",
            "    selection:",
            f"        {template.field}:",
            *(f"            - {quote(v)}" for v in values),
            "    condition: selection",
            "falsepositives:",
            "    - Unknown",
            "level: medium",
        ]
        return "\n".join(lines) + "\n"
