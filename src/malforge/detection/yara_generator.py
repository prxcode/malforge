import datetime

from malforge.ioc.extractor import IOC, IndicatorType

MAX_IOC_STRINGS = 10

IOC_PREFIXES = {
    IndicatorType.URL: "url",
    IndicatorType.DOMAIN: "dom",
    IndicatorType.IPV4: "ip",
}


def escape_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


class YaraGenerator:
    """Generates a YARA rule from suspicious imports and network IOCs."""

    def generate(
        self,
        sample_hash: str,
        suspicious_apis: list[str],
        iocs: list[IOC] | None = None,
    ) -> str | None:
        """Return the rule source, or None when there is nothing specific to match on."""
        api_strings = [
            f'$api{i} = "{escape_yara_string(api)}" ascii wide nocase'
            for i, api in enumerate(suspicious_apis)
        ]
        network_iocs = [ioc for ioc in iocs or [] if ioc.indicator_type in IOC_PREFIXES]
        ioc_strings = [
            f'$ioc_{IOC_PREFIXES[ioc.indicator_type]}{i} = "{escape_yara_string(ioc.value)}" ascii wide'
            for i, ioc in enumerate(network_iocs[:MAX_IOC_STRINGS])
        ]

        if not api_strings and not ioc_strings:
            return None

        conditions = ["uint16(0) == 0x5a4d"]
        if api_strings:
            conditions.append("3 of ($api*)" if len(api_strings) > 3 else "all of ($api*)")
        if ioc_strings:
            conditions.append("2 of ($ioc_*)" if len(ioc_strings) > 3 else "any of ($ioc_*)")

        meta = {
            "author": "Malforge",
            "description": "Auto-generated from static analysis",
            "date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d"),
            "hash": sample_hash,
            "tlp": "CLEAR",
        }

        lines = [f"rule Malforge_{sample_hash[:8]} {{", "    meta:"]
        lines += [f'        {key} = "{escape_yara_string(value)}"' for key, value in meta.items()]
        lines += ["", "    strings:"]
        lines += [f"        {s}" for s in api_strings + ioc_strings]
        lines += ["", "    condition:", f"        {conditions[0]}"]
        lines += [f"        and {c}" for c in conditions[1:]]
        lines.append("}")
        return "\n".join(lines) + "\n"
