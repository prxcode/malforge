import logging
from dataclasses import dataclass, field
from typing import Any

import yara

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Outcome of compiling a YARA rule and running it against its source sample."""

    is_valid: bool = False
    true_positive: bool = False
    error: str | None = None
    matches: list[dict[str, Any]] = field(default_factory=list)


class DetectionValidator:
    def validate_yara(self, rule_text: str, sample_data: bytes) -> ValidationResult:
        result = ValidationResult()

        try:
            rules = yara.compile(source=rule_text)
        except yara.Error as e:
            result.error = f"Compilation failed: {e}"
            logger.error("YARA compilation failed: %s", e)
            return result
        result.is_valid = True

        try:
            matches = rules.match(data=sample_data)
        except yara.Error as e:
            result.error = f"Matching failed: {e}"
            logger.error("YARA matching failed: %s", e)
            return result

        result.true_positive = bool(matches)
        for match in matches:
            result.matches.append(
                {
                    "rule": match.rule,
                    "strings": [
                        {
                            "identifier": s.identifier,
                            "offset": s.instances[0].offset,
                            "data": s.instances[0].matched_data[:32].hex(),
                        }
                        for s in match.strings
                        if s.instances
                    ],
                }
            )
        return result
