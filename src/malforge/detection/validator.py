import logging
from dataclasses import dataclass, field
from typing import Any

import yara

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a detection rule."""

    is_valid: bool = False
    true_positive: bool = False
    error: str | None = None
    matches: list[dict[str, Any]] = field(default_factory=list)


class DetectionValidator:
    """Validates and tests detection rules."""

    def validate_yara(self, rule_text: str, test_file_data: bytes) -> ValidationResult:
        """
        Compile the YARA rule and run it against the provided file data.
        Returns validation metrics.
        """
        result = ValidationResult()

        try:
            # Test 1: Syntax compilation
            compiled_rule = yara.compile(source=rule_text)
            result.is_valid = True

            # Test 2: True positive against the generating sample
            matches = compiled_rule.match(data=test_file_data)

            if matches:
                result.true_positive = True
                for match in matches:
                    match_info: dict[str, Any] = {"rule": match.rule, "strings": []}
                    for s in match.strings:
                        match_info["strings"].append(
                            {
                                "offset": s[0],
                                "identifier": s[1],
                                "data": s[2][:20],
                            }
                        )
                    result.matches.append(match_info)

        except yara.SyntaxError as e:
            result.error = f"Syntax error: {e!s}"
            logger.error("YARA compilation failed: %s", e)
        except Exception as e:
            result.error = f"Validation error: {e!s}"
            logger.error("YARA validation failed: %s", e)

        return result
