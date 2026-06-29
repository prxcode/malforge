# MAP — Detection Validator
# Validates generated YARA rules by compiling them and running them against the sample.

from typing import Any

import structlog
import yara

logger = structlog.get_logger()


class DetectionValidator:
    """Validates and tests detection rules."""

    def validate_yara(self, rule_text: str, test_file_data: bytes) -> dict[str, Any]:
        """
        Compile the YARA rule and run it against the provided file data.
        Returns validation metrics.
        """
        result = {"is_valid": False, "true_positive": False, "error": None, "matches": []}

        try:
            # Test 1: Syntax compilation
            compiled_rule = yara.compile(source=rule_text)
            result["is_valid"] = True

            # Test 2: True positive against the generating sample
            matches = compiled_rule.match(data=test_file_data)

            if matches:
                result["true_positive"] = True
                for match in matches:
                    result["matches"].append(
                        {
                            "rule": match.rule,
                            "strings": [
                                (s[0], s[1], s[2][:20]) for s in match.strings
                            ],  # offset, string_id, partial_data
                        }
                    )

        except yara.SyntaxError as e:
            result["error"] = f"Syntax error: {e!s}"
            logger.error("YARA compilation failed", error=str(e))
        except Exception as e:
            result["error"] = f"Validation error: {e!s}"
            logger.error("YARA validation failed", error=str(e))

        return result
