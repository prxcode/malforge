import yara
from typing import Dict, Any

class RuleValidator:
    def validate_yara(self, rule_text: str) -> Dict[str, Any]:
        """Validate YARA rule syntax by compiling it."""
        try:
            compiler = yara.compile(source=rule_text)
            return {
                "valid": True,
                "error": None,
                "warnings": []
            }
        except yara.SyntaxError as e:
            return {
                "valid": False,
                "error": str(e),
                "warnings": []
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"Unexpected error: {str(e)}",
                "warnings": []
            }

    def validate_sigma(self, rule_text: str) -> Dict[str, Any]:
        """Basic validation for Sigma rule YAML structure."""
        import yaml
        try:
            parsed = yaml.safe_load(rule_text)
            if not isinstance(parsed, dict):
                return {"valid": False, "error": "Root element must be a dictionary"}
            
            required_fields = ["title", "logsource", "detection"]
            missing = [f for f in required_fields if f not in parsed]
            
            if missing:
                return {"valid": False, "error": f"Missing required fields: {', '.join(missing)}"}
                
            return {"valid": True, "error": None}
            
        except yaml.YAMLError as e:
            return {
                "valid": False,
                "error": f"YAML syntax error: {str(e)}"
            }

rule_validator = RuleValidator()
