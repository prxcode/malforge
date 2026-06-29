from typing import Dict, Any, List

class YaraGenerator:
    def __init__(self):
        pass

    def generate_from_analysis(self, sample_id: str, pe_data: Dict[str, Any], strings_data: Dict[str, Any]) -> str:
        """Programmatically generate a YARA rule based on static analysis artifacts."""
        
        rule_name = f"Auto_Generated_Rule_{sample_id.replace('-', '_')}"
        
        # Build metadata
        meta = [
            f'        author = "MAP Auto-Generator"',
            f'        description = "Auto-generated rule for sample {sample_id}"',
            f'        date = "{self._current_date()}"'
        ]
        
        # Build strings
        strings_section = []
        condition_section = ["        all of them"]
        
        count = 0
        if "urls" in strings_data:
            for url in strings_data["urls"][:3]:  # Top 3 URLs
                strings_section.append(f'        $s{count} = "{self._escape_yara(url)}" ascii wide')
                count += 1
                
        if "registry" in strings_data:
            for reg in strings_data["registry"][:3]:  # Top 3 registry keys
                strings_section.append(f'        $s{count} = "{self._escape_yara(reg)}" ascii wide')
                count += 1
                
        # If no strings found, add a dummy to make valid YARA
        if not strings_section:
            strings_section.append('        $dummy = "DUMMY_STRING" ascii')
            condition_section = ["        $dummy"]
            
        rule = (
            f"rule {rule_name} {{\n"
            f"    meta:\n"
            f"{chr(10).join(meta)}\n"
            f"    strings:\n"
            f"{chr(10).join(strings_section)}\n"
            f"    condition:\n"
            f"{chr(10).join(condition_section)}\n"
            f"}}"
        )
        return rule
        
    def _current_date(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
        
    def _escape_yara(self, value: str) -> str:
        # Basic escaping for YARA string definition
        return value.replace('"', '\\"').replace('\\', '\\\\')

yara_generator = YaraGenerator()
