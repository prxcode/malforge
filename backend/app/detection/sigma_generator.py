from typing import Dict, Any

class SigmaGenerator:
    def __init__(self):
        pass

    def generate_from_analysis(self, sample_id: str, strings_data: Dict[str, Any]) -> str:
        """Programmatically generate a basic Sigma rule based on artifacts."""
        
        title = f"Auto Generated Sigma Rule {sample_id[:8]}"
        
        yaml = [
            f"title: {title}",
            f"id: {sample_id}",
            "status: experimental",
            "description: Auto-generated Sigma rule from static analysis strings",
            "author: MAP Auto-Generator",
            "logsource:",
            "    category: process_creation",
            "    product: windows",
            "detection:",
            "    selection:"
        ]
        
        has_artifacts = False
        
        # Add IPs if found
        if "ips" in strings_data and strings_data["ips"]:
            yaml.append("        DestinationIp:")
            for ip in strings_data["ips"][:5]:
                yaml.append(f"            - '{ip}'")
            has_artifacts = True
            
        if not has_artifacts:
            # Add a generic condition if nothing specific is found
            yaml.append("        CommandLine|contains: 'suspicious_command'")
            
        yaml.append("    condition: selection")
        
        return "\n".join(yaml)

sigma_generator = SigmaGenerator()
