# src/threatcorrelator/mitre_map.py

"""
MITRE ATT&CK mappings for IOC usage/behavior → technique ID and name.
"""
# Static MITRE ATT&CK mapping
MITRE_MAPPING = {
    # Example: Usage types from AbuseIPDB or context hints
    "SSH": ("T1110", "Brute Force"),
    "RDP": ("T1021", "Remote Services"),
    "VPN": ("T1133", "External Remote Services"),
    "Botnet": ("T1584", "Compromise Infrastructure"),
    # Example domain‐based categories
    "malicious.com": ("T1071", "Application Layer Protocol"),  # generic web‐based C2
    "badsite.example.net": ("T1190", "Exploit Public‐Facing Application"),
    # Default fallback
    "__default__": ("T1566", "Phishing"),
}

# Dynamic MITRE ATT&CK mapping logic
from typing import Optional

def dynamic_mitre_mapping(indicator: str, usage: Optional[str] = None, context: Optional[dict] = None):
    """
    Dynamically map an indicator to a MITRE ATT&CK technique based on usage or context.
    """
    # Example: Use usage type if available
    if usage and usage in MITRE_MAPPING:
        return MITRE_MAPPING[usage]
    # Example: Use domain-based mapping
    if indicator in MITRE_MAPPING:
        return MITRE_MAPPING[indicator]
    # Example: Use context (stub)
    # In production, expand with more logic
    return MITRE_MAPPING["__default__"]

def map_usage_to_mitre(usage: str):
    """Return MITRE tactic and technique for a given usage string."""
    return MITRE_MAPPING.get(usage, MITRE_MAPPING["__default__"])

