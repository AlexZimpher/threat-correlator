# src/threatcorrelator/mitre_map.py

"""
MITRE ATT&CK mappings for IOC usage/behavior → technique ID and name.
"""
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

