# src/threatcorrelator/mitre_map.py

"""
MITRE ATT&CK mappings for IOC usage/behavior → technique ID and name.
"""
# Comprehensive MITRE ATT&CK mapping
MITRE_MAPPING = {
    # Network protocols and services
    "SSH": ("T1110", "Brute Force"),
    "RDP": ("T1021", "Remote Services"),
    "VPN": ("T1133", "External Remote Services"),
    "FTP": ("T1567", "Exfiltration Over Web Service"),
    "SMTP": ("T1071", "Application Layer Protocol"),
    "HTTP": ("T1041", "Exfiltration Over C2 Channel"),
    "HTTPS": ("T1041", "Exfiltration Over C2 Channel"),
    "DNS": ("T1071", "Application Layer Protocol"),
    "SMB": ("T1021", "Remote Services"),
    "Telnet": ("T1021", "Remote Services"),
    "SNMP": ("T1040", "Network Sniffing"),
    # Attack types
    "Botnet": ("T1584", "Compromise Infrastructure"),
    "Phishing": ("T1566", "Phishing"),
    "Malware": ("T1059", "Command and Scripting Interpreter"),
    "C2": ("T1105", "Ingress Tool Transfer"),
    "Brute Force": ("T1110", "Brute Force"),
    "Exploit": ("T1190", "Exploit Public-Facing Application"),
    "Recon": ("T1595", "Active Scanning"),
    "Credential Access": ("T1003", "OS Credential Dumping"),
    "Persistence": ("T1547", "Boot or Logon Autostart Execution"),
    "Privilege Escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "Lateral Movement": ("T1021", "Remote Services"),
    "Exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "Data Staged": ("T1074", "Data Staged"),
    # Common domains/indicators
    "malicious.com": ("T1071", "Application Layer Protocol"),
    "badsite.example.net": ("T1190", "Exploit Public-Facing Application"),
    # File/host-based
    "Powershell": ("T1059.001", "PowerShell"),
    "WMI": ("T1047", "Windows Management Instrumentation"),
    "Registry": ("T1112", "Modify Registry"),
    "Scheduled Task": ("T1053", "Scheduled Task/Job"),
    # Cloud/infra
    "AWS": ("T1078", "Valid Accounts"),
    "Azure": ("T1078", "Valid Accounts"),
    "GCP": ("T1078", "Valid Accounts"),
    # Misc
    "Scan": ("T1595", "Active Scanning"),
    "Spam": ("T1566", "Phishing"),
    "SQL Injection": ("T1190", "Exploit Public-Facing Application"),
    "XSS": ("T1059", "Command and Scripting Interpreter"),
    "CVE": ("T1203", "Exploitation for Client Execution"),
    # Default fallback
    "__default__": ("T1566", "Phishing"),
}

from typing import Optional

def dynamic_mitre_mapping(indicator: str, usage: Optional[str] = None, context: Optional[dict] = None):
    """
    Dynamically map an indicator to a MITRE ATT&CK technique based on usage or context.
    """
    # Use usage type if available
    if usage and usage in MITRE_MAPPING:
        return MITRE_MAPPING[usage]
    # Use domain-based mapping
    if indicator in MITRE_MAPPING:
        return MITRE_MAPPING[indicator]
    # Try to match by keyword in usage
    if usage:
        for key in MITRE_MAPPING:
            if key != "__default__" and key.lower() in usage.lower():
                return MITRE_MAPPING[key]
    # Try to match by keyword in indicator
    if indicator:
        for key in MITRE_MAPPING:
            if key != "__default__" and key.lower() in indicator.lower():
                return MITRE_MAPPING[key]
    # Use context (stub)
    return MITRE_MAPPING["__default__"]

def map_usage_to_mitre(usage: str):
    """Return MITRE tactic and technique for a given usage string."""
    return MITRE_MAPPING.get(usage, MITRE_MAPPING["__default__"])

