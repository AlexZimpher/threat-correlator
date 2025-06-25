"""
Enrichment utilities for indicators (IP, domain, etc.):
- GeoIP (country, city)
- ASN lookup
- Reverse DNS
- Passive DNS (stub)
"""
import os
from typing import Optional, Dict

try:
    import geoip2.database
except ImportError:
    geoip2 = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

import socket


def enrich_geoip(indicator: str, geoip_db_path: Optional[str] = None) -> Dict:
    """Return GeoIP info for an IP address (country, city)."""
    if geoip2 is None or geoip_db_path is None:
        return {}
    try:
        reader = geoip2.database.Reader(geoip_db_path)
        response = reader.city(indicator)
        return {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
    except Exception:
        return {}

def enrich_asn(indicator: str) -> Dict:
    """Return ASN info for an IP address."""
    if IPWhois is None:
        return {}
    try:
        obj = IPWhois(indicator)
        res = obj.lookup_rdap()
        return {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
        }
    except Exception:
        return {}

def enrich_reverse_dns(indicator: str) -> Dict:
    """Return reverse DNS for an IP address."""
    try:
        host = socket.gethostbyaddr(indicator)[0]
        return {"reverse_dns": host}
    except Exception:
        return {}

def enrich_passive_dns(indicator: str) -> Dict:
    """Stub for passive DNS enrichment."""
    # In production, integrate with a real passive DNS API
    result = {}
    # Passive DNS enrichment (stub, can be replaced with real API)
    # Example: use SecurityTrails, Farsight, or open API if available
    # For now, just return a fake result for demonstration
    if indicator.endswith('.example.com'):
        result["passive_dns"] = [
            {"first_seen": "2025-01-01", "last_seen": "2025-06-01", "resolve": indicator}
        ]
    return result

def enrich_indicator(indicator: str, geoip_db_path: Optional[str] = None) -> Dict:
    """Aggregate enrichment for an indicator."""
    result = {}
    result.update(enrich_geoip(indicator, geoip_db_path))
    result.update(enrich_asn(indicator))
    result.update(enrich_reverse_dns(indicator))
    result.update(enrich_passive_dns(indicator))
    return result
