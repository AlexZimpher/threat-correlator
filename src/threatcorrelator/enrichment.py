
"""
Enrichment utilities for indicators (IP, domain, etc.).
Each function is robust, fails gracefully, and is clearly commented for maintainability.
"""


from typing import Optional, Dict

# GeoIP2 and IPWhois are optional dependencies for enrichment.
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
    """
    Return GeoIP info for an IP address (country, city, lat/lon).
    Returns empty dict if geoip2 is not available or DB path is not provided.
    """
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
    """
    Return ASN info for an IP address (autonomous system number and description).
    Returns empty dict if ipwhois is not available.
    """
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
    """
    Return reverse DNS for an IP address.
    Returns empty dict if lookup fails.
    """
    try:
        host = socket.gethostbyaddr(indicator)[0]
        return {"reverse_dns": host}
    except Exception:
        return {}

def enrich_passive_dns(indicator: str) -> Dict:
    """
    (Stub) Passive DNS enrichment.
    In production, integrate with a real passive DNS API (e.g., SecurityTrails, Farsight).
    For demo, returns a fake result for .example.com domains only.
    """
    result = {}
    if indicator.endswith('.example.com'):
        result["passive_dns"] = [
            {"first_seen": "2025-01-01", "last_seen": "2025-06-01", "resolve": indicator}
        ]
    return result

def enrich_indicator(indicator: str, geoip_db_path: Optional[str] = None) -> Dict:
    """
    Aggregate enrichment for an indicator (IP/domain).
    Returns a merged dict of all enrichment results.
    """
    result = {}
    result.update(enrich_geoip(indicator, geoip_db_path))
    result.update(enrich_asn(indicator))
    result.update(enrich_reverse_dns(indicator))
    result.update(enrich_passive_dns(indicator))
    return result
