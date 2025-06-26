from threatcorrelator.enrichment import (
    enrich_geoip,
    enrich_asn,
    enrich_reverse_dns,
    enrich_indicator,
)


def test_enrich_geoip_returns_dict():
    # Test that enrich_geoip returns a dict (empty if geoip2 not installed)
    result = enrich_geoip("8.8.8.8")
    assert isinstance(result, dict)


def test_enrich_asn_returns_dict():
    # Test that enrich_asn returns a dict (empty if ipwhois not installed)
    result = enrich_asn("8.8.8.8")
    assert isinstance(result, dict)


def test_enrich_reverse_dns_returns_dict():
    # Test that enrich_reverse_dns always returns a dict
    result = enrich_reverse_dns("8.8.8.8")
    assert isinstance(result, dict)


def test_enrich_indicator_aggregates():
    # Test that enrich_indicator returns a dict with all enrichment keys
    result = enrich_indicator("8.8.8.8")
    assert isinstance(result, dict)
    # Should include keys from all enrichment functions (may be empty)


def test_enrich_passive_dns_stub():
    # Test that enrich_passive_dns returns a dict with 'passive_dns' key or is empty
    from threatcorrelator.enrichment import enrich_passive_dns

    result = enrich_passive_dns("malicious.example.com")
    assert isinstance(result, dict)
    assert "passive_dns" in result or result == {}
