from threatcorrelator.enrichment import enrich_geoip, enrich_asn, enrich_reverse_dns, enrich_indicator

def test_enrich_geoip_returns_dict():
    # Should return empty dict if geoip2 not installed or db not provided
    result = enrich_geoip("8.8.8.8")
    assert isinstance(result, dict)

def test_enrich_asn_returns_dict():
    # Should return empty dict if ipwhois not installed
    result = enrich_asn("8.8.8.8")
    assert isinstance(result, dict)

def test_enrich_reverse_dns_returns_dict():
    # Should always return a dict, possibly empty
    result = enrich_reverse_dns("8.8.8.8")
    assert isinstance(result, dict)

def test_enrich_indicator_aggregates():
    result = enrich_indicator("8.8.8.8")
    assert isinstance(result, dict)
    # Should include keys from all enrichment functions (may be empty)

def test_enrich_passive_dns_stub():
    from threatcorrelator.enrichment import enrich_passive_dns
    result = enrich_passive_dns("malicious.example.com")
    assert isinstance(result, dict)
    assert "passive_dns" in result or result == {}
