import pytest
from threatcorrelator import enrichment

def test_country_lookup():
    # Should return a country name for a valid ISO code
    assert enrichment.country_lookup("US") == "United States"
    # Should return None or fallback for invalid code
    assert enrichment.country_lookup("ZZ") is None or enrichment.country_lookup("ZZ") == "Unknown"
