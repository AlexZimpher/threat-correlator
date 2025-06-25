import pytest
from threatcorrelator.country_lookup import country_lookup

def test_country_lookup():
    # Should return a country name for a valid ISO code
    assert country_lookup("US") == "United States"
    # Should return None for invalid code
    assert country_lookup("ZZ") is None
