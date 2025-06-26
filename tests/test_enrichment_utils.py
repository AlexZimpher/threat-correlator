from threatcorrelator.country_lookup import country_lookup


def test_country_lookup():
    # Test that a valid ISO code returns a country name
    assert country_lookup("US") == "United States"
    # Test that an invalid code returns None
    assert country_lookup("ZZ") is None
