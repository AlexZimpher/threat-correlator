from threatcorrelator.correlate import rate_threat

def test_rate_threat():
    thresholds = {"high": 80, "medium": 50}

    assert rate_threat(90, thresholds) == "High"
    assert rate_threat(75, thresholds) == "Medium"
    assert rate_threat(40, thresholds) == "Low"

