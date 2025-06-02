from datetime import datetime, timedelta, timezone
from threatcorrelator.correlate import rate_threat

def test_rate_threat_confidence_levels():
    now = datetime.now(timezone.utc).isoformat()
    assert rate_threat(95, 1, now, 0, 0) == "High"
    assert rate_threat(70, 1, now, 0, 0) == "Medium"
    assert rate_threat(30, 1, now, 0, 0) == "Low"

def test_rate_threat_age_filtering():
    old_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    assert rate_threat(90, 1, old_date, 0, 5) == "None"

def test_rate_threat_frequency_escalation():
    now = datetime.now(timezone.utc).isoformat()
    assert rate_threat(70, 10, now, 5, 0) == "Critical"
