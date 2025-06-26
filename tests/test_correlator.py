from datetime import datetime, timedelta, timezone
from threatcorrelator.correlate import rate_threat


def test_rate_threat_confidence_levels():
    # Test that threat rating is correct for different confidence levels
    now = datetime.now(timezone.utc).isoformat()
    assert rate_threat(95, 1, now, 0, 0) == "High"  # nosec
    assert rate_threat(70, 1, now, 0, 0) == "Medium"  # nosec
    assert rate_threat(30, 1, now, 0, 0) == "Low"  # nosec


def test_rate_threat_age_filtering():
    # Test that old threats are filtered out
    old_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    assert rate_threat(90, 1, old_date, 0, 5) == "None"  # nosec


def test_rate_threat_frequency_escalation():
    # Test that high frequency escalates threat rating
    now = datetime.now(timezone.utc).isoformat()
    assert rate_threat(70, 10, now, 5, 0) == "Critical"  # nosec
