import tempfile
import json
from pathlib import Path
from datetime import datetime, UTC
from threatcorrelator.correlate import correlate_logs
from threatcorrelator.storage import IOC, get_session


def test_correlate_logs_detects_known_threat():
    # Test that a log entry matching a known IOC is detected

    # Create a temporary log file with a malicious IP
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tmp_log:
        log_entry = {"src_ip": "1.2.3.4", "event_type": "alert"}
        tmp_log.write(json.dumps(log_entry) + "\n")
        tmp_log_path = Path(tmp_log.name)

    # Use an in-memory SQLite database for isolation
    session = get_session("sqlite:///:memory:")

    # Add a matching IOC to the database
    session.add(
        IOC(
            indicator="1.2.3.4",
            type="ip",
            confidence=85,
            country="US",
            last_seen=datetime.now(UTC),
            usage="test",
            source="unit_test",
        )
    )
    session.commit()

    # Run correlation and check that the threat is detected
    results = correlate_logs(tmp_log_path, session=session)
    assert len(results) == 1  # nosec
    assert results[0]["indicator"] == "1.2.3.4"  # nosec
    assert results[0]["severity"] == "High"  # nosec
