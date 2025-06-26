import tempfile
from pathlib import Path
from datetime import datetime, UTC
from threatcorrelator.correlate import correlate_logs
from threatcorrelator.storage import IOC, get_session


def test_extract_indicators_from_windows_xml():
    # Test that indicators are extracted from a sample Windows Event XML
    xml_content = """<?xml version="1.0"?>
    <Events>
      <Event>
        <System><Provider Name="Microsoft-Windows-Security-Auditing"/></System>
        <EventData>
          <Data Name="IpAddress">10.1.2.3</Data>
          <Data Name="Domain">malicious.example.com</Data>
        </EventData>
      </Event>
    </Events>"""
    with tempfile.NamedTemporaryFile("w+", suffix=".xml", delete=False) as tmp_xml:
        tmp_xml.write(xml_content)
        tmp_xml_path = Path(tmp_xml.name)

    session = get_session("sqlite:///:memory:")
    # Add matching IOCs to the database
    session.add(
        IOC(
            indicator="10.1.2.3",
            type="ip",
            confidence=90,
            country="US",
            last_seen=datetime.now(UTC),
            usage="test",
            source="unit_test",
        )
    )
    session.add(
        IOC(
            indicator="malicious.example.com",
            type="domain",
            confidence=80,
            country="US",
            last_seen=datetime.now(UTC),
            usage="test",
            source="unit_test",
        )
    )
    session.commit()

    # Run correlation and check that both indicators are found
    results = correlate_logs(tmp_xml_path, session=session)
    indicators = {r["indicator"] for r in results}
    assert "10.1.2.3" in indicators
    assert "malicious.example.com" in indicators
