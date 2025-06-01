from unittest.mock import patch
from threatcorrelator.fetch import fetch_abuseipdb_blacklist

@patch("threatcorrelator.fetch.requests.get")
def test_fetch_abuseipdb_blacklist_parses_data(mock_get):
    mock_response = {
        "data": [
            {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 90,
                "countryCode": "US",
                "lastReportedAt": "2024-12-01T12:00:00Z",
                "usageType": "ISP"
            }
        ]
    }

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = mock_response

    iocs = fetch_abuseipdb_blacklist()

    assert isinstance(iocs, list)
    assert iocs[0]["ip"] == "8.8.8.8"
    assert iocs[0]["confidence"] == 90
    assert iocs[0]["country"] == "US"
    assert iocs[0]["last_seen"] == "2024-12-01T12:00:00Z"
    assert iocs[0]["usage"] == "ISP"
    assert iocs[0]["source"] == "abuseipdb"

