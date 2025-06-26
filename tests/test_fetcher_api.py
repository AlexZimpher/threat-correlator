from threatcorrelator import fetch


def test_fetch_abuseipdb_blacklist(mocker):
    # Test that fetch_abuseipdb_blacklist returns parsed IOC dicts from API
    mocker.patch(
        "requests.get",
        return_value=mocker.Mock(
            status_code=200,
            json=lambda: {
                "data": [
                    {
                        "ipAddress": "1.2.3.4",
                        "abuseConfidenceScore": 99,
                        "countryCode": "US",
                        "lastReportedAt": "2025-06-01",
                        "usageType": "ISP",
                    }
                ]
            },
        ),
    )
    iocs = fetch.fetch_abuseipdb_blacklist(api_key="dummy")
    assert iocs
    assert iocs[0]["indicator"] == "1.2.3.4"
    assert iocs[0]["confidence"] == 99
    assert iocs[0]["country"] == "US"
