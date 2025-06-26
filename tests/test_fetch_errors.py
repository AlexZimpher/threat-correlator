from threatcorrelator.fetch import fetch_abuseipdb_blacklist, fetch_otx_feed


def test_fetch_abuseipdb_blacklist_handles_error(monkeypatch):
    # Test that fetch_abuseipdb_blacklist returns [] if requests.get fails
    def mock_get(*a, **k):
        raise Exception("fail")

    import threatcorrelator.fetch as fetch_mod

    monkeypatch.setattr(fetch_mod.requests, "get", mock_get)
    result = fetch_abuseipdb_blacklist()
    assert result == []


def test_fetch_otx_feed_handles_error(monkeypatch):
    # Test that fetch_otx_feed returns [] if OTXv2.getsince fails
    import threatcorrelator.fetch as fetch_mod

    monkeypatch.setattr(
        fetch_mod.OTXv2,
        "getsince",
        lambda self, since: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(fetch_mod, "OTXv2", lambda key: fetch_mod.OTXv2)
    result = fetch_otx_feed()
    assert result == []
