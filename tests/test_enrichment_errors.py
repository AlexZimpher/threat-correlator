import pytest
from threatcorrelator.enrichment import enrich_geoip, enrich_asn, enrich_reverse_dns

def test_enrich_geoip_handles_error(monkeypatch):
    # Patch geoip2.database.Reader to raise
    import threatcorrelator.enrichment as enrichment_mod
    class FakeReader:
        def city(self, ip):
            raise Exception("fail")
    class FakeDatabase:
        @staticmethod
        def Reader(path):
            return FakeReader()
    monkeypatch.setattr(enrichment_mod, "geoip2", type("geoip2", (), {"database": FakeDatabase})())
    result = enrich_geoip("8.8.8.8", geoip_db_path="fake")
    assert result == {}

def test_enrich_asn_handles_error(monkeypatch):
    import threatcorrelator.enrichment as enrichment_mod
    class FakeWhois:
        def lookup_rdap(self):
            raise Exception("fail")
    monkeypatch.setattr(enrichment_mod, "IPWhois", lambda ip: FakeWhois())
    result = enrich_asn("8.8.8.8")
    assert result == {}

def test_enrich_reverse_dns_handles_error(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(Exception("fail")))
    result = enrich_reverse_dns("8.8.8.8")
    assert result == {}
