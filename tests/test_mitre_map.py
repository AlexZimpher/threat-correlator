from threatcorrelator.mitre_map import dynamic_mitre_mapping


def test_dynamic_mitre_mapping_usage():
    # Test that usage 'SSH' maps to correct MITRE technique
    tid, tname = dynamic_mitre_mapping("1.2.3.4", usage="SSH")
    assert tid == "T1110"
    assert tname == "Brute Force"


def test_dynamic_mitre_mapping_indicator():
    # Test that a domain maps to correct MITRE technique
    tid, tname = dynamic_mitre_mapping("malicious.com")
    assert tid == "T1071"
    assert tname == "Application Layer Protocol"


def test_dynamic_mitre_mapping_default():
    # Test that unknown indicator maps to default MITRE technique
    tid, tname = dynamic_mitre_mapping("unknown.example")
    assert tid == "T1566"
    assert tname == "Phishing"
