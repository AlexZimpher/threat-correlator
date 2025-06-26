from threatcorrelator import mitre_map


def test_mitre_mapping():
    # Test that mapping for SSH returns valid tactic and technique
    tactic, technique = mitre_map.map_usage_to_mitre("SSH")
    assert tactic is not None
    assert technique is not None
