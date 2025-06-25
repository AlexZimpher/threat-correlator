import pytest
from threatcorrelator import mitre_map

def test_mitre_mapping():
    # Example: test mapping for SSH brute force
    tactic, technique = mitre_map.map_usage_to_mitre("SSH")
    assert tactic is not None
    assert technique is not None
