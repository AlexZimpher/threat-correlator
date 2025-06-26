import pytest
from threatcorrelator.generate_test_log import generate_test_log


def test_generate_test_log_handles_invalid_path(tmp_path):
    # Test that generate_test_log does not raise if given a bad path
    bad_path = tmp_path / "nonexistent" / "file.jsonl"
    try:
        generate_test_log(str(bad_path), ioc_count=1, false_positive_count=1)
    except Exception:
        pytest.fail("generate_test_log should not raise")
