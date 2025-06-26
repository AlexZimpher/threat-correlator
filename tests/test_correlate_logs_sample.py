from threatcorrelator.correlate import correlate_logs
from pathlib import Path


def test_correlate_logs_sample():
    # Test that sample log file is correlated and returns results
    log_path = Path("sampledata/example_log.jsonl")
    results = correlate_logs(log_path)
    assert isinstance(results, list)  # nosec
    # There should be at least one result if the sample log is set up
    assert results  # nosec
