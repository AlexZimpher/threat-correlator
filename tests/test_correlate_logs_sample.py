import pytest
from threatcorrelator.correlate import correlate_logs
from pathlib import Path

def test_correlate_logs_sample():
    # Use a sample log file that should exist in the repo
    log_path = Path("sampledata/example_log.jsonl")
    results = correlate_logs(log_path)
    assert isinstance(results, list)
    # If the sample log is set up, there should be at least one result
    assert results
