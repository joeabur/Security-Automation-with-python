from pathlib import Path

from soc_automation.log_parser import LogParser


def test_extract_ips_from_line():
    parser = LogParser()
    result = parser.extract_ips_from_line("Failed login from 203.0.113.10 and 198.51.100.25")
    assert result == ["203.0.113.10", "198.51.100.25"]


def test_parse_file_extracts_ips():
    parser = LogParser()
    sample_path = Path("sample_data/logs/suspicious_ips.log")
    result = parser.parse_file(sample_path)
    assert "198.51.100.25" in result
    assert "203.0.113.12" in result
    assert "8.8.8.8" in result
    assert "999.999.999.999" not in result
