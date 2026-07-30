from soc_automation.pipeline import IOCPipeline


def test_pipeline_runs_for_sample_log(tmp_path):
    pipeline = IOCPipeline("sample_data/logs/suspicious_ips.log", tmp_path)
    results = pipeline.run()

    assert isinstance(results, list)
    assert len(results) >= 1
    assert any(item["ip"] == "198.51.100.25" for item in results)
