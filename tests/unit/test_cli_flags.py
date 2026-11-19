"""Unit tests for Phase 7 CLI flags (--ai, --no-ai, --ai-provider, --ai-model, --format)."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sentinel.cli.main import cli
from sentinel.core.models import RiskScoreSummary, ScanMetadata
from sentinel.orchestrator.pipeline import ScanExecutionResult


def _mock_scan_result(tmp_path: Path) -> ScanExecutionResult:
    return ScanExecutionResult(
        scan_id="SCAN-CLI-001",
        metadata=ScanMetadata(
            scan_id="SCAN-CLI-001",
            app_path="app.apk",
            app_hash_sha256="abc12345",
            app_name="CliApp",
            package_name="com.example.cliapp",
        ),
        apk_meta=None,
        device_name="emulator-5554",
        risk_summary=RiskScoreSummary(overall_score=85.0, risk_level="LOW"),
    )


def test_cli_ai_enable_flag(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()
    mock_res = _mock_scan_result(tmp_path)

    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_res):
        res = runner.invoke(cli, ["test", str(fake_apk), "--ai", "--output", str(tmp_path / "out")])
        assert res.exit_code == 0
        assert os.environ.get("SENTINEL_AI_ENABLED") == "true"


def test_cli_no_ai_flag(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()
    mock_res = _mock_scan_result(tmp_path)

    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_res):
        res = runner.invoke(cli, ["test", str(fake_apk), "--no-ai", "--output", str(tmp_path / "out")])
        assert res.exit_code == 0
        assert os.environ.get("SENTINEL_AI_ENABLED") == "false"


def test_cli_ai_provider_and_model_flags(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()
    mock_res = _mock_scan_result(tmp_path)

    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_res):
        res = runner.invoke(
            cli,
            ["test", str(fake_apk), "--ai-provider", "ollama", "--ai-model", "llama3.2:1b", "--output", str(tmp_path / "out")]
        )
        assert res.exit_code == 0
        assert os.environ.get("SENTINEL_AI_PROVIDER") == "ollama"
        assert os.environ.get("SENTINEL_AI_MODEL") == "llama3.2:1b"


def test_cli_report_format_text_only(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()
    mock_res = _mock_scan_result(tmp_path)

    out_dir = tmp_path / "text_only_reports"
    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_res):
        res = runner.invoke(cli, ["test", str(fake_apk), "--format", "text", "--output", str(out_dir)])
        assert res.exit_code == 0

        target_dir = out_dir / mock_res.app_dir_name
        assert (target_dir / "report.txt").exists()
        assert not (target_dir / "report.json").exists()


def test_cli_report_format_json_only(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()
    mock_res = _mock_scan_result(tmp_path)

    out_dir = tmp_path / "json_only_reports"
    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_res):
        res = runner.invoke(cli, ["test", str(fake_apk), "--format", "json", "--output", str(out_dir)])
        assert res.exit_code == 0

        target_dir = out_dir / mock_res.app_dir_name
        assert (target_dir / "report.json").exists()
        assert not (target_dir / "report.txt").exists()


def test_cli_report_format_all(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()
    mock_res = _mock_scan_result(tmp_path)

    out_dir = tmp_path / "all_reports"
    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_res):
        res = runner.invoke(cli, ["test", str(fake_apk), "--format", "all", "--output", str(out_dir)])
        assert res.exit_code == 0

        target_dir = out_dir / mock_res.app_dir_name
        assert (target_dir / "report.txt").exists()
        assert (target_dir / "report.json").exists()


def test_cli_invalid_provider_choice(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()

    runner = CliRunner()
    res = runner.invoke(cli, ["test", str(fake_apk), "--ai-provider", "invalid_provider"])
    assert res.exit_code != 0
    assert "Invalid value for '--ai-provider'" in res.output
