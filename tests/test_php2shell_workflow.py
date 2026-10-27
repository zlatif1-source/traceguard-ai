from pathlib import Path

from app.config import Settings
from app.log_analyzer import analyze_logs
from app.models import AnalyzeRequest
from app.service import SecurityAnalystService

ROOT = Path(__file__).resolve().parents[1]


def test_php2shell_sample_detects_inventory_exposure(tmp_path: Path) -> None:
    logs = (ROOT / "data" / "sample_logs" / "php2shell.jsonl").read_text()
    analysis = analyze_logs(logs)

    assert analysis.severity == "critical"
    assert analysis.risk_score == 60
    assert any("PHP2Shell" in item.title for item in analysis.findings)
    assert any("8.4.27" in item.evidence for item in analysis.findings)
    assert analysis.timeline[0].suspicious

    service = SecurityAnalystService(
        Settings(database_path=tmp_path / "php-test.db", openai_api_key=None)
    )
    response = service.analyze(AnalyzeRequest(logs=logs, mode="demo"))
    assert response.recommended_actions[0].startswith("Patch the affected PHP runtime")
    assert any("PHP2Shell" in item.title for item in response.citations)


def test_patched_php_inventory_is_not_reported_as_exploited() -> None:
    logs = (
        '{"event_type":"software_inventory","product":"PHP","version":"8.4.27",'
        '"hostname":"demo-web-01","internet_facing":true}'
    )
    analysis = analyze_logs(logs)
    assert analysis.severity == "info"
    assert analysis.risk_score == 5
    assert not any("PHP2Shell" in item.title for item in analysis.findings)
