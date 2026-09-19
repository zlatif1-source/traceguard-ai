from pathlib import Path

import pytest

from app.config import Settings
from app.models import AnalyzeRequest
from app.service import SecurityAnalystService

ROOT = Path(__file__).resolve().parents[1]


def make_service(tmp_path: Path) -> SecurityAnalystService:
    settings = Settings(database_path=tmp_path / "test.db", openai_api_key=None)
    return SecurityAnalystService(settings)


def test_demo_analysis_returns_auditable_result(tmp_path: Path) -> None:
    logs = (ROOT / "data" / "sample_logs" / "brute_force.jsonl").read_text()
    response = make_service(tmp_path).analyze(
        AnalyzeRequest(logs=logs, mode="demo", explanation_mode="teach_me")
    )

    assert response.risk_score == 100
    assert response.severity == "critical"
    assert response.citations
    assert response.timeline
    assert "Why that matters" in response.answer
    assert response.metadata["provider"] == "deterministic-demo"


def test_live_mode_requires_api_key(tmp_path: Path) -> None:
    service = make_service(tmp_path)

    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        service.analyze(AnalyzeRequest(logs='{"event_type":"logout"}', mode="live"))
