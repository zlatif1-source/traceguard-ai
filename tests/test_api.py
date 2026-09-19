from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_and_health_are_available() -> None:
    dashboard = client.get("/")
    health = client.get("/api/health")

    assert dashboard.status_code == 200
    assert "TraceGuard AI" in dashboard.text
    assert health.status_code == 200
    assert health.json()["status"] == "ok"


def test_analyze_endpoint_returns_explainable_result() -> None:
    response = client.post(
        "/api/analyze",
        json={
            "question": "What happened and why?",
            "logs": (
                '{"event_type":"malware_alert","source_ip":"10.0.0.5",'
                '"message":"EDR detected malware"}'
            ),
            "mode": "demo",
            "explanation_mode": "teach_me",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["severity"] == "critical"
    assert body["risk_score"] == 50
    assert body["findings"][0]["mitre_technique"] == "T1204"
