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


def test_php2shell_sample_endpoint_and_dashboard_button() -> None:
    dashboard = client.get("/")
    response = client.get("/api/sample/php2shell")

    assert dashboard.status_code == 200
    assert 'id="load-php2shell"' in dashboard.text
    assert response.status_code == 200
    assert "software_inventory" in response.json()["logs"]
    assert "8.4.26" in response.json()["logs"]
