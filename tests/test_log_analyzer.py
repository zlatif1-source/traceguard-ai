from pathlib import Path

from app.log_analyzer import analyze_logs, parse_logs

ROOT = Path(__file__).resolve().parents[1]


def test_detects_attack_chain_and_mitre_mapping() -> None:
    logs = (ROOT / "data" / "sample_logs" / "brute_force.jsonl").read_text()
    result = analyze_logs(logs)

    assert result.severity == "critical"
    assert result.risk_score == 100
    assert len(result.events) == 9
    assert any(finding.mitre_technique == "T1110" for finding in result.findings)
    assert any(finding.mitre_technique == "T1078" for finding in result.findings)
    assert any(finding.mitre_technique == "T1098" for finding in result.findings)
    assert any(finding.mitre_technique == "T1048" for finding in result.findings)


def test_normal_activity_stays_low_risk() -> None:
    logs = (ROOT / "data" / "sample_logs" / "normal_activity.jsonl").read_text()
    result = analyze_logs(logs)

    assert result.severity == "info"
    assert result.risk_score == 5
    assert result.findings[0].title.startswith("No high-confidence")


def test_parses_common_ssh_logs() -> None:
    raw_logs = "\n".join(
        [
            "Sep 18 12:00:00 host sshd[1]: Failed password for admin from 192.0.2.8 port 22 ssh2",
            "Sep 18 12:00:02 host sshd[2]: Accepted password for admin from 192.0.2.8 port 22 ssh2",
        ]
    )
    events, errors = parse_logs(raw_logs)

    assert errors == 0
    assert [event["event_type"] for event in events] == ["failed_login", "successful_login"]
