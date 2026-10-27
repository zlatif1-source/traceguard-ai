import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

from app.models import Finding, RiskFactor, TimelineEvent
from app.php_advisories import detect_php2shell_exposures, is_unpatched_php_inventory

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class LogAnalysis:
    events: list[dict]
    findings: list[Finding]
    severity: str
    risk_score: int
    risk_factors: list[RiskFactor]
    timeline: list[TimelineEvent]
    parse_errors: int
    event_types: dict[str, int]


def parse_logs(raw_logs: str) -> tuple[list[dict], int]:
    events: list[dict] = []
    parse_errors = 0

    for line_number, raw_line in enumerate(raw_logs.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("JSON event must be an object")
            event.setdefault("line_number", line_number)
            events.append(event)
            continue
        except (json.JSONDecodeError, ValueError):
            pass

        auth_match = re.search(
            r"(?P<status>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) "
            r"from (?P<source_ip>[0-9a-fA-F:.]+)",
            line,
        )
        if auth_match:
            values = auth_match.groupdict()
            events.append(
                {
                    "line_number": line_number,
                    "event_type": (
                        "failed_login"
                        if values["status"].lower() == "failed"
                        else "successful_login"
                    ),
                    "user": values["user"],
                    "source_ip": values["source_ip"],
                    "message": line,
                }
            )
        else:
            parse_errors += 1

    return events, parse_errors


def analyze_logs(raw_logs: str) -> LogAnalysis:
    events, parse_errors = parse_logs(raw_logs)
    findings: list[Finding] = []
    failed_by_ip: Counter[str] = Counter()
    failed_users_by_ip: dict[str, set[str]] = defaultdict(set)
    successful_ips: set[str] = set()
    event_types: Counter[str] = Counter()
    risk_factors: list[RiskFactor] = []

    for event in events:
        event_type = str(event.get("event_type", "unknown")).lower()
        source_ip = str(event.get("source_ip", "unknown"))
        event_types[event_type] += 1

        if event_type == "failed_login":
            failed_by_ip[source_ip] += 1
            failed_users_by_ip[source_ip].add(str(event.get("user", "unknown")))
        elif event_type == "successful_login":
            successful_ips.add(source_ip)
        elif event_type in {"privilege_change", "admin_role_granted"}:
            findings.append(
                Finding(
                    title="Privileged access changed",
                    evidence=str(event.get("message", "A privilege-change event was recorded.")),
                    severity="high",
                    source_ip=None if source_ip == "unknown" else source_ip,
                    mitre_technique="T1098",
                    mitre_name="Account Manipulation",
                )
            )
            risk_factors.append(RiskFactor(reason="Privileged access changed", points=30))
        elif event_type in {"malware_alert", "endpoint_malware"}:
            findings.append(
                Finding(
                    title="Endpoint malware alert",
                    evidence=str(event.get("message", "An endpoint reported possible malware.")),
                    severity="critical",
                    source_ip=None if source_ip == "unknown" else source_ip,
                    mitre_technique="T1204",
                    mitre_name="User Execution",
                )
            )
            risk_factors.append(RiskFactor(reason="Endpoint malware alert", points=50))
        elif event_type == "network_connection" and int(event.get("bytes_out", 0)) >= 10_000_000:
            findings.append(
                Finding(
                    title="Large outbound transfer",
                    evidence=f"Observed {int(event.get('bytes_out', 0)):,} outbound bytes.",
                    severity="medium",
                    source_ip=None if source_ip == "unknown" else source_ip,
                    mitre_technique="T1048",
                    mitre_name="Exfiltration Over Alternative Protocol",
                )
            )
            risk_factors.append(RiskFactor(reason="Large outbound transfer", points=20))

    php_findings, php_factors = detect_php2shell_exposures(events)
    findings.extend(php_findings)
    risk_factors.extend(php_factors)

    for source_ip, count in failed_by_ip.items():
        if count >= 5:
            severity = "critical" if count >= 20 else "high"
            user_count = len(failed_users_by_ip[source_ip])
            findings.append(
                Finding(
                    title="Possible brute-force authentication attack",
                    evidence=(
                        f"{count} failed logins from {source_ip} targeted {user_count} account(s)."
                    ),
                    severity=severity,
                    source_ip=source_ip,
                    count=count,
                    mitre_technique="T1110",
                    mitre_name="Brute Force",
                )
            )
            brute_force_points = min(30, count * 2)
            risk_factors.append(
                RiskFactor(
                    reason=f"Repeated authentication failures ({count} events)",
                    points=brute_force_points,
                )
            )
            if source_ip in successful_ips:
                findings.append(
                    Finding(
                        title="Login succeeded after repeated failures",
                        evidence=(
                            f"{source_ip} produced both repeated failures and a successful login; "
                            "the account may be compromised."
                        ),
                        severity="critical",
                        source_ip=source_ip,
                        mitre_technique="T1078",
                        mitre_name="Valid Accounts",
                    )
                )
                risk_factors.append(
                    RiskFactor(reason="Successful login after repeated failures", points=40)
                )

    if not findings:
        findings.append(
            Finding(
                title="No high-confidence threat pattern detected",
                evidence=f"Parsed {len(events)} event(s) without matching a detection threshold.",
                severity="info",
            )
        )

    severity = max(findings, key=lambda item: SEVERITY_RANK[item.severity]).severity
    risk_score = min(100, sum(factor.points for factor in risk_factors))
    if not risk_factors:
        risk_factors.append(RiskFactor(reason="No threshold-based detection matched", points=5))
        risk_score = 5

    timeline = []
    for order, event in enumerate(events[:25], start=1):
        event_type = str(event.get("event_type", "unknown")).lower()
        suspicious = event_type in {
            "failed_login",
            "privilege_change",
            "admin_role_granted",
            "malware_alert",
            "endpoint_malware",
        } or is_unpatched_php_inventory(event)
        timeline.append(
            TimelineEvent(
                order=order,
                timestamp=str(event.get("timestamp", f"line {event.get('line_number', order)}")),
                label=event_type.replace("_", " ").title(),
                detail=str(
                    event.get(
                        "message",
                        f"user={event.get('user', 'n/a')} source={event.get('source_ip', 'n/a')}",
                    )
                ),
                suspicious=suspicious,
            )
        )

    return LogAnalysis(
        events=events,
        findings=findings,
        severity=severity,
        risk_score=risk_score,
        risk_factors=risk_factors,
        timeline=timeline,
        parse_errors=parse_errors,
        event_types=dict(event_types),
    )


def parse_timestamp(value: str) -> datetime | None:
    """Parse an ISO timestamp for future time-window detections."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
