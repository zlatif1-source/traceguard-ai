import json
from pathlib import Path

from app.log_analyzer import analyze_logs

DATASET = Path(__file__).with_name("dataset.json")


def run() -> int:
    cases = json.loads(DATASET.read_text(encoding="utf-8"))
    passed = 0

    print("TraceGuard deterministic detection evaluation")
    print("=" * 50)
    for case in cases:
        raw_logs = "\n".join(json.dumps(event) for event in case["logs"])
        result = analyze_logs(raw_logs)
        techniques = {
            finding.mitre_technique
            for finding in result.findings
            if finding.mitre_technique is not None
        }
        severity_ok = result.severity == case["expected_severity"]
        techniques_ok = set(case["expected_techniques"]).issubset(techniques)
        case_passed = severity_ok and techniques_ok
        passed += int(case_passed)
        print(
            f"{'PASS' if case_passed else 'FAIL':4}  {case['name']:<26} "
            f"severity={result.severity:<8} risk={result.risk_score:>3}"
        )

    accuracy = passed / len(cases)
    print("-" * 50)
    print(f"Accuracy: {passed}/{len(cases)} = {accuracy:.0%}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(run())
