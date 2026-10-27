from app.php_advisories import (
    classify_php_version,
    detect_php2shell_exposures,
    is_unpatched_php_inventory,
)


def test_php2shell_fixed_release_boundaries() -> None:
    for old, fixed in (
        ("8.2.34", "8.2.35"),
        ("8.3.35", "8.3.36"),
        ("8.4.26", "8.4.27"),
        ("8.5.11", "8.5.12"),
    ):
        assert classify_php_version(old) == ("vulnerable", fixed)
        assert classify_php_version(fixed) == ("fixed", fixed)


def test_php2shell_legacy_and_unknown_versions() -> None:
    assert classify_php_version("8.1.34") == ("unsupported", None)
    assert classify_php_version("7.4.33") == ("unsupported", None)
    assert classify_php_version("8.6.0-RC4") == ("unknown", None)
    assert classify_php_version("8.4.26 some text") == ("unknown", None)


def test_internet_facing_vulnerable_php_is_critical_but_not_proof_of_attack() -> None:
    event = {
        "event_type": "software_inventory",
        "product": "PHP",
        "version": "8.4.26",
        "hostname": "web-1",
        "internet_facing": True,
    }
    findings, factors = detect_php2shell_exposures([event, event])
    assert len(findings) == 1  # repeated inventory must not multiply the score
    assert findings[0].severity == "critical"
    assert "8.4.27" in findings[0].evidence
    assert "does not establish" in findings[0].evidence
    assert len(factors) == 1 and factors[0].points == 60
    assert is_unpatched_php_inventory(event)


def test_no_false_alarm_for_patched_or_unverified_versions() -> None:
    events = [
        {"event_type": "software_inventory", "product": "PHP", "version": "8.4.27"},
        {"event_type": "http_request", "product": "PHP", "version": "8.4.26"},
        {"event_type": "software_inventory", "product": "nginx", "version": "8.4.26"},
        {"event_type": "software_inventory", "product": "PHP", "version": "8.6.0"},
    ]
    assert detect_php2shell_exposures(events) == ([], [])


def test_unconfirmed_exposure_is_high_not_critical() -> None:
    findings, factors = detect_php2shell_exposures(
        [
            {
                "event_type": "php_version_report",
                "component": "PHP-FPM",
                "version": "8.3.35",
                "hostname": "batch-1",
            }
        ]
    )
    assert findings[0].severity == "high"
    assert factors[0].points == 35
