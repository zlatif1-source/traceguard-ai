"""Evidence-based PHP2Shell exposure checks for explicit software inventory events.

A version observation indicates possible exposure, not exploitation. TraceGuard does
not probe a network host or infer installed software from an HTTP request alone.
"""

import re

from app.models import Finding, RiskFactor

PHP2SHELL_CVES = ("CVE-2026-109618", "CVE-2026-109619")
PHP2SHELL_FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
PHP_PRODUCTS = {"php", "php runtime", "php-fpm", "mod_php", "php-cgi"}


def classify_php_version(version: str) -> tuple[str, str | None]:
    """Return (fixed | vulnerable | unsupported | unknown, upstream fixed version)."""
    match = VERSION_RE.fullmatch(version.strip())
    if match is None:
        return "unknown", None

    major, minor, patch = (int(group) for group in match.groups())
    current = (major, minor, patch)
    fixed = PHP2SHELL_FIXED.get((major, minor))
    if fixed is not None:
        return (
            ("fixed" if current >= fixed else "vulnerable"),
            ".".join(str(part) for part in fixed),
        )
    if (major == 5 and minor >= 4) or major == 7 or (major == 8 and minor <= 1):
        return "unsupported", None
    return "unknown", None


def is_php_inventory(event: dict) -> bool:
    event_type = str(event.get("event_type", "")).strip().lower()
    product = str(event.get("product", event.get("component", ""))).strip().lower()
    return event_type in {"software_inventory", "php_version_report"} and product in PHP_PRODUCTS


def is_unpatched_php_inventory(event: dict) -> bool:
    if not is_php_inventory(event):
        return False
    state, _ = classify_php_version(str(event.get("version", "")))
    return state in {"vulnerable", "unsupported"}


def detect_php2shell_exposures(events: list[dict]) -> tuple[list[Finding], list[RiskFactor]]:
    """Detect potentially affected PHP runtimes from *explicit* inventory evidence."""
    findings: list[Finding] = []
    factors: list[RiskFactor] = []
    seen_assets: set[tuple[str, str]] = set()

    for event in events:
        if not is_php_inventory(event):
            continue
        version = str(event.get("version", "")).strip()
        state, fixed_version = classify_php_version(version)
        if state not in {"vulnerable", "unsupported"}:
            continue

        host = str(event.get("hostname") or event.get("host") or "unspecified host")
        asset = (host, version)
        if asset in seen_assets:
            continue
        seen_assets.add(asset)
        internet_facing = event.get("internet_facing") is True
        source_ip = event.get("source_ip")
        if state == "vulnerable":
            guidance = (
                f"PHP {version} is below upstream fixed release {fixed_version} for "
                f"{PHP2SHELL_CVES[0]} and {PHP2SHELL_CVES[1]}."
            )
            title = "PHP2Shell: unpatched PHP runtime identified"
        else:
            guidance = (
                f"PHP {version} is an unsupported upstream PHP release potentially affected "
                f"by {PHP2SHELL_CVES[0]} and {PHP2SHELL_CVES[1]}; verify any vendor backport."
            )
            title = "PHP2Shell: legacy PHP runtime needs vendor review"

        exposure = "Internet-facing" if internet_facing else "Internet exposure not confirmed"
        findings.append(
            Finding(
                title=title,
                evidence=(
                    f"{host}: {guidance} {exposure}. Software version alone does not "
                    "establish that exploitation occurred."
                ),
                severity="critical" if internet_facing else "high",
                source_ip=str(source_ip) if source_ip else None,
            )
        )
        factors.append(
            RiskFactor(
                reason=f"PHP2Shell patch exposure ({host}, PHP {version})",
                points=60 if internet_facing else 35,
            )
        )
    return findings, factors
