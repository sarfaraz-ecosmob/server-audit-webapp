"""
Best-effort extraction of dashboard-card numbers from the self-contained
HTML report that gen_report.py produces, so the project/server list can show
a grade + counts without loading the full report. If any of these regexes
fail to match (e.g. gen_report.py's variable names change upstream), we
degrade gracefully to an empty summary — the report itself is always still
viewable/downloadable regardless.
"""
import re
import json
from datetime import datetime


def _first_int(pattern: str, html: str) -> int | None:
    m = re.search(pattern, html)
    return int(m.group(1)) if m else None


def _extract_js_var(html: str, var_name: str) -> str | None:
    """Extract the raw JSON literal assigned to `var <var_name>=...;` in the
    report's embedded JS. Scans bracket-by-bracket while respecting JSON
    string literals (including escaped quotes), so a description containing
    `]`, `{`, or `;` can never break the match. Returns None if not found.
    The JSON is embedded via gen_report.py's `js_safe()` (`</` -> `<\/`),
    which is a valid JSON escape, so `json.loads` handles it directly."""
    marker = f"var {var_name}="
    start = html.find(marker)
    if start == -1:
        return None
    i = start + len(marker)
    while i < len(html) and html[i] in " \t\r\n":
        i += 1
    if i >= len(html) or html[i] not in "[{":
        return None
    depth = 0
    in_str = False
    esc = False
    for j in range(i, len(html)):
        c = html[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
            if depth == 0:
                return html[i : j + 1]
    return None


def parse_summary(html: str) -> dict:
    summary = {}

    lynis_score = _first_int(r"Score:\s*(\d+)/100", html)
    grade_match = re.search(r"Grade\s+([A-F])</small>", html)
    if lynis_score is not None:
        summary["lynis_score"] = lynis_score
    if grade_match:
        summary["lynis_grade"] = grade_match.group(1)

    warn_sugg = re.search(r"(\d+)\s*warnings\s*&middot;\s*(\d+)\s*suggestions", html)
    if warn_sugg:
        summary["lynis_warnings"] = int(warn_sugg.group(1))
        summary["lynis_suggestions"] = int(warn_sugg.group(2))

    open_ports = _first_int(r'"open_count"\s*:\s*(\d+)', html) or _first_int(
        r"Open Ports.{0,200}?(\d+)", html
    )
    if open_ports is not None:
        summary["open_ports"] = open_ports

    web_alerts = re.search(r"(\d+)\s*high.{0,20}?(\d+)\s*med.{0,20}?(\d+)\s*low", html)
    if web_alerts:
        summary["zap_high"] = int(web_alerts.group(1))
        summary["zap_medium"] = int(web_alerts.group(2))
        summary["zap_low"] = int(web_alerts.group(3))

    health_fail = re.search(r"(\d+)\s*failed of\s*(\d+)\s*service", html)
    if health_fail:
        summary["health_failed"] = int(health_fail.group(1))
        summary["health_total"] = int(health_fail.group(2))

    suid = re.search(r"(\d+)\s*Privileged binaries", html)
    if suid:
        summary["suid_sgid_count"] = int(suid.group(1))

    kernel_vulns = re.search(r"Kernel Vulns[^<]*<span[^>]*id=\"kvcnt\"[^>]*>(\d+)</span>", html)
    if kernel_vulns:
        summary["kernel_vulns_count"] = int(kernel_vulns.group(1))

    kernel_crit = re.search(r"Trivy:\s*(\d+)\s*critical", html)
    if kernel_crit:
        summary["kernel_critical_count"] = int(kernel_crit.group(1))

    kernel_high = re.search(r"Trivy:\s*\d+\s*critical\s*&middot;\s*(\d+)\s*high", html)
    if kernel_high:
        summary["kernel_high_count"] = int(kernel_high.group(1))

    # The full kernel-filtered vulnerability list — the same array
    # gen_report.py embeds as `var KERNEL_VULNS=[...]` (already filtered to
    # kernel packages + HIGH/CRITICAL by server_audit.sh's jq step). Capped
    # to keep the summary JSON column small; the complete list is always
    # available inside the report itself.
    kernel_vulns_json = _extract_js_var(html, "KERNEL_VULNS")
    if kernel_vulns_json:
        try:
            vulns = json.loads(kernel_vulns_json)
        except ValueError:
            vulns = None
        if vulns:
            summary["kernel_vulnerabilities"] = [
                {
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "severity": v.get("Severity"),
                    "title": v.get("Title"),
                }
                for v in vulns[:100]
            ]

    # Trivy/jq availability from the embedded tool-status array — lets the
    # frontend distinguish "kernel scan ran clean" from "kernel scan was
    # skipped because the tools aren't installed" (a skipped scan also
    # renders 0 counts, which would otherwise be read as a clean bill of
    # health).
    tools_json = _extract_js_var(html, "TOOLS")
    if tools_json:
        try:
            tools = json.loads(tools_json)
        except ValueError:
            tools = None
        if tools:
            trivy_ok = any(
                (t.get("name") or "").lower().startswith("trivy") and t.get("status") == "found"
                for t in tools
            )
            jq_ok = any(
                (t.get("name") or "").lower() == "jq" and t.get("status") == "found"
                for t in tools
            )
            if not (trivy_ok and jq_ok):
                missing = [name for ok, name in ((trivy_ok, "Trivy"), (jq_ok, "jq")) if not ok]
                summary["kernel_scan_skipped"] = True
                summary["kernel_scan_skip_reason"] = (
                    f"{' and '.join(missing)} not installed on the server"
                )

    ts = re.search(r"Audit Timestamp[^\d]*(\d{8}_\d{6})", html)
    if ts:
        try:
            summary["audit_timestamp"] = datetime.strptime(
                ts.group(1), "%Y%m%d_%H%M%S"
            ).isoformat()
        except ValueError:
            pass

    return summary
