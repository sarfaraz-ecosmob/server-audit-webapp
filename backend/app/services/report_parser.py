"""
Best-effort extraction of dashboard-card numbers from the self-contained
HTML report that gen_report.py produces, so the project/server list can show
a grade + counts without loading the full report. If any of these regexes
fail to match (e.g. gen_report.py's variable names change upstream), we
degrade gracefully to an empty summary — the report itself is always still
viewable/downloadable regardless.
"""
import re
from datetime import datetime


def _first_int(pattern: str, html: str) -> int | None:
    m = re.search(pattern, html)
    return int(m.group(1)) if m else None


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

    ts = re.search(r"Audit Timestamp[^\d]*(\d{8}_\d{6})", html)
    if ts:
        try:
            summary["audit_timestamp"] = datetime.strptime(
                ts.group(1), "%Y%m%d_%H%M%S"
            ).isoformat()
        except ValueError:
            pass

    return summary
