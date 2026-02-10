#!/usr/bin/env python3
"""
Credence HTML Report Generator — Human-readable scan reports.

Takes scan-summary.json and evidence.json, produces a standalone HTML report
matching the Credence visual identity (IBM Plex, orange/gray, dark theme).

Usage:
    python report_generator.py /path/to/scan-summary.json [evidence.json] [output.html]
"""

import json
import sys
from datetime import datetime
from pathlib import Path


def generate_report(summary: dict, evidence: dict = None) -> str:
    """Generate an HTML report from scan summary and evidence."""

    server_name = summary.get("server_name", "Unknown Server")
    repo_url = summary.get("repo_url", "")
    commit = summary.get("commit_sha", "")[:12]
    source_hash = summary.get("source_hash", "")[:24]
    trust_score = summary.get("trust_score")
    verdict = summary.get("thinktank_verdict", "PENDING")
    scan_time = summary.get("scan_timestamp", "")
    flags = summary.get("provenance_flags", [])
    is_fork = summary.get("is_fork", False)
    scan_results = summary.get("scan_results", {})
    lockfile = summary.get("lockfile_name", "none")
    lockfile_hash = summary.get("lockfile_hash", "none")[:16]
    desc_hashes = summary.get("description_hashes", {})
    signed = summary.get("signature") is not None
    version = summary.get("pipeline_version", "?")

    # Score color
    if trust_score is not None:
        if trust_score >= 80:
            score_color = "#4ade80"
            score_label = "LOW RISK"
        elif trust_score >= 50:
            score_color = "#D06030"
            score_label = "MEDIUM RISK"
        else:
            score_color = "#ef4444"
            score_label = "HIGH RISK"
    else:
        score_color = "#606060"
        score_label = "PENDING"

    # Evidence summary
    ev_total = 0
    ev_by_severity = {}
    ev_findings_html = ""
    if evidence:
        ev_total = evidence.get("total_findings", 0)
        ev_by_severity = evidence.get("by_severity", {})
        findings = evidence.get("findings", [])

        if findings:
            rows = []
            for f in findings[:50]:  # Cap at 50 for readability
                sev = f.get("severity", "info")
                sev_class = {
                    "critical": "sev-critical",
                    "high": "sev-high",
                    "medium": "sev-medium",
                    "low": "sev-low",
                }.get(sev, "sev-info")
                rows.append(f"""<tr>
                    <td><span class="{sev_class}">{sev.upper()}</span></td>
                    <td>{_esc(f.get('scanner', ''))}</td>
                    <td>{_esc(f.get('title', ''))}</td>
                    <td class="mono">{_esc(f.get('file', ''))}:{f.get('line', 0)}</td>
                    <td>{_esc(f.get('description', '')[:120])}</td>
                </tr>""")
            ev_findings_html = "\n".join(rows)

    # Flag badges
    flag_html = ""
    if flags:
        flag_badges = " ".join(f'<span class="flag-badge">{_esc(f)}</span>' for f in flags)
        flag_html = f'<div class="flags">{flag_badges}</div>'
    else:
        flag_html = '<div class="flags"><span class="flag-ok">No provenance flags</span></div>'

    # Description hashes
    desc_html = ""
    if desc_hashes:
        desc_rows = "\n".join(
            f'<tr><td class="mono">{_esc(name)}</td><td class="mono dim">{h[:24]}...</td></tr>'
            for name, h in desc_hashes.items()
        )
        desc_html = f"""
        <section>
            <h2>Tool Description Hashes</h2>
            <p class="dim">These hashes pin tool descriptions at attestation time. If descriptions change after attestation, it may indicate a rug pull.</p>
            <table><thead><tr><th>Tool</th><th>Description Hash (SHA-256)</th></tr></thead>
            <tbody>{desc_rows}</tbody></table>
        </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Credence Report: {_esc(server_name)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'IBM Plex Sans', sans-serif;
    background: #0d0d0d; color: #e0e0e0;
    padding: 40px 20px; max-width: 900px; margin: 0 auto;
    line-height: 1.6;
  }}
  h1 {{ font-family: 'IBM Plex Mono', monospace; font-size: 1.6rem; margin-bottom: 8px; }}
  h2 {{ font-family: 'IBM Plex Mono', monospace; font-size: 1.1rem; color: #D06030; margin: 32px 0 12px; }}
  .mono {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.85rem; }}
  .dim {{ color: #808080; }}
  a {{ color: #D06030; }}

  .header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 32px; }}
  .score-ring {{
    width: 80px; height: 80px; border-radius: 50%;
    border: 4px solid {score_color};
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    flex-shrink: 0;
  }}
  .score-num {{ font-family: 'IBM Plex Mono', monospace; font-size: 1.4rem; font-weight: 600; color: {score_color}; }}
  .score-label {{ font-size: 0.6rem; color: {score_color}; letter-spacing: 0.1em; }}

  .meta {{ margin-bottom: 24px; }}
  .meta-row {{ display: flex; gap: 8px; margin-bottom: 4px; }}
  .meta-label {{ color: #808080; width: 120px; flex-shrink: 0; }}

  .flags {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }}
  .flag-badge {{
    background: rgba(208, 96, 48, 0.15); border: 1px solid #D06030;
    color: #D06030; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .flag-ok {{
    background: rgba(74, 222, 128, 0.1); border: 1px solid #4ade80;
    color: #4ade80; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem;
  }}

  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 8px; border-bottom: 1px solid #333; color: #808080; font-weight: 400; }}
  td {{ padding: 8px; border-bottom: 1px solid #1a1a1a; vertical-align: top; }}

  .scan-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 12px 0; }}
  .scan-card {{
    background: #141414; border: 1px solid #222; border-radius: 8px;
    padding: 12px; text-align: center;
  }}
  .scan-card .num {{ font-family: 'IBM Plex Mono', monospace; font-size: 1.4rem; font-weight: 600; }}
  .scan-card .label {{ font-size: 0.75rem; color: #808080; margin-top: 4px; }}
  .num-zero {{ color: #4ade80; }}
  .num-warn {{ color: #D06030; }}
  .num-crit {{ color: #ef4444; }}

  .sev-critical {{ background: #ef4444; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; }}
  .sev-high {{ background: #D06030; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; }}
  .sev-medium {{ background: #a16207; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; }}
  .sev-low {{ background: #333; color: #ccc; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; }}
  .sev-info {{ background: #1a1a1a; color: #808080; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; }}

  .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid #222; color: #606060; font-size: 0.75rem; }}
</style>
</head>
<body>

<div class="header">
    <div class="score-ring">
        <div class="score-num">{trust_score if trust_score is not None else '?'}</div>
        <div class="score-label">{score_label}</div>
    </div>
    <div>
        <h1>{_esc(server_name)}</h1>
        <div class="dim">{_esc(repo_url)}</div>
        <div class="mono dim" style="margin-top: 4px;">
            {'🔏 Signed' if signed else '⚠️ Unsigned'} · Verdict: {_esc(verdict)}
        </div>
    </div>
</div>

<section>
    <h2>Attestation Details</h2>
    <div class="meta">
        <div class="meta-row"><span class="meta-label">Commit</span><span class="mono">{_esc(commit)}</span></div>
        <div class="meta-row"><span class="meta-label">Source hash</span><span class="mono">{_esc(source_hash)}...</span></div>
        <div class="meta-row"><span class="meta-label">Lockfile</span><span class="mono">{_esc(lockfile)} → {_esc(lockfile_hash)}...</span></div>
        <div class="meta-row"><span class="meta-label">Fork</span><span>{'Yes' if is_fork else 'No'}</span></div>
        <div class="meta-row"><span class="meta-label">Scanned</span><span>{_esc(scan_time)}</span></div>
    </div>
    {flag_html}
</section>

<section>
    <h2>Scan Results</h2>
    <div class="scan-grid">
        {_scan_card('Semgrep', scan_results.get('semgrep_findings', 0))}
        {_scan_card('Bandit', scan_results.get('bandit_findings', 0))}
        {_scan_card('ESLint', scan_results.get('eslint_security_issues', 0))}
        {_scan_card('Trivy CVEs', scan_results.get('trivy_vulnerabilities', 0))}
        {_scan_card('npm audit', scan_results.get('npm_audit_vulnerabilities', 0))}
        {_scan_card('pip-audit', scan_results.get('pip_audit_vulnerabilities', 0))}
        {_scan_card('Secrets', scan_results.get('gitleaks_secrets', 0))}
        {_scan_card('MCP Tools', scan_results.get('mcp_tool_warnings', 0))}
    </div>
</section>

{'<section><h2>Findings Detail</h2>' + f'<p class="dim">{ev_total} total findings across all scanners</p>' + '<table><thead><tr><th>Severity</th><th>Scanner</th><th>Finding</th><th>Location</th><th>Description</th></tr></thead><tbody>' + ev_findings_html + '</tbody></table></section>' if ev_findings_html else ''}

{desc_html}

<div class="footer">
    Credence Pipeline v{_esc(version)} · <a href="https://pestafford.github.io/credence-registry/">pestafford.github.io/credence-registry</a> · Singularity Systems
</div>

</body>
</html>"""


def _esc(s) -> str:
    """Basic HTML escaping."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _scan_card(label: str, count: int) -> str:
    """Generate a scan result card."""
    if count == 0:
        css = "num-zero"
    elif count <= 3:
        css = "num-warn"
    else:
        css = "num-crit"
    return f'<div class="scan-card"><div class="num {css}">{count}</div><div class="label">{label}</div></div>'


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} scan-summary.json [evidence.json] [output.html]")
        sys.exit(1)

    summary_path = sys.argv[1]
    evidence_path = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].endswith('.html') else None
    output_path = sys.argv[-1] if sys.argv[-1].endswith('.html') else "/tmp/credence-report.html"

    with open(summary_path) as f:
        summary = json.load(f)

    evidence = None
    if evidence_path:
        try:
            with open(evidence_path) as f:
                evidence = json.load(f)
        except Exception:
            pass

    html = generate_report(summary, evidence)

    with open(output_path, 'w') as f:
        f.write(html)

    print(f"Report generated: {output_path}")


if __name__ == "__main__":
    main()
