"""
recon47/reporter.py — HTML report generator (hacker-theme)
Author: 0xMasruful
"""

from __future__ import annotations

import json
import time
from pathlib import Path


def generate_html_report(ctx) -> Path:
    """Generate the full HTML report from scan context."""
    data = ctx.to_dict()
    html = _build_html(data, ctx)
    out_path = ctx.output_dir / "recon47_report.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": "#ff0040",
        "HIGH": "#ff6b35",
        "MEDIUM": "#ffd700",
        "LOW": "#00bfff",
        "INFO": "#888",
    }.get(sev.upper(), "#888")


def _build_html(data: dict, ctx) -> str:
    meta = data.get("meta", {})
    sc = data.get("severity_counts", {})

    def vuln_cards(vulns):
        if not vulns:
            return '<div class="empty">No findings in this category.</div>'
        cards = []
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            color = _sev_color(sev)
            title = v.get("title", "Unknown")
            desc = v.get("description", "")
            source = v.get("source", "")
            rec = v.get("recommendation", "")
            cves = v.get("cves", [])
            cve_html = "".join(f'<span class="cve-tag">{c}</span>' for c in (cves if cves else []))

            rec_html = f'<div class="rec"><span class="rec-label">⟹ FIX</span> {rec}</div>' if rec else ""
            cards.append(f"""
            <div class="vuln-card" data-sev="{sev}">
              <div class="vuln-header">
                <span class="sev-badge" style="color:{color};border-color:{color}">{sev}</span>
                <span class="vuln-title">{title}</span>
                <span class="source-tag">{source}</span>
              </div>
              {f'<div class="vuln-desc">{desc}</div>' if desc and desc != title else ""}
              {cve_html}
              {rec_html}
            </div>""")
        return "\n".join(cards)

    all_vulns = data.get("vulnerabilities", {})
    all_vuln_list = (
        all_vulns.get("nikto", []) +
        all_vulns.get("nuclei", []) +
        all_vulns.get("header_issues", []) +
        all_vulns.get("js_secrets", [])
    )

    subdomains_html = ""
    for s in data.get("subdomains", []):
        subdomains_html += f'<tr><td>{s.get("subdomain","")}</td><td>{s.get("ip","")}</td></tr>'

    ports_html = ""
    for port, info in sorted(data.get("ports", {}).items(), key=lambda x: int(x[0])):
        banner = info.get("banner", "")[:60]
        tls = "🔒" if info.get("tls") else ""
        ports_html += f'<tr><td>{port}/tcp</td><td>{info.get("service","")}</td><td>{tls}</td><td class="mono dim">{banner}</td></tr>'

    techs_html = ""
    for t in data.get("technologies", []):
        ver = t.get("version", "")
        techs_html += f'<span class="tech-tag">{t["name"]}{(" " + ver) if ver else ""}</span>'

    endpoints_html = ""
    for ep in data.get("endpoints", [])[:100]:
        endpoints_html += f'<div class="endpoint mono">{ep}</div>'

    dirs_html = ""
    for d in data.get("directories", []):
        sev_col = _sev_color(d.get("severity", "INFO"))
        dirs_html += (
            f'<tr><td style="color:{sev_col}">[{d.get("status","")}]</td>'
            f'<td class="mono">{d.get("path","")}</td>'
            f'<td>{d.get("size","")}b</td>'
            f'<td class="dim">{d.get("title","")}</td></tr>'
        )

    js_findings_html = vuln_cards(data.get("js_findings", []))
    nikto_html = vuln_cards(all_vulns.get("nikto", []))
    nuclei_html = vuln_cards(all_vulns.get("nuclei", []))
    header_html = vuln_cards(all_vulns.get("header_issues", []))
    all_vulns_html = vuln_cards(all_vuln_list)

    dns_data = data.get("dns", {})
    dns_html = ""
    for rtype, vals in dns_data.items():
        if not vals:
            continue
        if isinstance(vals, list):
            dns_html += f'<tr><td class="rtype">{rtype}</td><td class="mono">{", ".join(str(v) for v in vals[:5])}</td></tr>'
        elif isinstance(vals, dict):
            dns_html += f'<tr><td class="rtype">{rtype}</td><td class="mono">{json.dumps(vals)[:120]}</td></tr>'

    whois = data.get("whois", {})
    whois_html = ""
    for k, v in whois.items():
        if v and k != "error":
            whois_html += f'<tr><td class="dim">{k}</td><td>{v}</td></tr>'

    ai_section = ""
    if data.get("ai_summary"):
        ai_section = f"""
        <section id="ai" class="section">
          <h2 class="section-title">
            <span class="section-icon">🤖</span>
            AI Security Analysis
            <span class="badge-count powered">Claude AI</span>
          </h2>
          <div class="ai-summary">{data["ai_summary"].replace(chr(10), "<br>")}</div>
        </section>"""

    waf_tag = f'<span class="waf-badge">{ctx.waf}</span>' if ctx.waf else '<span class="dim">Not detected</span>'
    cdn_tag = f'<span class="tech-tag">{ctx.cdn}</span>' if ctx.cdn else '<span class="dim">—</span>'

    total_vulns = sum(sc.values())
    risk = "CRITICAL" if sc.get("CRITICAL", 0) > 0 else \
           "HIGH" if sc.get("HIGH", 0) > 0 else \
           "MEDIUM" if sc.get("MEDIUM", 0) > 0 else \
           "LOW" if sc.get("LOW", 0) > 0 else "INFO"
    risk_color = _sev_color(risk)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recon47 Report :: {meta.get("target","")}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Orbitron:wght@400;600;700;900&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #040608;
      --bg2: #080c10;
      --bg3: #0d1117;
      --surface: #0f1923;
      --surface2: #141d2b;
      --border: #1a2a3a;
      --border2: #0f3040;
      --green: #00ff41;
      --green2: #00cc33;
      --green3: #009922;
      --cyan: #00e5ff;
      --red: #ff0040;
      --orange: #ff6b35;
      --yellow: #ffd700;
      --blue: #00bfff;
      --purple: #bd00ff;
      --text: #c9d1d9;
      --text2: #8b949e;
      --text3: #4a5568;
      --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
      --font-display: 'Orbitron', sans-serif;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 1.6;
      overflow-x: hidden;
    }}

    /* Scanline overlay */
    body::before {{
      content: '';
      position: fixed; inset: 0; z-index: 9999; pointer-events: none;
      background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.015) 2px, rgba(0,255,65,0.015) 4px);
      animation: scanline 8s linear infinite;
    }}
    @keyframes scanline {{
      0% {{ background-position: 0 0; }}
      100% {{ background-position: 0 100vh; }}
    }}

    /* Glitch grid background */
    body::after {{
      content: '';
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image:
        linear-gradient(rgba(0,255,65,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,65,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
    }}

    /* Header */
    .header {{
      position: relative; z-index: 1;
      background: linear-gradient(180deg, #000 0%, var(--bg2) 100%);
      border-bottom: 1px solid var(--border2);
      padding: 40px 60px 30px;
      overflow: hidden;
    }}
    .header::after {{
      content: '';
      position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
      background: linear-gradient(90deg, transparent, var(--green), transparent);
      animation: glow-line 3s ease-in-out infinite;
    }}
    @keyframes glow-line {{
      0%, 100% {{ opacity: 0.3; }}
      50% {{ opacity: 1; }}
    }}
    .logo {{
      font-family: var(--font-display);
      font-size: 2.8rem;
      font-weight: 900;
      letter-spacing: 0.3em;
      color: var(--green);
      text-shadow: 0 0 20px rgba(0,255,65,0.5), 0 0 60px rgba(0,255,65,0.2);
      animation: logo-flicker 5s ease-in-out infinite;
    }}
    @keyframes logo-flicker {{
      0%, 95%, 100% {{ opacity: 1; }}
      96% {{ opacity: 0.8; }}
      97% {{ opacity: 1; }}
      98% {{ opacity: 0.85; }}
    }}
    .logo-sub {{
      font-size: 0.65rem;
      letter-spacing: 0.4em;
      color: var(--text3);
      margin-top: 4px;
      text-transform: uppercase;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 28px;
    }}
    .meta-item {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 12px 16px;
    }}
    .meta-label {{
      font-size: 0.65rem;
      letter-spacing: 0.2em;
      color: var(--text3);
      text-transform: uppercase;
      margin-bottom: 4px;
    }}
    .meta-value {{
      color: var(--cyan);
      font-size: 0.85rem;
      font-weight: 600;
    }}

    /* Risk indicator */
    .risk-badge {{
      display: inline-block;
      font-family: var(--font-display);
      font-size: 0.9rem;
      font-weight: 700;
      letter-spacing: 0.15em;
      padding: 6px 20px;
      border: 2px solid {risk_color};
      color: {risk_color};
      text-shadow: 0 0 10px {risk_color}88;
      box-shadow: 0 0 15px {risk_color}44, inset 0 0 15px {risk_color}11;
      border-radius: 2px;
    }}

    /* Sidebar nav */
    .layout {{
      display: flex;
      position: relative;
      z-index: 1;
    }}
    .nav {{
      width: 200px;
      min-width: 200px;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
      background: var(--bg2);
      border-right: 1px solid var(--border);
      padding: 20px 0;
    }}
    .nav::-webkit-scrollbar {{ width: 3px; }}
    .nav::-webkit-scrollbar-thumb {{ background: var(--green3); border-radius: 3px; }}
    .nav-label {{
      font-size: 0.6rem;
      letter-spacing: 0.3em;
      color: var(--text3);
      text-transform: uppercase;
      padding: 12px 16px 6px;
    }}
    .nav a {{
      display: block;
      padding: 7px 16px;
      color: var(--text2);
      text-decoration: none;
      font-size: 0.78rem;
      border-left: 2px solid transparent;
      transition: all 0.15s;
    }}
    .nav a:hover {{
      color: var(--green);
      border-left-color: var(--green);
      background: rgba(0,255,65,0.05);
    }}
    .nav-count {{
      float: right;
      font-size: 0.65rem;
      color: var(--text3);
      background: var(--surface);
      padding: 1px 6px;
      border-radius: 10px;
    }}

    /* Main content */
    .main {{
      flex: 1;
      min-width: 0;
      padding: 30px 40px;
    }}

    /* Stats bar */
    .stats-bar {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 32px;
      padding: 20px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      border-top: 2px solid var(--green3);
    }}
    .stat-box {{
      flex: 1;
      min-width: 90px;
      text-align: center;
      padding: 12px 8px;
      background: var(--bg3);
      border-radius: 3px;
      border: 1px solid var(--border);
      cursor: pointer;
      transition: all 0.2s;
    }}
    .stat-box:hover {{
      border-color: var(--green);
      box-shadow: 0 0 12px rgba(0,255,65,0.15);
    }}
    .stat-box.active {{ border-color: var(--green); background: rgba(0,255,65,0.05); }}
    .stat-num {{
      font-family: var(--font-display);
      font-size: 1.8rem;
      font-weight: 700;
      line-height: 1;
    }}
    .stat-label {{ font-size: 0.65rem; color: var(--text3); letter-spacing: 0.1em; margin-top: 4px; }}

    /* Sections */
    .section {{
      margin-bottom: 32px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      overflow: hidden;
    }}
    .section-title {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 14px 20px;
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
      font-family: var(--font-display);
      font-size: 0.8rem;
      font-weight: 600;
      letter-spacing: 0.12em;
      color: var(--cyan);
      cursor: pointer;
      user-select: none;
    }}
    .section-title:hover {{ background: var(--bg3); }}
    .section-title .section-icon {{ font-size: 1rem; }}
    .section-body {{
      padding: 20px;
      overflow-x: auto;
    }}
    .section-body.collapsed {{ display: none; }}

    /* Filter bar */
    .filter-bar {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    .filter-btn {{
      padding: 4px 14px;
      border: 1px solid var(--border);
      background: var(--bg3);
      color: var(--text2);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      cursor: pointer;
      border-radius: 2px;
      transition: all 0.15s;
    }}
    .filter-btn:hover {{ border-color: var(--green); color: var(--green); }}
    .filter-btn.active {{ background: var(--green); color: #000; border-color: var(--green); font-weight: 700; }}

    /* Tables */
    table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
    th {{
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border2);
      color: var(--text3);
      font-size: 0.65rem;
      letter-spacing: 0.15em;
      text-transform: uppercase;
    }}
    td {{ padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(0,255,65,0.03); }}
    .rtype {{ color: var(--cyan); font-weight: 600; font-size: 0.75rem; }}

    /* Vuln cards */
    .vuln-card {{
      margin-bottom: 10px;
      border: 1px solid var(--border);
      border-radius: 3px;
      padding: 12px 16px;
      background: var(--bg3);
      transition: all 0.2s;
    }}
    .vuln-card:hover {{ border-color: rgba(0,255,65,0.2); }}
    .vuln-card[data-sev="CRITICAL"] {{ border-left: 3px solid var(--red); }}
    .vuln-card[data-sev="HIGH"] {{ border-left: 3px solid var(--orange); }}
    .vuln-card[data-sev="MEDIUM"] {{ border-left: 3px solid var(--yellow); }}
    .vuln-card[data-sev="LOW"] {{ border-left: 3px solid var(--blue); }}
    .vuln-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .sev-badge {{
      font-family: var(--font-display);
      font-size: 0.6rem;
      font-weight: 700;
      letter-spacing: 0.15em;
      padding: 2px 8px;
      border: 1px solid;
      border-radius: 2px;
      min-width: 70px;
      text-align: center;
    }}
    .vuln-title {{ flex: 1; font-weight: 500; color: var(--text); font-size: 0.85rem; }}
    .source-tag {{
      font-size: 0.65rem;
      color: var(--text3);
      background: var(--surface2);
      padding: 2px 8px;
      border-radius: 10px;
    }}
    .vuln-desc {{ margin-top: 8px; color: var(--text2); font-size: 0.8rem; }}
    .cve-tag {{
      display: inline-block;
      margin-top: 6px;
      margin-right: 6px;
      padding: 2px 8px;
      background: rgba(255,0,64,0.1);
      border: 1px solid rgba(255,0,64,0.3);
      color: var(--red);
      font-size: 0.7rem;
      border-radius: 2px;
    }}
    .rec {{
      margin-top: 8px;
      padding: 6px 10px;
      background: rgba(0,255,65,0.05);
      border-left: 2px solid var(--green3);
      font-size: 0.78rem;
      color: var(--text2);
    }}
    .rec-label {{ color: var(--green); font-weight: 700; margin-right: 6px; }}

    /* Misc */
    .tech-tag {{
      display: inline-block;
      margin: 3px;
      padding: 3px 12px;
      background: rgba(0,229,255,0.08);
      border: 1px solid rgba(0,229,255,0.2);
      color: var(--cyan);
      font-size: 0.78rem;
      border-radius: 2px;
    }}
    .waf-badge {{
      display: inline-block;
      padding: 3px 12px;
      background: rgba(189,0,255,0.1);
      border: 1px solid rgba(189,0,255,0.3);
      color: var(--purple);
      font-size: 0.78rem;
      border-radius: 2px;
    }}
    .badge-count {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      padding: 2px 8px;
      background: rgba(0,255,65,0.1);
      border: 1px solid var(--green3);
      color: var(--green);
      border-radius: 10px;
      margin-left: auto;
    }}
    .badge-count.powered {{
      background: rgba(189,0,255,0.1);
      border-color: rgba(189,0,255,0.4);
      color: var(--purple);
    }}
    .endpoint {{
      padding: 4px 8px;
      border-bottom: 1px solid rgba(255,255,255,0.03);
      font-size: 0.78rem;
      color: var(--text2);
      word-break: break-all;
    }}
    .endpoint:hover {{ color: var(--text); background: rgba(0,255,65,0.03); }}
    .mono {{ font-family: var(--font-mono); }}
    .dim {{ color: var(--text3); }}
    .empty {{ padding: 20px; text-align: center; color: var(--text3); font-size: 0.8rem; }}
    .ai-summary {{
      padding: 20px;
      background: var(--bg3);
      border: 1px solid rgba(189,0,255,0.2);
      border-radius: 3px;
      font-size: 0.85rem;
      line-height: 1.8;
      color: var(--text);
    }}
    .chevron {{ margin-left: auto; color: var(--text3); transition: transform 0.2s; }}
    .section-title.open .chevron {{ transform: rotate(90deg); }}

    /* Footer */
    .footer {{
      position: relative; z-index: 1;
      text-align: center;
      padding: 24px;
      border-top: 1px solid var(--border);
      color: var(--text3);
      font-size: 0.75rem;
    }}
    .footer span {{ color: var(--green); }}

    /* Print */
    @media print {{
      body::before, body::after {{ display: none; }}
      .nav {{ display: none; }}
      .main {{ padding: 20px; }}
      .section-body {{ display: block !important; }}
    }}
  </style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:20px">
    <div>
      <div class="logo">RECON47</div>
      <div class="logo-sub">Automated Recon &amp; Vulnerability Assessment Framework</div>
    </div>
    <div style="text-align:right">
      <div style="color:var(--text3);font-size:0.7rem;letter-spacing:0.15em;margin-bottom:8px">OVERALL RISK</div>
      <div class="risk-badge">{risk}</div>
    </div>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{meta.get("target","")}</div></div>
    <div class="meta-item"><div class="meta-label">Timestamp</div><div class="meta-value">{meta.get("timestamp","")}</div></div>
    <div class="meta-item"><div class="meta-label">Duration</div><div class="meta-value">{meta.get("duration","")}</div></div>
    <div class="meta-item"><div class="meta-label">Author</div><div class="meta-value">{meta.get("author","0xMasruful")}</div></div>
    <div class="meta-item"><div class="meta-label">WAF</div><div class="meta-value">{waf_tag}</div></div>
    <div class="meta-item"><div class="meta-label">CDN</div><div class="meta-value">{cdn_tag}</div></div>
  </div>
</div>

<div class="layout">
  <!-- Sidebar -->
  <nav class="nav">
    <div class="nav-label">Report Sections</div>
    <a href="#overview">Overview <span class="nav-count">{total_vulns}</span></a>
    <a href="#vulns">All Findings <span class="nav-count">{total_vulns}</span></a>
    <a href="#dns">DNS / WHOIS</a>
    <a href="#subdomains">Subdomains <span class="nav-count">{len(data.get("subdomains",[]))}</span></a>
    <a href="#ports">Open Ports <span class="nav-count">{len(data.get("ports",{}))}</span></a>
    <a href="#tech">Technologies <span class="nav-count">{len(data.get("technologies",[]))}</span></a>
    <a href="#headers">Headers <span class="nav-count">{len(data.get("header_issues",[]))}</span></a>
    <a href="#endpoints">Endpoints <span class="nav-count">{len(data.get("endpoints",[]))}</span></a>
    <a href="#dirs">Directories <span class="nav-count">{len(data.get("directories",[]))}</span></a>
    <a href="#js">JS Findings <span class="nav-count">{len(data.get("js_findings",[]))}</span></a>
    <a href="#nikto">Nikto <span class="nav-count">{len(data.get("vulnerabilities",{}).get("nikto",[]))}</span></a>
    <a href="#nuclei">Nuclei <span class="nav-count">{len(data.get("vulnerabilities",{}).get("nuclei",[]))}</span></a>
    {'<a href="#ai">AI Analysis</a>' if data.get("ai_summary") else ""}
  </nav>

  <!-- Main -->
  <main class="main">

    <!-- Stats bar -->
    <div id="overview" class="stats-bar">
      <div class="stat-box" onclick="filterVulns('ALL')" id="stat-ALL">
        <div class="stat-num" style="color:var(--green)">{total_vulns}</div>
        <div class="stat-label">Total</div>
      </div>
      <div class="stat-box" onclick="filterVulns('CRITICAL')" id="stat-CRITICAL">
        <div class="stat-num" style="color:var(--red)">{sc.get("CRITICAL",0)}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-box" onclick="filterVulns('HIGH')" id="stat-HIGH">
        <div class="stat-num" style="color:var(--orange)">{sc.get("HIGH",0)}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-box" onclick="filterVulns('MEDIUM')" id="stat-MEDIUM">
        <div class="stat-num" style="color:var(--yellow)">{sc.get("MEDIUM",0)}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-box" onclick="filterVulns('LOW')" id="stat-LOW">
        <div class="stat-num" style="color:var(--blue)">{sc.get("LOW",0)}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--cyan)">{len(data.get("subdomains",[]))}</div>
        <div class="stat-label">Subdomains</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--cyan)">{len(data.get("ports",{}))}</div>
        <div class="stat-label">Open Ports</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--cyan)">{len(data.get("endpoints",[]))}</div>
        <div class="stat-label">Endpoints</div>
      </div>
    </div>

    <!-- All Vulnerabilities -->
    <section id="vulns" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">⚡</span>
        All Vulnerability Findings
        <span class="badge-count">{total_vulns}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">
        <div class="filter-bar">
          <button class="filter-btn active" onclick="filterVulns('ALL',this)">ALL</button>
          <button class="filter-btn" onclick="filterVulns('CRITICAL',this)" style="color:var(--red);border-color:var(--red)">CRITICAL</button>
          <button class="filter-btn" onclick="filterVulns('HIGH',this)" style="color:var(--orange);border-color:var(--orange)">HIGH</button>
          <button class="filter-btn" onclick="filterVulns('MEDIUM',this)" style="color:var(--yellow);border-color:var(--yellow)">MEDIUM</button>
          <button class="filter-btn" onclick="filterVulns('LOW',this)" style="color:var(--blue);border-color:var(--blue)">LOW</button>
          <button class="filter-btn" onclick="filterVulns('INFO',this)">INFO</button>
        </div>
        <div id="vuln-list">
          {all_vulns_html}
        </div>
      </div>
    </section>

    <!-- DNS -->
    <section id="dns" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">🌐</span>
        DNS Records & WHOIS
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">
        <table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{dns_html}</tbody></table>
        {('<br><table><thead><tr><th>WHOIS Field</th><th>Value</th></tr></thead><tbody>' + whois_html + '</tbody></table>') if whois_html else ""}
      </div>
    </section>

    <!-- Subdomains -->
    <section id="subdomains" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">🔍</span>
        Discovered Subdomains
        <span class="badge-count">{len(data.get("subdomains",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">
        <table>
          <thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead>
          <tbody>{subdomains_html if subdomains_html else '<tr><td colspan="2" class="dim" style="text-align:center">No subdomains discovered</td></tr>'}</tbody>
        </table>
      </div>
    </section>

    <!-- Ports -->
    <section id="ports" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">🔓</span>
        Open Ports & Services
        <span class="badge-count">{len(data.get("ports",{}))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>TLS</th><th>Banner</th></tr></thead>
          <tbody>{ports_html if ports_html else '<tr><td colspan="4" class="dim" style="text-align:center">No open ports found</td></tr>'}</tbody>
        </table>
      </div>
    </section>

    <!-- Technologies -->
    <section id="tech" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">⚙️</span>
        Technologies & Fingerprints
        <span class="badge-count">{len(data.get("technologies",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">
        <div>{techs_html if techs_html else '<span class="dim">No technologies detected</span>'}</div>
        <div style="margin-top:14px">
          <span style="color:var(--text3);font-size:0.75rem">WAF:</span> {waf_tag}
          &nbsp;&nbsp;
          <span style="color:var(--text3);font-size:0.75rem">CDN:</span> {cdn_tag}
        </div>
      </div>
    </section>

    <!-- Headers -->
    <section id="headers" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">🛡️</span>
        Security Header Issues
        <span class="badge-count">{len(data.get("header_issues",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">{header_html}</div>
    </section>

    <!-- Endpoints -->
    <section id="endpoints" class="section">
      <h2 class="section-title" onclick="toggleSection(this)">
        <span class="section-icon">🗺️</span>
        Discovered Endpoints
        <span class="badge-count">{len(data.get("endpoints",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body collapsed">
        {endpoints_html if endpoints_html else '<div class="empty">No endpoints discovered</div>'}
      </div>
    </section>

    <!-- Directories -->
    <section id="dirs" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">📂</span>
        Directory Brute-Force Results
        <span class="badge-count">{len(data.get("directories",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">
        <table>
          <thead><tr><th>Status</th><th>Path</th><th>Size</th><th>Title</th></tr></thead>
          <tbody>{dirs_html if dirs_html else '<tr><td colspan="4" class="dim" style="text-align:center">No paths found</td></tr>'}</tbody>
        </table>
      </div>
    </section>

    <!-- JS Findings -->
    <section id="js" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">🔑</span>
        JavaScript Secrets & Endpoints
        <span class="badge-count">{len(data.get("js_findings",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">{js_findings_html}</div>
    </section>

    <!-- Nikto -->
    <section id="nikto" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">🎯</span>
        Nikto Scan Results
        <span class="badge-count">{len(data.get("vulnerabilities",{}).get("nikto",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">{nikto_html}</div>
    </section>

    <!-- Nuclei -->
    <section id="nuclei" class="section">
      <h2 class="section-title open" onclick="toggleSection(this)">
        <span class="section-icon">☢️</span>
        Nuclei Scan Results
        <span class="badge-count">{len(data.get("vulnerabilities",{}).get("nuclei",[]))}</span>
        <span class="chevron">›</span>
      </h2>
      <div class="section-body">{nuclei_html}</div>
    </section>

    {ai_section}

  </main>
</div>

<div class="footer">
  Generated by <span>Recon47</span> v{meta.get("version","1.0.0")} &nbsp;|&nbsp;
  Author: <span>{meta.get("author","0xMasruful")}</span> &nbsp;|&nbsp;
  {meta.get("timestamp","")} &nbsp;|&nbsp;
  <span style="color:var(--red)">For authorized use only</span>
</div>

<script>
function toggleSection(titleEl) {{
  titleEl.classList.toggle('open');
  const body = titleEl.nextElementSibling;
  body.classList.toggle('collapsed');
}}

function filterVulns(sev, btnEl) {{
  // Update button styles
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');

  // Filter cards
  document.querySelectorAll('.vuln-card').forEach(card => {{
    if (sev === 'ALL' || card.dataset.sev === sev) {{
      card.style.display = '';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}

// Smooth scroll for nav
document.querySelectorAll('.nav a').forEach(a => {{
  a.addEventListener('click', e => {{
    e.preventDefault();
    const target = document.querySelector(a.getAttribute('href'));
    if (target) target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
  }});
}});

// Highlight active nav link on scroll
const sections = document.querySelectorAll('section[id], div[id]');
const navLinks = document.querySelectorAll('.nav a');
window.addEventListener('scroll', () => {{
  let current = '';
  sections.forEach(s => {{
    if (window.scrollY + 100 >= s.offsetTop) current = s.id;
  }});
  navLinks.forEach(a => {{
    a.style.color = a.getAttribute('href') === '#' + current ? 'var(--green)' : '';
    a.style.borderLeftColor = a.getAttribute('href') === '#' + current ? 'var(--green)' : '';
  }});
}});
</script>
</body>
</html>"""
