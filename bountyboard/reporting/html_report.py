"""HTML report generator — self-contained dark-theme report with interactive features."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BountyBoard Report — {generated_at}</title>
<style>
  :root {{
    --bg: #0a0e17;
    --bg2: #111827;
    --bg3: #1f2937;
    --border: #2d3748;
    --accent: #00d4aa;
    --accent2: #0080ff;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --critical: #ef4444;
    --high: #f59e0b;
    --medium: #3b82f6;
    --low: #6b7280;
    --success: #10b981;
    --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
    --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Layout */
  .sidebar {{ position: fixed; left: 0; top: 0; width: 220px; height: 100vh; background: var(--bg2); border-right: 1px solid var(--border); padding: 20px 0; overflow-y: auto; z-index: 100; }}
  .main {{ margin-left: 220px; padding: 30px 40px; max-width: 1400px; }}
  .sidebar-logo {{ padding: 0 20px 20px; border-bottom: 1px solid var(--border); margin-bottom: 15px; }}
  .sidebar-logo h2 {{ color: var(--accent); font-size: 18px; font-weight: 800; letter-spacing: 2px; }}
  .sidebar-logo p {{ color: var(--text-dim); font-size: 11px; margin-top: 4px; }}
  .nav-section {{ padding: 0 20px; margin-bottom: 8px; }}
  .nav-section h3 {{ color: var(--text-dim); font-size: 10px; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 6px; }}
  .nav-link {{ display: block; padding: 6px 10px; border-radius: 6px; color: var(--text); font-size: 13px; cursor: pointer; transition: all 0.15s; margin-bottom: 2px; }}
  .nav-link:hover {{ background: var(--bg3); color: var(--accent); }}
  .nav-link.active {{ background: var(--bg3); color: var(--accent); border-left: 3px solid var(--accent); }}

  /* Header */
  .page-header {{ margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
  .page-header h1 {{ font-size: 28px; font-weight: 800; color: var(--accent); letter-spacing: -0.5px; }}
  .page-header p {{ color: var(--text-dim); margin-top: 6px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}

  /* Stats cards */
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 30px; }}
  .stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 20px; transition: border-color 0.2s; }}
  .stat-card:hover {{ border-color: var(--accent); }}
  .stat-card .value {{ font-size: 32px; font-weight: 800; line-height: 1; }}
  .stat-card .label {{ color: var(--text-dim); font-size: 12px; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat-critical {{ border-left: 4px solid var(--critical); }}
  .stat-high {{ border-left: 4px solid var(--high); }}
  .stat-medium {{ border-left: 4px solid var(--medium); }}
  .stat-low {{ border-left: 4px solid var(--low); }}
  .stat-accent {{ border-left: 4px solid var(--accent); }}

  /* Tables */
  .table-wrap {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 24px; }}
  .table-header {{ padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }}
  .table-header h3 {{ font-size: 14px; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ padding: 10px 16px; text-align: left; font-size: 11px; font-weight: 600; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); background: var(--bg3); }}
  td {{ padding: 10px 16px; border-bottom: 1px solid #1a2233; font-size: 13px; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .mono {{ font-family: var(--mono); font-size: 12px; }}

  /* Severity badges */
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
  .sev-CRITICAL {{ background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }}
  .sev-HIGH {{ background: rgba(245,158,11,0.15); color: var(--high); border: 1px solid rgba(245,158,11,0.3); }}
  .sev-MEDIUM {{ background: rgba(59,130,246,0.15); color: var(--medium); border: 1px solid rgba(59,130,246,0.3); }}
  .sev-LOW {{ background: rgba(107,114,128,0.15); color: var(--low); border: 1px solid rgba(107,114,128,0.3); }}

  /* Section */
  .section {{ margin-bottom: 40px; }}
  .section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 16px; color: var(--text); display: flex; align-items: center; gap: 10px; }}
  .section-title::after {{ content: ''; flex: 1; height: 1px; background: var(--border); }}

  /* Collapsible */
  .collapsible {{ cursor: pointer; }}
  .collapsible .toggle {{ transition: transform 0.2s; display: inline-block; }}
  .collapsible.collapsed .toggle {{ transform: rotate(-90deg); }}
  .collapsible-content {{ overflow: hidden; transition: max-height 0.3s ease; }}
  .collapsible.collapsed .collapsible-content {{ max-height: 0 !important; }}

  /* Search */
  .search-bar {{ width: 100%; padding: 10px 14px; background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 13px; margin-bottom: 16px; outline: none; }}
  .search-bar:focus {{ border-color: var(--accent); }}

  /* Snippet */
  .snippet {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-family: var(--mono); font-size: 11px; color: #94a3b8; white-space: pre-wrap; word-break: break-all; max-height: 80px; overflow: hidden; cursor: pointer; }}
  .snippet:hover {{ max-height: 300px; color: var(--text); }}

  /* Copy button */
  .copy-btn {{ display: inline-block; padding: 3px 8px; background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; color: var(--text-dim); cursor: pointer; transition: all 0.15s; font-family: var(--mono); }}
  .copy-btn:hover {{ background: var(--accent); color: var(--bg); border-color: var(--accent); }}

  /* Screenshots */
  .screenshots-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }}
  .screenshot-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; transition: transform 0.2s, border-color 0.2s; cursor: pointer; }}
  .screenshot-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
  .screenshot-card img {{ width: 100%; height: 180px; object-fit: cover; object-position: top; }}
  .screenshot-card .info {{ padding: 10px 12px; }}
  .screenshot-card .url {{ font-family: var(--mono); font-size: 11px; color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

  /* Lightbox */
  .lightbox {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 999; justify-content: center; align-items: center; cursor: zoom-out; }}
  .lightbox.active {{ display: flex; }}
  .lightbox img {{ max-width: 95vw; max-height: 95vh; border-radius: 8px; }}

  /* Charts */
  .chart-bar-wrap {{ display: flex; flex-direction: column; gap: 8px; }}
  .chart-row {{ display: flex; align-items: center; gap: 12px; }}
  .chart-label {{ width: 120px; font-size: 12px; color: var(--text-dim); text-align: right; flex-shrink: 0; }}
  .chart-bar-bg {{ flex: 1; background: var(--bg3); border-radius: 4px; height: 22px; overflow: hidden; }}
  .chart-bar {{ height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 11px; font-weight: 600; transition: width 0.8s ease; min-width: 30px; }}
  .chart-count {{ width: 50px; text-align: right; font-family: var(--mono); font-size: 12px; color: var(--text-dim); }}

  /* Buttons */
  .btn {{ display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); font-size: 13px; cursor: pointer; transition: all 0.15s; }}
  .btn:hover {{ background: var(--accent); color: var(--bg); border-color: var(--accent); }}
  .btn-group {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }}

  /* Filter tabs */
  .filter-tabs {{ display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }}
  .filter-tab {{ padding: 5px 14px; border-radius: 20px; border: 1px solid var(--border); background: var(--bg3); color: var(--text-dim); font-size: 12px; cursor: pointer; transition: all 0.15s; }}
  .filter-tab:hover, .filter-tab.active {{ background: var(--accent); color: var(--bg); border-color: var(--accent); }}

  /* Scrollbar */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}

  /* Tags */
  .tag {{ display: inline-block; padding: 1px 6px; background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; color: var(--text-dim); margin: 1px; }}

  /* Responsive */
  @media (max-width: 768px) {{
    .sidebar {{ display: none; }}
    .main {{ margin-left: 0; padding: 20px; }}
  }}
</style>
</head>
<body>

<!-- Sidebar -->
<nav class="sidebar">
  <div class="sidebar-logo">
    <h2>BOUNTYBOARD</h2>
    <p>Generated {generated_at}</p>
  </div>
  <div class="nav-section">
    <h3>Overview</h3>
    <a class="nav-link active" onclick="showSection('dashboard')">📊 Dashboard</a>
    <a class="nav-link" onclick="showSection('findings')">🚨 Findings</a>
    <a class="nav-link" onclick="showSection('subdomains')">🌐 Subdomains</a>
    <a class="nav-link" onclick="showSection('services')">⚡ Services</a>
    <a class="nav-link" onclick="showSection('screenshots')">📸 Screenshots</a>
    <a class="nav-link" onclick="showSection('analytics')">📈 Analytics</a>
  </div>
  <div class="nav-section" style="margin-top:20px;">
    <h3>Programs</h3>
    {program_nav}
  </div>
</nav>

<!-- Main Content -->
<div class="main">

  <!-- Dashboard -->
  <div id="section-dashboard" class="section">
    <div class="page-header">
      <h1>Morning Brief</h1>
      <p>Attack surface intelligence — {generated_at}</p>
    </div>

    <div class="stats-grid">
      <div class="stat-card stat-accent">
        <div class="value">{total_subdomains}</div>
        <div class="label">Total Subdomains</div>
      </div>
      <div class="stat-card stat-accent">
        <div class="value">{total_services}</div>
        <div class="label">Live Services</div>
      </div>
      <div class="stat-card" style="border-left-color:#10b981">
        <div class="value" style="color:#10b981">{new_subdomains}</div>
        <div class="label">New This Run</div>
      </div>
      <div class="stat-card stat-critical">
        <div class="value" style="color:var(--critical)">{findings_critical}</div>
        <div class="label">Critical Findings</div>
      </div>
      <div class="stat-card stat-high">
        <div class="value" style="color:var(--high)">{findings_high}</div>
        <div class="label">High Findings</div>
      </div>
      <div class="stat-card stat-medium">
        <div class="value" style="color:var(--medium)">{findings_medium}</div>
        <div class="label">Medium Findings</div>
      </div>
    </div>

    <!-- Recommendations -->
    {recommendations_html}

    <!-- Critical findings preview -->
    <div class="section-title">🚨 Critical Findings</div>
    {critical_table}
  </div>

  <!-- Findings -->
  <div id="section-findings" class="section" style="display:none">
    <div class="section-title">All Findings</div>
    <div class="btn-group">
      <button class="btn" onclick="exportData('json')">⬇️ Export JSON</button>
      <button class="btn" onclick="exportData('csv')">⬇️ Export CSV</button>
      <button class="btn" onclick="exportData('markdown')">⬇️ Export Markdown</button>
    </div>
    <input class="search-bar" type="text" id="findings-search"
           placeholder="🔍 Filter findings by URL, check name, severity..."
           oninput="filterFindings()">
    <div class="filter-tabs">
      <span class="filter-tab active" onclick="filterBySev('ALL')">All ({total_findings})</span>
      <span class="filter-tab" onclick="filterBySev('CRITICAL')" style="color:var(--critical)">🚨 Critical ({findings_critical})</span>
      <span class="filter-tab" onclick="filterBySev('HIGH')" style="color:var(--high)">⚠️ High ({findings_high})</span>
      <span class="filter-tab" onclick="filterBySev('MEDIUM')" style="color:var(--medium)">🔵 Medium ({findings_medium})</span>
      <span class="filter-tab" onclick="filterBySev('LOW')">⬜ Low ({findings_low})</span>
    </div>
    {all_findings_table}
  </div>

  <!-- Subdomains -->
  <div id="section-subdomains" class="section" style="display:none">
    <div class="section-title">Subdomain Inventory</div>
    <input class="search-bar" type="text" id="sub-search"
           placeholder="🔍 Filter subdomains..."
           oninput="filterTable('sub-search', 'subdomains-table')">
    {subdomains_table}
  </div>

  <!-- Services -->
  <div id="section-services" class="section" style="display:none">
    <div class="section-title">Live Services</div>
    <input class="search-bar" type="text" id="svc-search"
           placeholder="🔍 Filter services by URL, technology, status..."
           oninput="filterTable('svc-search', 'services-table')">
    {services_table}
  </div>

  <!-- Screenshots -->
  <div id="section-screenshots" class="section" style="display:none">
    <div class="section-title">Screenshots</div>
    <div class="screenshots-grid">
      {screenshots_html}
    </div>
  </div>

  <!-- Analytics -->
  <div id="section-analytics" class="section" style="display:none">
    <div class="section-title">Analytics</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">
      <div class="table-wrap" style="padding:20px;">
        <h3 style="margin-bottom:16px;font-size:14px;">Findings by Severity</h3>
        {severity_chart}
      </div>
      <div class="table-wrap" style="padding:20px;">
        <h3 style="margin-bottom:16px;font-size:14px;">Technology Distribution</h3>
        {tech_chart}
      </div>
      <div class="table-wrap" style="padding:20px;">
        <h3 style="margin-bottom:16px;font-size:14px;">Discovery Sources</h3>
        {source_chart}
      </div>
      <div class="table-wrap" style="padding:20px;">
        <h3 style="margin-bottom:16px;font-size:14px;">HTTP Status Codes</h3>
        {status_chart}
      </div>
    </div>
  </div>

</div><!-- /main -->

<!-- Lightbox -->
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
  <img id="lightbox-img" src="" alt="">
</div>

<script>
// --- Data ---
const FINDINGS = {findings_json};
const SUBDOMAINS = {subdomains_json};
const SERVICES = {services_json};

let currentSevFilter = 'ALL';

// --- Navigation ---
function showSection(name) {{
  document.querySelectorAll('[id^="section-"]').forEach(el => el.style.display = 'none');
  document.getElementById('section-' + name).style.display = '';
  document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
  event.target.classList.add('active');
}}

// --- Filtering ---
function filterFindings() {{
  const q = document.getElementById('findings-search').value.toLowerCase();
  document.querySelectorAll('#all-findings-table tbody tr').forEach(row => {{
    const text = row.textContent.toLowerCase();
    const sev = row.dataset.sev || '';
    const matchQ = !q || text.includes(q);
    const matchSev = currentSevFilter === 'ALL' || sev === currentSevFilter;
    row.style.display = (matchQ && matchSev) ? '' : 'none';
  }});
}}

function filterBySev(sev) {{
  currentSevFilter = sev;
  document.querySelectorAll('.filter-tab').forEach(el => el.classList.remove('active'));
  event.target.classList.add('active');
  filterFindings();
}}

function filterTable(inputId, tableId) {{
  const q = document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(row => {{
    row.style.display = !q || row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}

// --- Copy curl ---
function copyCurl(url) {{
  const cmd = `curl -sk "${{url}}" | head -c 2000`;
  navigator.clipboard.writeText(cmd).then(() => {{
    event.target.textContent = 'copied!';
    setTimeout(() => event.target.textContent = 'curl', 2000);
  }});
}}

// --- Lightbox ---
function openLightbox(src) {{
  document.getElementById('lightbox-img').src = src;
  document.getElementById('lightbox').classList.add('active');
}}
function closeLightbox() {{
  document.getElementById('lightbox').classList.remove('active');
}}

// --- Export ---
function exportData(format) {{
  let content = '', type = '', ext = '';
  if (format === 'json') {{
    content = JSON.stringify(FINDINGS, null, 2);
    type = 'application/json'; ext = 'json';
  }} else if (format === 'csv') {{
    const headers = ['severity','check_name','url','status_code','found_at'];
    const rows = FINDINGS.map(f => headers.map(h => JSON.stringify(f[h] || '')).join(','));
    content = [headers.join(','), ...rows].join('\\n');
    type = 'text/csv'; ext = 'csv';
  }} else {{
    content = '# BountyBoard Findings\\n\\n';
    FINDINGS.forEach(f => {{
      content += `## [${{f.severity}}] ${{f.check_name}}\\n- URL: ${{f.url}}\\n- Status: ${{f.status_code}}\\n- Found: ${{f.found_at}}\\n\\n`;
    }});
    type = 'text/markdown'; ext = 'md';
  }}
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], {{type}}));
  a.download = `bountyboard-findings.${{ext}}`;
  a.click();
}}

// --- Sortable tables ---
document.querySelectorAll('th[data-sort]').forEach(th => {{
  th.style.cursor = 'pointer';
  th.addEventListener('click', () => {{
    const table = th.closest('table');
    const col = Array.from(th.parentElement.children).indexOf(th);
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const asc = th.dataset.dir !== 'asc';
    th.dataset.dir = asc ? 'asc' : 'desc';
    rows.sort((a, b) => {{
      const av = a.cells[col].textContent.trim();
      const bv = b.cells[col].textContent.trim();
      return asc ? av.localeCompare(bv, undefined, {{numeric: true}}) : bv.localeCompare(av, undefined, {{numeric: true}});
    }});
    rows.forEach(r => tbody.appendChild(r));
  }});
}});
</script>
</body>
</html>"""


def _severity_color(sev: str) -> str:
    return {"CRITICAL": "#ef4444", "HIGH": "#f59e0b",
            "MEDIUM": "#3b82f6", "LOW": "#6b7280"}.get(sev, "#6b7280")


def _build_findings_table(findings: list[dict], table_id: str = "findings-table") -> str:
    if not findings:
        return "<p style='color:var(--text-dim);padding:20px;'>No findings.</p>"

    rows = []
    for f in findings:
        sev = f.get("severity", "LOW")
        snippet = (f.get("response_snippet") or "")[:120].replace("<", "&lt;").replace(">", "&gt;")
        url = f.get("url", "")
        rows.append(f"""
        <tr data-sev="{sev}">
          <td><span class="sev sev-{sev}">{sev}</span></td>
          <td class="mono">{f.get("check_name", "")}</td>
          <td><a href="{url}" target="_blank" class="mono" style="font-size:12px">{url[:80]}</a></td>
          <td style="text-align:center">{f.get("status_code", "")}</td>
          <td style="text-align:right;font-family:var(--mono);font-size:11px">{f.get("response_size", 0):,}</td>
          <td><div class="snippet" title="Click to expand">{snippet}</div></td>
          <td><button class="copy-btn" onclick="copyCurl('{url}')">curl</button></td>
          <td style="font-size:11px;color:var(--text-dim)">{(f.get("found_at") or "")[:16]}</td>
        </tr>""")

    return f"""
    <div class="table-wrap">
      <table id="{table_id}">
        <thead>
          <tr>
            <th data-sort>SEV</th>
            <th data-sort>CHECK</th>
            <th data-sort>URL</th>
            <th data-sort>STATUS</th>
            <th data-sort>SIZE</th>
            <th>EVIDENCE</th>
            <th>CURL</th>
            <th data-sort>FOUND</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>"""


def _build_bar_chart(items: dict[str, int], colors: dict[str, str] = None) -> str:
    if not items:
        return "<p style='color:var(--text-dim)'>No data</p>"

    max_val = max(items.values()) if items else 1
    rows = []
    default_color = "#00d4aa"

    for label, count in sorted(items.items(), key=lambda x: -x[1]):
        color = (colors or {}).get(label, default_color)
        pct = int((count / max_val) * 100) if max_val else 0
        rows.append(f"""
        <div class="chart-row">
          <div class="chart-label">{label[:15]}</div>
          <div class="chart-bar-bg">
            <div class="chart-bar" style="width:{pct}%;background:{color}">{count}</div>
          </div>
          <div class="chart-count">{count}</div>
        </div>""")

    return f'<div class="chart-bar-wrap">{"".join(rows)}</div>'


def _build_recommendations_html(recs: list[str]) -> str:
    if not recs:
        return ""

    items = []
    for rec in recs:
        icon = "🚨" if "CRITICAL" in rec.upper() else "⚠️" if "HIGH" in rec.upper() else "🔍"
        items.append(f"""
        <div style="display:flex;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border);align-items:flex-start;">
          <span style="font-size:18px;flex-shrink:0">{icon}</span>
          <span style="font-size:13px;line-height:1.5">{rec}</span>
        </div>""")

    return f"""
    <div class="table-wrap" style="margin-bottom:24px;">
      <div class="table-header"><h3>Actionable Recommendations</h3></div>
      {"".join(items)}
    </div>"""


def generate_html_report(data: dict, output_path: str) -> str:
    """Generate a complete HTML report and write to output_path."""

    stats = data.get("stats", {})
    findings = data.get("findings", [])
    subdomains = data.get("subdomains", [])
    services = data.get("services", [])
    recs = data.get("recommendations", [])
    programs = data.get("programs", [])
    screenshots = data.get("screenshots", [])

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Build program nav
    program_nav = "\n".join(
        f'<a class="nav-link" onclick="showSection(\'prog-{i}\')">{p}</a>'
        for i, p in enumerate(programs)
    )

    # Count by severity
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Critical findings table
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    critical_table = _build_findings_table(critical[:20])

    # All findings table
    all_findings_table = _build_findings_table(findings, "all-findings-table")

    # Subdomains table
    sub_rows = []
    for s in subdomains[:2000]:
        sub_rows.append(f"""
        <tr>
          <td class="mono">{s.get("subdomain", "")}</td>
          <td><span class="tag">{s.get("source", "")}</span></td>
          <td style="font-size:11px;color:var(--text-dim)">{(s.get("first_seen") or "")[:16]}</td>
          <td style="font-size:11px;color:var(--text-dim)">{(s.get("last_seen") or "")[:16]}</td>
        </tr>""")

    subdomains_table = f"""
    <div class="table-wrap">
      <table id="subdomains-table">
        <thead><tr><th data-sort>SUBDOMAIN</th><th data-sort>SOURCE</th><th data-sort>FIRST SEEN</th><th data-sort>LAST SEEN</th></tr></thead>
        <tbody>{"".join(sub_rows)}</tbody>
      </table>
    </div>"""

    # Services table
    svc_rows = []
    for s in services[:2000]:
        techs = json.loads(s.get("technologies", "[]") or "[]")
        tech_tags = "".join(f'<span class="tag">{t}</span>' for t in techs[:3])
        svc_rows.append(f"""
        <tr>
          <td><a href="{s.get("url","")}" target="_blank" class="mono" style="font-size:12px">{(s.get("url",""))[:70]}</a></td>
          <td style="text-align:center">{s.get("status_code","")}</td>
          <td class="mono" style="font-size:11px">{s.get("server_header","")[:25]}</td>
          <td>{tech_tags}</td>
          <td style="font-size:11px;color:var(--text-dim)">{(s.get("last_seen") or "")[:16]}</td>
        </tr>""")

    services_table = f"""
    <div class="table-wrap">
      <table id="services-table">
        <thead><tr><th data-sort>URL</th><th data-sort>STATUS</th><th data-sort>SERVER</th><th>TECHNOLOGIES</th><th data-sort>LAST SEEN</th></tr></thead>
        <tbody>{"".join(svc_rows)}</tbody>
      </table>
    </div>"""

    # Screenshots
    shot_cards = []
    for s in screenshots:
        url = s.get("url", "")
        thumb = s.get("thumb_path", s.get("path", ""))
        full = s.get("path", "")
        shot_cards.append(f"""
        <div class="screenshot-card" onclick="openLightbox('{full}')">
          <img src="{thumb}" alt="{url}" onerror="this.src='';this.parentElement.style.display='none'">
          <div class="info"><div class="url">{url}</div></div>
        </div>""")

    screenshots_html = "".join(shot_cards) or "<p style='color:var(--text-dim)'>No screenshots captured.</p>"

    # Charts
    sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#3b82f6", "LOW": "#6b7280"}
    severity_chart = _build_bar_chart(sev_counts, sev_colors)

    tech_counts: dict[str, int] = {}
    for svc in services:
        techs = json.loads(svc.get("technologies", "[]") or "[]")
        for t in techs:
            tech_counts[t] = tech_counts.get(t, 0) + 1
    tech_chart = _build_bar_chart(dict(sorted(tech_counts.items(), key=lambda x: -x[1])[:15]))

    source_counts: dict[str, int] = {}
    for s in subdomains:
        src = s.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    source_chart = _build_bar_chart(source_counts)

    status_counts: dict[str, int] = {}
    for svc in services:
        code = str(svc.get("status_code", "?"))
        status_counts[code] = status_counts.get(code, 0) + 1
    status_chart = _build_bar_chart(status_counts)

    recommendations_html = _build_recommendations_html(recs)

    html = HTML_TEMPLATE.format(
        generated_at=generated_at,
        program_nav=program_nav,
        total_subdomains=f"{stats.get('total_subdomains', 0):,}",
        total_services=f"{stats.get('total_services', 0):,}",
        new_subdomains=f"{stats.get('subdomains_new', 0):,}",
        findings_critical=sev_counts.get("CRITICAL", 0),
        findings_high=sev_counts.get("HIGH", 0),
        findings_medium=sev_counts.get("MEDIUM", 0),
        findings_low=sev_counts.get("LOW", 0),
        total_findings=len(findings),
        critical_table=critical_table,
        all_findings_table=all_findings_table,
        subdomains_table=subdomains_table,
        services_table=services_table,
        screenshots_html=screenshots_html,
        severity_chart=severity_chart,
        tech_chart=tech_chart,
        source_chart=source_chart,
        status_chart=status_chart,
        recommendations_html=recommendations_html,
        findings_json=json.dumps(findings[:5000]),
        subdomains_json=json.dumps(subdomains[:5000]),
        services_json=json.dumps(services[:5000]),
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    return str(output)
