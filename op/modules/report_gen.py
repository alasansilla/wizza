"""
Automated Pentest Report Generator — authorized penetration testing only.
Pulls data from c2_server's agents dict / loot / credentials files and
generates a professional HTML report.

Usage:
  from report_gen import generate_report
  html = generate_report(agents, agent_resps, loot_dir, creds_file)
  open("report.html","w").write(html)

Or from start script:
  start report [html|json|csv]
"""
import os, json, time, base64, hashlib, html as _html
from datetime import datetime

# ── Severity scoring heuristics ──────────────────────────────────────────────
def _severity(agent: dict) -> str:
    priv = agent.get("priv","").upper()
    if priv in ("ROOT","SYSTEM","ADMIN","NT AUTHORITY\\SYSTEM"): return "CRITICAL"
    if priv in ("SUDO","WHEEL","DOMAIN ADMIN"): return "HIGH"
    return "MEDIUM"

def _color(sev: str) -> str:
    return {"CRITICAL":"#ff3a3a","HIGH":"#ff8c00","MEDIUM":"#ffd700","LOW":"#4caf50"}.get(sev,"#aaa")


# ── HTML report ───────────────────────────────────────────────────────────────
def generate_html(agents: dict, agent_resps: dict,
                   loot_dir: str = "", creds_file: str = "",
                   title: str = "WiZZA Pentest Report",
                   engagement: str = "", operator: str = "") -> str:
    ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_str = datetime.now().strftime("%B %d, %Y")

    # Build findings list
    findings = []
    for aid, a in agents.items():
        sev = _severity(a)
        findings.append({
            "agent_id": aid,
            "host": a.get("hostname","?"),
            "ip": a.get("ip","?"),
            "user": a.get("user","?"),
            "priv": a.get("priv","?"),
            "os": a.get("os","?"),
            "type": a.get("type","?"),
            "first_seen": a.get("first_seen","?"),
            "last_seen": a.get("last_seen","?"),
            "persist": a.get("persist_methods",[]),
            "spread": a.get("spread_log",[]),
            "severity": sev,
        })

    # Summary stats
    total_hosts = len(agents)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high      = sum(1 for f in findings if f["severity"] == "HIGH")
    medium    = sum(1 for f in findings if f["severity"] == "MEDIUM")

    # Count creds
    cred_count = 0
    creds_html = ""
    if creds_file and os.path.exists(creds_file):
        lines = open(creds_file).readlines()
        cred_count = len(lines)
        for line in lines[-50:]:
            parts = {}
            [parts.__setitem__(*(tok.split("=",1))) for tok in line.strip().split("  ") if "=" in tok]
            u = _html.escape(parts.get("user","?").strip("'"))
            p = _html.escape(parts.get("pass","?").strip("'"))
            s = _html.escape(parts.get("src","?"))
            creds_html += f"<tr><td>{u}</td><td>{p}</td><td>{s}</td></tr>"

    # Count loot
    loot_count = 0
    loot_html  = ""
    if loot_dir and os.path.isdir(loot_dir):
        files = sorted(os.listdir(loot_dir), reverse=True)[:30]
        loot_count = len(os.listdir(loot_dir))
        for f in files:
            fp = os.path.join(loot_dir, f)
            sz = os.path.getsize(fp) // 1024
            ext = f.lower()
            if ext.endswith((".png",".jpg",".jpeg")):
                loot_html += f"<li><img src='/loot/dl/{_html.escape(f)}' style='max-width:200px;max-height:150px;border:1px solid #333'><br>{_html.escape(f)} ({sz}KB)</li>"
            else:
                loot_html += f"<li><a href='/loot/dl/{_html.escape(f)}'>{_html.escape(f)}</a> ({sz}KB)</li>"

    # Agent rows
    agent_rows = ""
    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"])):
        color = _color(f["severity"])
        persist_str = ", ".join(f["persist"]) or "—"
        spread_str  = f"{len(f['spread'])} hosts" if f["spread"] else "—"
        agent_rows += f"""<tr>
<td><span style="color:{color};font-weight:700">{f["severity"]}</span></td>
<td style="font-family:monospace">{_html.escape(f["agent_id"])}</td>
<td>{_html.escape(f["host"])}</td>
<td>{_html.escape(f["ip"])}</td>
<td>{_html.escape(f["user"])}</td>
<td style="color:{color};font-weight:bold">{_html.escape(f["priv"])}</td>
<td style="font-size:11px">{_html.escape(f["os"][:60])}</td>
<td>{_html.escape(persist_str[:60])}</td>
<td>{spread_str}</td>
<td>{_html.escape(f["first_seen"])}</td>
</tr>"""

    # Command output section
    output_html = ""
    for aid, resps in agent_resps.items():
        for r in resps[-4:]:
            cmd  = _html.escape(r.get("cmd","?")[:80])
            resp = _html.escape(r.get("resp","")[:2000])
            ts_r = _html.escape(r.get("ts","?"))
            output_html += f"""<div style="margin-bottom:16px;background:#1a1a1a;border:1px solid #333;border-radius:5px;overflow:hidden">
<div style="padding:6px 12px;background:#222;font-size:12px;color:#888">
  <span style="color:#4af">[{_html.escape(aid)}]</span>
  <span style="color:#fa0;margin-left:8px">{cmd}</span>
  <span style="float:right;color:#555">{ts_r}</span>
</div>
<pre style="padding:10px 12px;font-size:11px;color:#9f9;white-space:pre-wrap;max-height:200px;overflow:auto;margin:0">{resp}</pre>
</div>"""

    # Executive summary
    risk_rating = "CRITICAL" if critical else ("HIGH" if high else "MEDIUM")
    risk_color  = _color(risk_rating)

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_html.escape(title)}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0 }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d0d0d; color: #e0e0e0; font-size: 13px }}
.page {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px }}
.cover {{ text-align: center; padding: 60px 0 40px; border-bottom: 2px solid #222; margin-bottom: 40px }}
.cover h1 {{ font-size: 32px; color: #4af; letter-spacing: 2px; margin-bottom: 8px }}
.cover .sub {{ color: #888; font-size: 14px; margin-bottom: 24px }}
.cover .meta {{ color: #aaa; font-size: 12px }}
.risk-badge {{ display: inline-block; padding: 8px 24px; border-radius: 20px; font-size: 16px;
               font-weight: 700; border: 2px solid; margin: 16px 0 }}
.section {{ margin-bottom: 40px }}
.section h2 {{ font-size: 18px; color: #4af; border-bottom: 1px solid #333; padding-bottom: 8px;
               margin-bottom: 16px; letter-spacing: 1px }}
.section h3 {{ font-size: 14px; color: #ccc; margin: 12px 0 8px }}
.stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px }}
.stat {{ background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px 24px;
         text-align: center; min-width: 120px }}
.stat .n {{ font-size: 28px; font-weight: 700 }}
.stat .l {{ font-size: 11px; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px }}
th {{ background: #1a1a1a; color: #4af; padding: 8px 10px; text-align: left;
      border: 1px solid #333; font-size: 11px; letter-spacing: .5px; text-transform: uppercase }}
td {{ padding: 7px 10px; border: 1px solid #2a2a2a; font-size: 12px; vertical-align: middle }}
tr:hover td {{ background: rgba(255,255,255,.03) }}
.crit {{ color: #ff3a3a }} .high {{ color: #ff8c00 }} .med {{ color: #ffd700 }}
.finding {{ background: #111; border: 1px solid #222; border-left: 4px solid; border-radius: 4px;
             padding: 16px; margin-bottom: 16px }}
.finding h4 {{ font-size: 13px; margin-bottom: 8px }}
.finding p {{ color: #aaa; font-size: 12px; line-height: 1.6 }}
ul.loot {{ list-style: none; display: flex; flex-wrap: wrap; gap: 12px }}
ul.loot li {{ background: #1a1a1a; border: 1px solid #333; padding: 8px; border-radius: 4px;
               font-size: 11px; text-align: center }}
ul.loot li a {{ color: #4af }}
.footer {{ text-align: center; color: #444; font-size: 11px; margin-top: 40px; padding-top: 20px;
            border-top: 1px solid #222 }}
@media print {{ body{{ background:#fff;color:#000 }} table{{ font-size:10px }} }}
</style>
</head>
<body>
<div class="page">

<!-- ── Cover ────────────────────────────────────────────── -->
<div class="cover">
  <h1>{_html.escape(title)}</h1>
  <div class="sub">Authorized Penetration Test — Confidential</div>
  <div class="risk-badge" style="color:{risk_color};border-color:{risk_color}">
    OVERALL RISK: {risk_rating}
  </div>
  <div class="meta">
    {"Engagement: " + _html.escape(engagement) + " &nbsp;|&nbsp;" if engagement else ""}
    {"Operator: " + _html.escape(operator) + " &nbsp;|&nbsp;" if operator else ""}
    Generated: {ts_now}
  </div>
</div>

<!-- ── Executive Summary ─────────────────────────────────── -->
<div class="section">
  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat"><div class="n" style="color:#4af">{total_hosts}</div><div class="l">Hosts Compromised</div></div>
    <div class="stat"><div class="n crit">{critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n high">{high}</div><div class="l">High</div></div>
    <div class="stat"><div class="n med">{medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:#e0e0e0">{cred_count}</div><div class="l">Credentials</div></div>
    <div class="stat"><div class="n" style="color:#e0e0e0">{loot_count}</div><div class="l">Loot Files</div></div>
  </div>

  <div class="finding" style="border-left-color:{risk_color}">
    <h4 style="color:{risk_color}">Risk Rating: {risk_rating}</h4>
    <p>
      {total_hosts} system(s) were successfully compromised during this engagement.
      {"A CRITICAL severity finding indicates full system/domain compromise with SYSTEM or root access." if critical else ""}
      {"Credential capture and persistence mechanisms were established." if cred_count > 0 else ""}
      {"Active spreading was observed across " + str(sum(len(f["spread"]) for f in findings)) + " additional targets." if any(f["spread"] for f in findings) else ""}
    </p>
  </div>
</div>

<!-- ── Compromised Hosts ──────────────────────────────────── -->
<div class="section">
  <h2>Compromised Hosts ({total_hosts})</h2>
  <table>
    <tr><th>Severity</th><th>Agent ID</th><th>Hostname</th><th>IP</th><th>User</th>
        <th>Privilege</th><th>OS</th><th>Persistence</th><th>Spread</th><th>First Seen</th></tr>
    {agent_rows if agent_rows else "<tr><td colspan='10' style='color:#666;text-align:center;padding:20px'>No agents recorded</td></tr>"}
  </table>
</div>

<!-- ── Captured Credentials ──────────────────────────────── -->
<div class="section">
  <h2>Captured Credentials ({cred_count})</h2>
  {"<table><tr><th>Username</th><th>Password</th><th>Source</th></tr>" + creds_html + "</table>" if creds_html else "<p style='color:#555'>No credentials captured.</p>"}
</div>

<!-- ── Loot Files ─────────────────────────────────────────── -->
<div class="section">
  <h2>Exfiltrated Loot ({loot_count} files)</h2>
  {"<ul class='loot'>" + loot_html + "</ul>" if loot_html else "<p style='color:#555'>No loot files.</p>"}
</div>

<!-- ── Command Output ─────────────────────────────────────── -->
<div class="section">
  <h2>Command Output Log</h2>
  {output_html if output_html else "<p style='color:#555'>No command output recorded.</p>"}
</div>

<!-- ── Remediation Recommendations ──────────────────────── -->
<div class="section">
  <h2>Recommendations</h2>
  <table>
    <tr><th>#</th><th>Finding</th><th>Recommendation</th><th>Priority</th></tr>
    <tr><td>1</td><td>Credential capture via phishing portal</td>
        <td>Implement MFA, security awareness training, FIDO2 hardware keys</td>
        <td class="crit">CRITICAL</td></tr>
    <tr><td>2</td><td>Persistence via registry/cron/services</td>
        <td>Endpoint Detection & Response (EDR), application whitelisting (AppLocker/Wdac)</td>
        <td class="high">HIGH</td></tr>
    <tr><td>3</td><td>Lateral movement via SSH/SMB</td>
        <td>Network segmentation, disable SMBv1, SSH key management, just-in-time access</td>
        <td class="high">HIGH</td></tr>
    <tr><td>4</td><td>USB spreading</td>
        <td>Disable USB autorun, DLP, endpoint USB blocking via GPO</td>
        <td class="med">MEDIUM</td></tr>
    <tr><td>5</td><td>LLMNR/NBT-NS credential capture</td>
        <td>Disable LLMNR/NBT-NS via GPO, enable SMB signing, deploy LAPS</td>
        <td class="high">HIGH</td></tr>
    <tr><td>6</td><td>Browser credential exfiltration</td>
        <td>Password manager policy, browser lockdown, credential guard</td>
        <td class="high">HIGH</td></tr>
  </table>
</div>

<div class="footer">
  {_html.escape(title)} &nbsp;|&nbsp; {date_str} &nbsp;|&nbsp; Generated by WiZZA C2 &nbsp;|&nbsp; CONFIDENTIAL
</div>
</div>
</body>
</html>"""

    return html_out


# ── JSON report ───────────────────────────────────────────────────────────────
def generate_json(agents: dict, agent_resps: dict,
                   loot_dir: str = "", creds_file: str = "") -> str:
    creds = []
    if creds_file and os.path.exists(creds_file):
        for line in open(creds_file).readlines():
            parts = {}
            [parts.__setitem__(*(tok.split("=",1))) for tok in line.strip().split("  ") if "=" in tok]
            creds.append({"user": parts.get("user","?").strip("'"),
                           "pass": parts.get("pass","?").strip("'"),
                           "src":  parts.get("src","?")})

    loot = []
    if loot_dir and os.path.isdir(loot_dir):
        for f in os.listdir(loot_dir):
            loot.append({"file": f, "size": os.path.getsize(os.path.join(loot_dir, f))})

    report = {
        "generated": datetime.now().isoformat(),
        "summary": {
            "total_hosts": len(agents),
            "critical": sum(1 for a in agents.values() if _severity(a) == "CRITICAL"),
            "credentials": len(creds),
            "loot_files": len(loot),
        },
        "agents": {
            aid: {**{k:v for k,v in a.items() if k != "log"},
                  "severity": _severity(a)}
            for aid, a in agents.items()
        },
        "credentials": creds[:200],
        "loot": loot,
    }
    return json.dumps(report, indent=2, default=str)


# ── CSV report ────────────────────────────────────────────────────────────────
def generate_csv(agents: dict) -> str:
    lines = ["severity,agent_id,hostname,ip,user,privilege,os,type,first_seen,last_seen"]
    for aid, a in agents.items():
        sev = _severity(a)
        def esc(v): return '"' + str(v).replace('"','""') + '"'
        lines.append(",".join([esc(sev), esc(aid), esc(a.get("hostname","?")),
                                esc(a.get("ip","?")), esc(a.get("user","?")),
                                esc(a.get("priv","?")), esc(a.get("os","?")[:60]),
                                esc(a.get("type","?")), esc(a.get("first_seen","?")),
                                esc(a.get("last_seen","?"))]))
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────
def generate_report(agents: dict, agent_resps: dict = None,
                     loot_dir: str = "", creds_file: str = "",
                     fmt: str = "html", **kwargs) -> str:
    agent_resps = agent_resps or {}
    if fmt == "json":
        return generate_json(agents, agent_resps, loot_dir, creds_file)
    if fmt == "csv":
        return generate_csv(agents)
    return generate_html(agents, agent_resps, loot_dir, creds_file, **kwargs)
