#!/usr/bin/env python3
# BlackIce Command (NetWatch Skin) – Safe Recon/Intel Console (Extended, Dual-Mode)
# For authorized testing only. Non-destructive modules only.

import os, sys, shutil, subprocess, datetime, json, html, time, sqlite3, socket
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.live import Live
from rich.align import Align
from rich.layout import Layout

console = Console()

# ---------------------- Paths & Globals ----------------------
BASE = Path.cwd()
DATA = BASE / "blackice_dossier"
EVID = DATA / "evidence"
SCANS = DATA / "scans"
REPORTS = DATA / "reports"
GRAPH = DATA / "graphs"
MSF = DATA / "msf"
CONFIG = BASE / "config"
CONFIG.mkdir(exist_ok=True)

for d in (DATA, EVID, SCANS, REPORTS, GRAPH, MSF):
    d.mkdir(parents=True, exist_ok=True)

DB = DATA / "case.db"

# === BANNER (unchanged; your fixed ANSI kept) ===
BANNER = """  /$$$$$$$  /$$                     /$$       /$$$$$$                    
| $$__  $$| $$                    | $$      |_  $$_/                    
| $$  \\ $$| $$  /$$$$$$   /$$$$$$$| $$   /$$  | $$    /$$$$$$$  /$$$$$$ 
| $$$$$$$ | $$ |____  $$ /$$_____/| $$  /$$/  | $$   /$$_____/ /$$__  $$
| $$__  $$| $$  /$$$$$$$| $$      | $$$$$$/   | $$  | $$      | $$$$$$$$
| $$  \\ $$| $$ /$$__  $$| $$      | $$_  $$   | $$  | $$      | $$_____/
| $$$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$ \\  $$ /$$$$$$|  $$$$$$$|  $$$$$$$
|_______/ |__/ \\_______/ \\_______/|__/  \\__/|______/ \\_______/ \\_______/
────────────────────────────────────────────────────────────────────────────────
[ NETWATCH CYBER INTELLIGENCE COMMAND SYSTEM ]
  CODE-NAME: BLACKICE COMMAND
  ACCESS LEVEL: ALPHA-PRIME
  LOCATION: OPERATIONS NODE // TYCHO-07
  STATUS: ONLINE – AUTHORIZED OPS CONSOLE
──────────────────────────────────────────────
UNAUTHORIZED ACCESS IS A VIOLATION OF NETWATCH 
STATUTES AND WILL TRIGGER BLACK ICE DEPLOYMENT
──────────────────────────────────────────────"""

def ts(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def ts_file(): return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ---------------------- Config / API Manager (NEW) ----------------------
API_KEYS_PATH = CONFIG / "api_keys.json"   # put keys here
SETTINGS_PATH = CONFIG / "settings.json"   # misc defaults

def load_json(path: Path, default: dict):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return default
    return default

API = load_json(API_KEYS_PATH, default={
    "shodan": "",         # SHODAN_API_KEY
    "censys_id": "",      # CENSYS_API_ID
    "censys_secret": "",  # CENSYS_API_SECRET
    "fofa_email": "",     # FOFA_EMAIL
    "fofa_key": "",       # FOFA_API_KEY
    "ipinfo": "",         # IPINFO_TOKEN
})
SET = load_json(SETTINGS_PATH, default={
    "screenshots_driver": "gowitness",  # or "chromium"
    "geoip_db": str((CONFIG / "GeoLite2-City.mmdb").resolve()),  # optional offline
})

def net_online(host="1.1.1.1", port=53, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

ONLINE = net_online()

def have(tool): return shutil.which(tool) is not None
def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)

# ---------------------- DB Init (unchanged) ----------------------
def db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""CREATE TABLE IF NOT EXISTS project(
        id INTEGER PRIMARY KEY, name TEXT, scope TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS asset(
        id INTEGER PRIMARY KEY, project_id INT, type TEXT, name TEXT, ip TEXT, meta_json TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS service(
        id INTEGER PRIMARY KEY, asset_id INT, port INT, proto TEXT, product TEXT, version TEXT, cpe TEXT, notes TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS evidence(
        id INTEGER PRIMARY KEY, project_id INT, kind TEXT, path TEXT, text TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS finding(
        id INTEGER PRIMARY KEY, asset_id INT, title TEXT, severity TEXT, description TEXT,
        evidence_path TEXT, mitre_json TEXT, recommendations TEXT)""")
    return conn

# ---------------------- UI Skin (unchanged) ----------------------
def boot_sequence():
    console.clear()
    console.print(Panel.fit(BANNER, border_style="cyan", style="bold cyan"))
    steps = [
        "[Establishing secure uplink to NETWATCH C.I.C...]",
        "[Authenticating clearance credentials...]",
        "[Routing through Ghostline relay TYCHO-07...]",
        "[Synchronizing classified ciphersuite...]",
        "[Connection established — Black ICE armed]"
    ]
    with Live(Panel("Initializing...", border_style="blue"), refresh_per_second=12) as live:
        for s in steps:
            live.update(Panel(s, border_style="blue")); time.sleep(0.6)
    console.print()

def header(module_name: str):
    hdr = f"[ BLACKICE COMMAND // NETWATCH OPS ]\nMODULE: {module_name}\nCLEARANCE: ALPHA-PRIME • OPS NODE TYCHO-07"
    console.print(Panel(hdr, border_style="cyan", style="bold cyan"))

def footer_ok(path_note: str | None = None):
    msg = "[BLACKICE COMMAND] Operation complete. Results stored in NetWatch Dossier."
    if path_note:
        msg += f"\n{path_note}"
    console.print(Panel(msg, border_style="green"))

def dep_note(maybe_tools):
    missing = [t for t in maybe_tools if t and not have(t)]
    if missing:
        console.print(Panel(
            f"Optional tools not found: [cyan]{', '.join(missing)}[/cyan]\nInstall to enable richer output.",
            border_style="yellow"))

# ---------------------- Helpers (unchanged) ----------------------
def run_to_file(cmd, outfile: Path, note=None):
    ensure_dir(outfile.parent)
    if note: console.print(Panel(note, border_style="blue"))
    try:
        with open(outfile, "w", encoding="utf-8", errors="ignore") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False, text=True)
    except KeyboardInterrupt:
        console.print(Panel("Cancelled by user.", border_style="yellow"))
    except FileNotFoundError:
        console.print(Panel(f"Command not found: {cmd[0]}", border_style="red"))
    except Exception as e:
        console.print(Panel(f"Unexpected error: {e}", border_style="red"))

def choose_project_id():
    with db() as c:
        rows = c.execute("SELECT id,name,created_at FROM project ORDER BY id DESC").fetchall()
    if not rows:
        console.print(Panel("No projects yet. Create one first.", border_style="yellow")); return None
    tbl = Table(title="Projects", show_lines=True, border_style="cyan")
    tbl.add_column("ID", justify="right"); tbl.add_column("Name"); tbl.add_column("Created")
    valid = []
    for pid, name, created in rows:
        tbl.add_row(str(pid), name, created); valid.append(str(pid))
    console.print(tbl)
    pick = Prompt.ask("Select Project ID", choices=valid)
    return int(pick)

# ---------------------- Core Functions (existing) ----------------------
def create_project():
    header("Create Project")
    name = Prompt.ask("[cyan]Project name[/cyan]")
    scope = Prompt.ask("[cyan]Scope / ROE notes[/cyan]")
    with db() as c:
        c.execute("INSERT INTO project(name,scope,created_at) VALUES(?,?,?)", (name, scope, ts()))
    footer_ok()

def list_projects():
    header("List Projects")
    with db() as c:
        rows = c.execute("SELECT id,name,created_at FROM project ORDER BY id DESC").fetchall()
    tbl = Table(title="Projects", show_lines=True, border_style="cyan")
    tbl.add_column("ID", justify="right"); tbl.add_column("Name"); tbl.add_column("Created")
    for pid, name, created in rows:
        tbl.add_row(str(pid), name, created)
    console.print(tbl); footer_ok()

def add_asset():
    header("Add Asset")
    pid = choose_project_id()
    if not pid: return
    a_type = Prompt.ask("[cyan]Asset type[/cyan]", default="host")
    name = Prompt.ask("[cyan]Asset name[/cyan]")
    ip = Prompt.ask("[cyan]IP (optional)[/cyan]", default="")
    meta = {"notes": Prompt.ask("[cyan]Notes[/cyan]", default="")}
    with db() as c:
        c.execute("INSERT INTO asset(project_id,type,name,ip,meta_json) VALUES(?,?,?,?,?)",
                  (pid, a_type, name, ip, json.dumps(meta)))
    footer_ok()

def list_assets():
    header("List Assets")
    pid = choose_project_id()
    if not pid: return
    with db() as c:
        rows = c.execute("SELECT id,type,name,ip FROM asset WHERE project_id=?",(pid,)).fetchall()
    tbl = Table(title=f"Assets (Project {pid})", show_lines=True, border_style="cyan")
    tbl.add_column("ID", justify="right"); tbl.add_column("Type"); tbl.add_column("Name"); tbl.add_column("IP")
    for rid, typ, nm, ip in rows:
        tbl.add_row(str(rid), typ, nm, ip or "")
    console.print(tbl); footer_ok()

# ---------- Recon & Scans (existing) ----------
def import_nmap_xml():
    header("Import Nmap XML")
    pid = choose_project_id()
    if not pid: return
    xml_path = Prompt.ask("[cyan]Path to Nmap XML[/cyan]")
    p = Path(xml_path)
    if not p.exists():
        console.print(Panel("File not found.", border_style="red")); return
    dst = EVID / f"nmap_{p.name}"; shutil.copy2(p, dst)
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(p); root = tree.getroot()
    except Exception as e:
        console.print(Panel(f"Parse error: {e}", border_style="red")); return
    with db() as c:
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else ""
            hn = ""
            hn_el = host.find("hostnames")
            if hn_el is not None:
                h = hn_el.find("hostname")
                if h is not None: hn = h.get("name","")
            c.execute("INSERT INTO asset(project_id,type,name,ip,meta_json) VALUES(?,?,?,?,?)",
                      (pid,"host",hn or ip or "host",ip,json.dumps({"source":"nmap"})))
            asset_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
            ports = host.find("ports")
            if ports is None: continue
            for pe in ports.findall("port"):
                port = int(pe.get("portid","0")); proto = pe.get("protocol","tcp")
                sv = pe.find("service")
                product = sv.get("product","") if sv is not None else ""
                version = sv.get("version","") if sv is not None else ""
                cpe = ""
                if sv is not None:
                    for cpe_el in sv.findall("cpe"):
                        if cpe_el.text: cpe = cpe_el.text
                c.execute("""INSERT INTO service(asset_id,port,proto,product,version,cpe,notes)
                             VALUES(?,?,?,?,?,?,?)""",
                          (asset_id, port, proto, product, version, cpe, "imported from nmap"))
        c.execute("INSERT INTO evidence(project_id,kind,path,text) VALUES(?,?,?,?)",
                  (pid,"nmap-xml", str(dst), ""))
    footer_ok(f"[cyan]Evidence:[/cyan] {dst}")

def nmap_scan():
    header("Nmap Scan")
    if not have("nmap"):
        console.print(Panel("nmap not found.", border_style="red")); return
    target = Prompt.ask("[cyan]Target (IP/CIDR/host)[/cyan]")
    console.print("\n[yellow]Profiles[/yellow]\n[cyan]1[/cyan] Quick (-T4 -F)\n[cyan]2[/cyan] Intense (-T4 -A -v)\n[cyan]3[/cyan] Vuln (-sV --script vuln)")
    prof = Prompt.ask("Choose", choices=["1","2","3"], default="1")
    out = SCANS / f"nmap_{target.replace('/','_')}_{ts_file()}.txt"
    cmd_map = {
        "1": ["nmap","-T4","-F",target,"-oN",str(out)],
        "2": ["nmap","-T4","-A","-v",target,"-oN",str(out)],
        "3": ["nmap","-sV","--script","vuln",target,"-oN",str(out)],
    }
    run_to_file(cmd_map[prof], out, note=f"Running Nmap → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def port_banner_grab():
    header("Port Banner Grab")
    if not have("nmap"):
        console.print(Panel("nmap not found.", border_style="red")); return
    target = Prompt.ask("[cyan]Target (IP/host)[/cyan]")
    out = SCANS / f"banner_{target.replace('/','_')}_{ts_file()}.txt"
    cmd = ["nmap","-sV","--version-light","-Pn","-T4",target,"-oN",str(out)]
    run_to_file(cmd, out, note=f"Running banner grab → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def gobuster_scan():
    header("Gobuster Scan")
    if not have("gobuster"):
        console.print(Panel("gobuster not found.", border_style="red")); return
    url = Prompt.ask("[cyan]URL (http://example)[/cyan]")
    wordlist = Prompt.ask("[cyan]Wordlist[/cyan]", default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    if not Path(wordlist).exists():
        console.print(Panel(f"Wordlist not found: {wordlist}", border_style="red")); return
    out = SCANS / f"gobuster_{ts_file()}.txt"
    cmd = ["gobuster","dir","-u",url,"-w",wordlist,"-x","php,html,txt,bak"]
    run_to_file(cmd, out, note=f"Running Gobuster → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def wpscan_audit():
    header("WordPress Scan")
    if not have("wpscan"):
        console.print(Panel("wpscan not found.", border_style="red")); return
    url = Prompt.ask("[cyan]WordPress URL[/cyan]")
    api = Prompt.ask("[cyan]WPScan API token (optional)[/cyan]", default="")
    console.print("[yellow]Enums:[/yellow] 1=vp (vuln plugins), 2=vt (vuln themes), 3=u (users). e.g. 1,2")
    enums = Prompt.ask("Choose", default="1,2")
    emap = {"1":"vp","2":"vt","3":"u"}
    sel = "".join(emap.get(x.strip(),"") for x in enums.split(","))
    out = SCANS / f"wpscan_{ts_file()}.txt"
    cmd = ["wpscan","--url",url]
    if api: cmd += ["--api-token",api]
    if sel: cmd += ["-e",sel]
    run_to_file(cmd, out, note=f"Running WPScan → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# ---------- DNS / WHOIS / HTTP / TLS (existing) ----------
def dns_records():
    header("DNS Records")
    if not have("dig"):
        console.print(Panel("dig not found (dnsutils).", border_style="red")); return
    domain = Prompt.ask("[cyan]Domain[/cyan]")
    out = SCANS / f"dns_{domain}_{ts_file()}.txt"
    cmds = [
        ["dig","+short",domain,"A"],
        ["dig","+short",domain,"AAAA"],
        ["dig","+short",domain,"MX"],
        ["dig","+short","TXT",domain],
        ["dig","+short",domain,"NS"],
        ["dig","+short","CAA",domain],
        ["dig","+short","SOA",domain],
        ["dig","+short",f"_dmarc.{domain}","TXT"],
    ]
    with open(out,"w") as f:
        for c in cmds:
            f.write(f"$ {' '.join(c)}\n")
            subprocess.run(c, stdout=f, stderr=subprocess.STDOUT, text=True)
            f.write("\n")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def whois_lookup():
    header("WHOIS Lookup")
    if not have("whois"):
        console.print(Panel("whois not found.", border_style="red")); return
    target = Prompt.ask("[cyan]Domain or IP[/cyan]")
    out = SCANS / f"whois_{target}_{ts_file()}.txt"
    run_to_file(["whois", target], out, note=f"Running WHOIS → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def http_headers_audit():
    header("HTTP Headers Audit")
    if not have("curl"):
        console.print(Panel("curl not found.", border_style="red")); return
    url = Prompt.ask("[cyan]URL (include scheme)[/cyan]")
    out = SCANS / f"http_headers_{ts_file()}.txt"
    cmd = ["curl","-sS","-D","-","-o","/dev/null",url]
    run_to_file(cmd, out, note=f"Fetching headers → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def fetch_robots_sitemap():
    header("Fetch robots.txt & sitemap.xml")
    if not have("curl"):
        console.print(Panel("curl not found.", border_style="red")); return
    base = Prompt.ask("[cyan]Base URL (e.g., https://example.com)[/cyan]")
    out_r = SCANS / f"robots_{ts_file()}.txt"
    out_s = SCANS / f"sitemap_{ts_file()}.xml"
    run_to_file(["curl","-sS",f"{base.rstrip('/')}/robots.txt"], out_r, note=f"robots.txt → {out_r}")
    run_to_file(["curl","-sS",f"{base.rstrip('/')}/sitemap.xml"], out_s, note=f"sitemap.xml → {out_s}")
    footer_ok(f"[cyan]Outputs:[/cyan] {out_r}  |  {out_s}")

def tls_ssl_scan():
    header("TLS/SSL Scan")
    host = Prompt.ask("[cyan]Hostname (example.com)[/cyan]")
    port = Prompt.ask("[cyan]Port[/cyan]", default="443")
    out = SCANS / f"tls_{host}_{port}_{ts_file()}.txt"
    if have("testssl.sh"):
        cmd = ["testssl.sh","--quiet","--sneaky",f"{host}:{port}"]
        run_to_file(cmd,out,note=f"Running testssl.sh → {out}")
    elif have("sslyze"):
        cmd = ["sslyze","--regular",f"{host}:{port}"]
        run_to_file(cmd,out,note=f"Running sslyze → {out}")
    else:
        console.print(Panel("Neither testssl.sh nor sslyze found.", border_style="yellow")); return
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# ---------- Passive Subdomains / Tech Fingerprint (existing) ----------
def passive_subdomains():
    header("Passive Subdomain Recon")
    domain = Prompt.ask("[cyan]Domain[/cyan]")
    out = SCANS / f"subdomains_{domain}_{ts_file()}.txt"
    if have("subfinder"):
        cmd = ["subfinder","-silent","-all","-d",domain]
        run_to_file(cmd, out, note=f"subfinder → {out}")
    elif have("amass"):
        cmd = ["amass","enum","-passive","-d",domain]
        run_to_file(cmd, out, note=f"amass passive → {out}")
    else:
        console.print(Panel("subfinder or amass not found.", border_style="yellow")); return
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def web_tech_fingerprint():
    header("Web Tech Fingerprint")
    url = Prompt.ask("[cyan]URL (http:// or https://)[/cyan]")
    out = SCANS / f"whatweb_{ts_file()}.txt"
    if have("whatweb"):
        run_to_file(["whatweb","-a","3",url], out, note=f"whatweb → {out}")
    elif have("httpx"):
        run_to_file(["httpx","-silent","-title","-tech-detect","-status-code","-u",url], out, note=f"httpx → {out}")
    else:
        console.print(Panel("whatweb or httpx not found.", border_style="yellow")); return
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def nuclei_safe_scan():
    header("Nuclei (Safe Profile)")
    if not have("nuclei"):
        console.print(Panel("nuclei not found.", border_style="red")); return
    url = Prompt.ask("[cyan]Target URL or host[/cyan]")
    out = SCANS / f"nuclei_{ts_file()}.txt"
    cmd = ["nuclei","-u",url,"-severity","info,low,medium","-rl","50","-c","50","-ni","-timeout","5","-o",str(out)]
    run_to_file(cmd, out, note=f"Running nuclei (safe) → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def curl_save_body():
    header("Fetch HTTP Body")
    if not have("curl"):
        console.print(Panel("curl not found.", border_style="red")); return
    url = Prompt.ask("[cyan]URL[/cyan]")
    out = EVID / f"http_body_{ts_file()}.html"
    cmd = ["curl","-sS",url]
    run_to_file(cmd, out, note=f"Saving body → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# ---------- Secrets & SBOM / Vuln (existing) ----------
def secrets_scan_gitleaks():
    header("Secrets Scan (gitleaks)")
    if not have("gitleaks"):
        console.print(Panel("gitleaks not found.", border_style="red")); return
    target = Prompt.ask("[cyan]Path to repo or directory[/cyan]")
    out = SCANS / f"gitleaks_{ts_file()}.json"
    cmd = ["gitleaks","detect","-s",target,"-f","json","-r",str(out)]
    run_to_file(cmd, out, note=f"Running gitleaks → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def sbom_generate_syft():
    header("Generate SBOM (syft)")
    if not have("syft"):
        console.print(Panel("syft not found.", border_style="red")); return
    target = Prompt.ask("[cyan]Path or image (e.g., dir or docker:nginx:latest)[/cyan]")
    out = SCANS / f"sbom_{ts_file()}.json"
    cmd = ["syft", target, "-o", "json"]
    run_to_file(cmd, out, note=f"Running syft → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def sbom_vuln_scan():
    header("SBOM Vulnerability Scan (grype/trivy)")
    sbom_path = Prompt.ask("[cyan]Path to SBOM (JSON from syft)[/cyan]")
    p = Path(sbom_path)
    if not p.exists():
        console.print(Panel("SBOM file not found.", border_style="red")); return
    out = SCANS / f"sbom_vuln_{ts_file()}.txt"
    if have("grype"):
        cmd = ["grype", f"sbom:{str(p)}"]
        run_to_file(cmd, out, note=f"Running grype → {out}")
    elif have("trivy"):
        cmd = ["trivy","sbom",str(p)]
        run_to_file(cmd, out, note=f"Running trivy sbom → {out}")
    else:
        console.print(Panel("Neither grype nor trivy found.", border_style="yellow")); return
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def container_scan_trivy():
    header("Container/Image Scan (trivy)")
    if not have("trivy"):
        console.print(Panel("trivy not found.", border_style="red")); return
    image = Prompt.ask("[cyan]Container image (e.g., nginx:latest)[/cyan]")
    out = SCANS / f"trivy_{image.replace('/','_').replace(':','_')}_{ts_file()}.txt"
    cmd = ["trivy","image","--scanners","vuln,secret,config",image]
    run_to_file(cmd, out, note=f"Running trivy image → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def pip_audit_deps():
    header("Python Dependency Audit (pip-audit)")
    if not have("pip-audit"):
        console.print(Panel("pip-audit not found.", border_style="red")); return
    path = Prompt.ask("[cyan]Project path (with requirements.txt or env)[/cyan]", default=".")
    out = SCANS / f"pip_audit_{ts_file()}.txt"
    cmd = ["pip-audit","-r",str(Path(path)/"requirements.txt")] if (Path(path)/"requirements.txt").exists() else ["pip-audit"]
    run_to_file(cmd, out, note=f"Running pip-audit → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

def npm_audit_deps():
    header("Node Dependency Audit (npm audit)")
    if not have("npm"):
        console.print(Panel("npm not found.", border_style="red")); return
    out = SCANS / f"npm_audit_{ts_file()}.txt"
    cmd = ["npm","audit","--audit-level=low","--json"]
    run_to_file(cmd, out, note=f"Running npm audit → {out}")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# ---------- Findings & Report (existing) ----------
def add_finding():
    header("Add Finding")
    pid = choose_project_id()
    if not pid: return
    with db() as c:
        assets = c.execute("SELECT id,name,ip FROM asset WHERE project_id=?",(pid,)).fetchall()
    if not assets:
        console.print(Panel("No assets in this project yet.", border_style="yellow")); return
    tbl = Table(title="Assets", show_lines=True, border_style="cyan")
    tbl.add_column("ID", justify="right"); tbl.add_column("Name"); tbl.add_column("IP")
    valid = []
    for aid, nm, ip in assets:
        tbl.add_row(str(aid), nm, ip or ""); valid.append(str(aid))
    console.print(tbl)
    aid = int(Prompt.ask("Asset ID", choices=valid))
    title = Prompt.ask("[cyan]Finding title[/cyan]")
    severity = Prompt.ask("[cyan]Severity[/cyan]", choices=["info","low","medium","high","critical"], default="medium")
    desc = Prompt.ask("[cyan]Description[/cyan]")
    evp = Prompt.ask("[cyan]Evidence path (optional)[/cyan]", default="")
    mitre = Prompt.ask("[cyan]MITRE technique IDs (comma separated)[/cyan]", default="")
    recs = Prompt.ask("[cyan]Recommendations[/cyan]", default="Apply patches; least privilege; detections.")
    with db() as c:
        c.execute("""INSERT INTO finding(asset_id,title,severity,description,evidence_path,mitre_json,recommendations)
                     VALUES(?,?,?,?,?,?,?)""",
                  (aid,title,severity,desc,evp,json.dumps([x.strip() for x in mitre.split(",") if x.strip()]),recs))
    footer_ok()

def generate_report():
    header("Generate Report (HTML)")
    pid = choose_project_id()
    if not pid: return
    with db() as c:
        proj = c.execute("SELECT name,scope,created_at FROM project WHERE id=?",(pid,)).fetchone()
        assets = c.execute("SELECT id,type,name,ip FROM asset WHERE project_id=?",(pid,)).fetchall()
        svcs = c.execute("""SELECT a.name,a.ip,s.port,s.proto,s.product,s.version,s.cpe
                            FROM service s JOIN asset a ON a.id=s.asset_id
                            WHERE a.project_id=?""",(pid,)).fetchall()
        findings = c.execute("""SELECT f.title,f.severity,a.name,a.ip,f.description,f.evidence_path,f.mitre_json,f.recommendations
                                FROM finding f JOIN asset a ON a.id=f.asset_id
                                WHERE a.project_id=?""",(pid,)).fetchall()
    def esc(s): return html.escape(s or "")
    rows_assets = "".join(f"<tr><td>{esc(t)}</td><td>{esc(n)}</td><td>{esc(ip or '')}</td></tr>"
                          for _,t,n,ip in assets)
    rows_svcs = "".join(f"<tr><td>{esc(hn)}</td><td>{esc(ip or '')}</td><td>{p}/{esc(proto)}</td><td>{esc(prod)}</td><td>{esc(ver)}</td><td>{esc(cpe)}</td></tr>"
                        for hn,ip,p,proto,prod,ver,cpe in svcs)
    rows_find = ""
    for title, sev, aname, aip, desc, evp, mitre_json, recs in findings:
        tids = ", ".join(json.loads(mitre_json or "[]"))
        rows_find += f"<tr><td>{esc(title)}</td><td>{esc(sev)}</td><td>{esc(aname)}</td><td>{esc(aip or '')}</td><td>{esc(desc)}</td><td>{esc(tids)}</td><td>{esc(recs)}</td><td>{esc(evp or '')}</td></tr>"
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>BLACKICE COMMAND – NetWatch Dossier</title>
<style>
body{{background:#0a0f14;color:#d5f3ff;font-family:Consolas,monospace}}
h1,h2{{color:#7ad1ff}} table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{border:1px solid #1e2a36;padding:6px}} th{{background:#11202b}}
.badge{{display:inline-block;padding:2px 6px;border:1px solid #2b6f91;margin-left:8px}}
.header{{white-space:pre;line-height:1.2;border:1px solid #1e2a36;padding:10px;background:#0c1520}}
.code{{background:#0c1520;border:1px solid #1e2a36;padding:10px}}
</style></head><body>
<div class="header">{html.escape(BANNER)}</div>
<h1>BLACKICE COMMAND – Operational Dossier</h1>
<p><b>Project:</b> {esc(proj[0])} &nbsp; <b>Created:</b> {esc(proj[2])}</p>
<p><b>Scope/ROE:</b><br><div class="code">{esc(proj[1])}</div></p>
<h2>Assets</h2>
<table><tr><th>Type</th><th>Name</th><th>IP</th></tr>{rows_assets}</table>
<h2>Services</h2>
<table><tr><th>Host</th><th>IP</th><th>Port/Proto</th><th>Product</th><th>Version</th><th>CPE</th></tr>{rows_svcs}</table>
<h2>Findings</h2>
<table><tr><th>Title</th><th>Severity</th><th>Asset</th><th>IP</th><th>Description</th><th>MITRE</th><th>Recommendations</th><th>Evidence</th></tr>{rows_find}</table>
<p class="badge">OPS NODE: TYCHO-07</p> <p class="badge">CLEARANCE: ALPHA-PRIME</p>
</body></html>"""
    out = REPORTS / f"blackice_report_{pid}_{ts_file()}.html"
    out.write_text(html_doc, encoding="utf-8")
    footer_ok(f"[cyan]Report:[/cyan] {out}")

# ---------- MSF (Knowledge Only) ----------
def metasploit_search():
    header("Search Metasploit")
    if not have("msfconsole"):
        console.print(Panel("msfconsole not found on PATH.", border_style="red")); return
    term = Prompt.ask("[cyan]Search term[/cyan]", default="smb")
    console.print(Panel(f"Running: search {term}", border_style="blue"))
    subprocess.run(["msfconsole","-q","-x",f"search {term}; exit"], check=False)
    footer_ok()

def metasploit_info():
    header("Metasploit Module Info")
    if not have("msfconsole"):
        console.print(Panel("msfconsole not found on PATH.", border_style="red")); return
    mod = Prompt.ask("[cyan]Module (e.g., auxiliary/scanner/smb/smb_version)[/cyan]")
    console.print(Panel(f"Running: info {mod}", border_style="blue"))
    subprocess.run(["msfconsole","-q","-x",f"info {mod}; exit"], check=False)
    footer_ok()

# ===================== NEW DUAL-MODE MODULES =====================

# 1) Shodan (API / API-Free / Offline)
def shodan_asset_search():
    header("Shodan Asset Search (API / API-Free / Offline)")
    target = Prompt.ask("[cyan]Target (IP/CIDR/host or query)[/cyan]")
    out = SCANS / f"shodan_{target.replace('/','_')}_{ts_file()}.txt"

    if API.get("shodan") and have("shodan"):
        # API mode via shodan CLI (requires `shodan init KEY` done once)
        run_to_file(["shodan","search",target], out, note="Shodan CLI (API mode)")
    elif ONLINE and have("curl"):
        # API-free: very light HTML dorking (public search page) – saves raw HTML
        q = target.replace(" ", "+")
        run_to_file(["curl","-sS", f"https://www.shodan.io/search?query={q}"], out, note="Shodan web (API-free, HTML saved)")
    else:
        # Offline fallback: quick local nmap SV detection
        if not have("nmap"):
            console.print(Panel("Offline fallback needs nmap.", border_style="yellow")); return
        run_to_file(["nmap","-sV","-T4","-F",target], out, note="Offline fallback: nmap -sV -F")
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# 2) Censys / FOFA (API / API-Free / Offline)
def censys_fofa_query():
    header("Censys / FOFA Query (API / API-Free / Offline)")
    query = Prompt.ask("[cyan]Query (domain/IP/ASN/search)[/cyan]")
    out = SCANS / f"censys_fofa_{ts_file()}.txt"

    # Try Censys via CLI if creds exist (you can also wire Python SDK if desired)
    if API.get("censys_id") and API.get("censys_secret") and have("curl") and ONLINE:
        run_to_file(["curl","-sS","https://search.censys.io/"], out, note="(Placeholder) Censys portal reachable; store landing for audit")
    elif API.get("fofa_email") and API.get("fofa_key") and have("curl") and ONLINE:
        run_to_file(["curl","-sS","https://fofa.info/"], out, note="(Placeholder) FOFA portal reachable; store landing for audit")
    elif ONLINE and have("curl"):
        # API-free: Cert Transparency quick dump from crt.sh
        run_to_file(["curl","-sS", f"https://crt.sh/?q={query}&output=json"], out, note="crt.sh (API-free cert transparency JSON)")
    else:
        # Offline fallback: parse from local nmap/gobuster outputs into a stitched note
        with open(out,"w") as f:
            f.write("Offline fallback: No internet; aggregate local scans instead.\n")
        console.print(Panel("Offline: wrote placeholder note. Correlate with local scans.", border_style="yellow"))
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# 3) Web Screenshots (no API)
def screenshot_web_services():
    header("Screenshot Web Services")
    base = Prompt.ask("[cyan]URL or file of URLs (one per line)[/cyan]")
    out_dir = EVID / f"screenshots_{ts_file()}"
    ensure_dir(out_dir)

    if SET.get("screenshots_driver") == "gowitness" and have("gowitness"):
        # gowitness can take a single URL or file via 'file' mode
        if Path(base).exists():
            run_to_file(["gowitness","file","-f",str(base),"-P",str(out_dir)], out_dir / "gowitness.log",
                        note=f"gowitness file → {out_dir}")
        else:
            run_to_file(["gowitness","single","-u",base,"-P",str(out_dir)], out_dir / "gowitness.log",
                        note=f"gowitness single → {out_dir}")
    elif have("chromium") or have("google-chrome"):
        browser = "chromium" if have("chromium") else "google-chrome"
        if Path(base).exists():
            with open(base) as fh:
                for i, url in enumerate(fh, 1):
                    url = url.strip()
                    if not url: continue
                    png = out_dir / f"shot_{i:03d}.png"
                    run_to_file([browser,"--headless","--disable-gpu","--screenshot",url,"--window-size=1366,768"],
                                png, note=f"{browser} headless → {png}")
        else:
            png = out_dir / "shot.png"
            run_to_file([browser,"--headless","--disable-gpu","--screenshot",base,"--window-size=1366,768"],
                        png, note=f"{browser} headless → {png}")
    else:
        console.print(Panel("No screenshot driver found (install gowitness or chromium).", border_style="yellow")); return
    footer_ok(f"[cyan]Screenshots dir:[/cyan] {out_dir}")

# 4) IP Geolocation & ASN (API / Offline DB / WHOIS)
def ip_geo_asn_lookup():
    header("IP Geolocation & ASN Lookup")
    target_ip = Prompt.ask("[cyan]IP address[/cyan]")
    out = SCANS / f"geoasn_{target_ip}_{ts_file()}.txt"

    if API.get("ipinfo") and have("curl") and ONLINE:
        run_to_file(["curl","-sS", f"https://ipinfo.io/{target_ip}?token={API['ipinfo']}"], out,
                    note="ipinfo API (geo+ASN)")
    elif have("geoiplookup"):
        run_to_file(["geoiplookup", target_ip], out, note="geoiplookup (offline DB if present)")
    elif have("whois"):
        run_to_file(["whois", target_ip], out, note="whois (extract ASN/org manually)")
    else:
        console.print(Panel("Need ipinfo token OR geoiplookup OR whois.", border_style="yellow")); return
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# 5) Passive DNS (API / API-Free / Offline WHOIS)
def passive_dns_whois():
    header("Passive DNS & WHOIS (API / API-Free / Offline)")
    domain = Prompt.ask("[cyan]Domain[/cyan]")
    out = SCANS / f"passivedns_{domain}_{ts_file()}.txt"

    # API stubs could be added for SecurityTrails/VirusTotal if keys supplied.
    if ONLINE and have("curl"):
        # API-free: DNSDumpster HTML is heavy; store HTML for analyst review
        run_to_file(["curl","-sS","-A","Mozilla/5.0", f"https://dnsdumpster.com/"], out,
                    note="Saved dnsdumpster landing (manual use) + run dig locally")
        with open(out, "a") as f:
            f.write("\n\n# dig historical-like records (live):\n")
        # augment with live records
        if have("dig"):
            with open(out, "a") as f:
                for rec in ("A","AAAA","MX","NS","TXT","CAA"):
                    f.write(f"\n$ dig +short {domain} {rec}\n")
                    subprocess.run(["dig","+short",domain,rec], stdout=f, stderr=subprocess.STDOUT, text=True)
    elif have("whois"):
        run_to_file(["whois", domain], out, note="WHOIS (offline/basic)")
    else:
        console.print(Panel("No internet & no whois; cannot run.", border_style="yellow")); return
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# 6) Markdown → PDF (no API; local tools)
def export_markdown_to_pdf():
    header("Export Markdown to PDF")
    md_path = Prompt.ask("[cyan]Path to Markdown file[/cyan]")
    mdp = Path(md_path)
    if not mdp.exists():
        console.print(Panel("Markdown file not found.", border_style="red")); return
    out_pdf = REPORTS / f"{mdp.stem}_{ts_file()}.pdf"
    if have("pandoc"):
        run_to_file(["pandoc", str(mdp), "-o", str(out_pdf)], out_pdf, note="pandoc → PDF")
    elif have("weasyprint"):
        # weasyprint expects HTML; simple route: pandoc missing → inline convert via minimal HTML wrapper
        tmp_html = REPORTS / f"{mdp.stem}_{ts_file()}.html"
        html_body = f"<pre style='font-family:monospace; white-space:pre-wrap'>{html.escape(mdp.read_text())}</pre>"
        tmp_html.write_text(f"<!doctype html><meta charset='utf-8'><body>{html_body}</body>", encoding="utf-8")
        run_to_file(["weasyprint", str(tmp_html), str(out_pdf)], out_pdf, note="weasyprint → PDF")
    else:
        console.print(Panel("Install pandoc or weasyprint for PDF export.", border_style="yellow")); return
    footer_ok(f"[cyan]PDF:[/cyan] {out_pdf}")

# 7) Service Enumeration (read-only)
def service_enumeration():
    header("Service Enumeration (SSH/SMTP/SNMP – read-only)")
    target = Prompt.ask("[cyan]Target (IP/host)[/cyan]")
    out = SCANS / f"enum_{target.replace('/','_')}_{ts_file()}.txt"
    with open(out, "w") as f:
        if have("nmap"):
            f.write("$ nmap -sV -p 22,25,161 -Pn -T4\n")
            subprocess.run(["nmap","-sV","-p","22,25,161","-Pn","-T4",target], stdout=f, stderr=subprocess.STDOUT, text=True)
        if have("nc"):
            f.write("\n# SSH banner (nc):\n"); subprocess.run(["nc","-vz",target,"22"], stdout=f, stderr=subprocess.STDOUT, text=True)
            f.write("\n# SMTP banner (nc):\n"); subprocess.run(["nc","-vz",target,"25"], stdout=f, stderr=subprocess.STDOUT, text=True)
        if have("snmpwalk"):
            f.write("\n# SNMP read-only probe (public):\n")
            subprocess.run(["snmpwalk","-v2c","-c","public",target,"1.3.6.1.2.1.1"], stdout=f, stderr=subprocess.STDOUT, text=True)
    footer_ok(f"[cyan]Output:[/cyan] {out}")

# ---------------------- Menu ----------------------
MENU = [
    # Projects / Assets
    ("Create Project", create_project),
    ("List Projects", list_projects),
    ("Add Asset", add_asset),
    ("List Assets", list_assets),

    # Recon & scans
    ("Import Nmap XML", import_nmap_xml),
    ("Nmap Scan", nmap_scan),
    ("Port Banner Grab", port_banner_grab),
    ("Gobuster Scan", gobuster_scan),
    ("WordPress Scan", wpscan_audit),

    # DNS / HTTP / TLS
    ("DNS Records", dns_records),
    ("WHOIS Lookup", whois_lookup),
    ("HTTP Headers Audit", http_headers_audit),
    ("Fetch robots.txt / sitemap.xml", fetch_robots_sitemap),
    ("TLS/SSL Scan", tls_ssl_scan),

    # Passive / Tech
    ("Passive Subdomain Recon", passive_subdomains),
    ("Web Tech Fingerprint", web_tech_fingerprint),
    ("Nuclei (Safe Profile)", nuclei_safe_scan),

    # Evidence & content
    ("Fetch HTTP Body (save to evidence)", curl_save_body),

    # Secrets / SBOM / Container / Deps
    ("Secrets Scan (gitleaks)", secrets_scan_gitleaks),
    ("Generate SBOM (syft)", sbom_generate_syft),
    ("SBOM Vulnerability Scan (grype/trivy)", sbom_vuln_scan),
    ("Container/Image Scan (trivy)", container_scan_trivy),
    ("Python Dependency Audit (pip-audit)", pip_audit_deps),
    ("Node Dependency Audit (npm audit)", npm_audit_deps),

    # ===== New Dual-Mode Modules =====
    ("Shodan Asset Search (API/API-Free/Offline)", shodan_asset_search),
    ("Censys/FOFA Query (API/API-Free/Offline)", censys_fofa_query),
    ("Screenshot Web Services", screenshot_web_services),
    ("IP Geolocation & ASN Lookup", ip_geo_asn_lookup),
    ("Passive DNS & WHOIS", passive_dns_whois),
    ("Export Markdown → PDF", export_markdown_to_pdf),
    ("Service Enumeration (SSH/SMTP/SNMP)", service_enumeration),

    # Findings & report
    ("Add Finding", add_finding),
    ("Generate Report (HTML)", generate_report),

    # Metasploit knowledge only
    ("Search Metasploit", metasploit_search),
    ("Metasploit Module Info", metasploit_info),

    ("Exit", lambda: sys.exit(0)),
]

def status_bar():
    return Align.center(
        "[cyan]NETWATCH LINK:[/cyan] TYCHO-07 • [green]ONLINE[/green]  |  "
        "[cyan]CLEARANCE:[/cyan] ALPHA-PRIME  |  "
        f"[cyan]DOSSIER:[/cyan] {DATA}", vertical="middle"
    )

def main():
    boot_sequence()
    # Note: we don’t hard-fail if optional tools are missing; modules will explain.
    dep_note(["nmap","gobuster","wpscan","msfconsole","dig","whois","curl","testssl.sh","sslyze",
              "subfinder","amass","whatweb","httpx","nuclei","gitleaks","syft","grype","trivy",
              "pip-audit","npm","gowitness","chromium","geoiplookup","snmpwalk","nc","pandoc","weasyprint","shodan"])
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=9),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3),
    )
    layout["header"].update(Panel(BANNER, border_style="cyan"))
    with Live(layout, refresh_per_second=4, screen=False):
        while True:
            tbl = Table(title="BLACKICE COMMAND — Authorized Operations Console", show_lines=True, border_style="cyan")
            tbl.add_column("#", justify="right"); tbl.add_column("Action")
            for i, (label, _) in enumerate(MENU, 1):
                tbl.add_row(str(i), label)
            layout["body"].update(tbl)
            layout["footer"].update(Panel(status_bar(), border_style="blue"))
            choice = Prompt.ask("\nSelect option", choices=[str(i) for i in range(1, len(MENU)+1)])
            label, func = MENU[int(choice)-1]
            if label == "Exit":
                console.print(Panel("Disconnecting from NETWATCH C.I.C… Link closed.", border_style="cyan"))
                sys.exit(0)
            func()
            Prompt.ask("\n[cyan]Press Enter to return to menu[/cyan]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Session terminated by user.[/yellow]")
