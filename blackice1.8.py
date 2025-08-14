#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlackIce v1.8.1 — Cyberpunk Console (Boot Every Launch)

SAFE Recon/Intel console with:
- Cyberpunk boot + neon UI (always on)
- Cases & per-case session logs
- GeoIP + ASN Intel (API-free, Team Cymru/WHOIS/GeoIP fallbacks)
- Traceroute with per-hop ASN/Geo + ASCII + HTML hop graph
- Banner Grabber (HTTP/SMTP/FTP/SSH + generic + TLS wrap)
- JSON + Neon HTML case reports

NEW v1.8 modules:
- DNS Suite (records + SPF/DMARC parse + AXFR test)
- Robots/Sitemap + Quick Dir Probe
- Lite Crawler (depth 1–2, titles & internal links)
- Wayback Snapshots (Internet Archive)
- ASN → Prefixes (Team Cymru)
- Batch Screenshots (gowitness list)

All actions are non-destructive. Works in bare terminals (TTY/Konsole/xterm).
"""

from __future__ import annotations
import os, sys, shutil, subprocess, socket, json, re, time, random, ssl, ipaddress
from pathlib import Path
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen, Request

# ---------------------- Paths (Global) ----------------------
BASE      = Path.cwd()
DATA      = BASE / "blackice_dossier"
SCANS     = DATA / "scans"          # legacy flat scans dir (kept for compat)
REPORTS   = DATA / "reports"
LOGS      = DATA / "logs"
CASES_DIR = DATA / "cases"
for d in (DATA, SCANS, REPORTS, LOGS, CASES_DIR):
    d.mkdir(parents=True, exist_ok=True)

GLOBAL_LOG = LOGS / "blackice.log"
ACTIVE_CASE = "default"

# ---------------------- ANSI ----------------------
class C:
    reset = "\033[0m"; bold  = "\033[1m"; dim = "\033[2m"; it = "\033[3m"; und = "\033[4m"
    c0="\033[38;5;45m"; c1="\033[38;5;48m"; c2="\033[38;5;201m"; c3="\033[38;5;214m"
    c4="\033[38;5;87m"; c5="\033[38;5;199m"; grey="\033[38;5;244m"

def clr(): os.system("clear" if os.name != "nt" else "cls")
def line(w=66, col=C.grey): return col + "─"*w + C.reset
def frame(title:str):
    t = title[:64]; pad = 64 - len(t); pad = pad if pad>0 else 0
    return f"{C.c2}╔{line(64, C.c2)}╗\n{C.c2}║{C.reset}{C.bold}{t}{C.reset}{' '*pad}{C.c2}║\n{C.c2}╚{line(64, C.c2)}╝{C.reset}"

# ---------------------- Boot / Lore ----------------------
def slowprint(s:str, delay=0.02):
    for ch in s: print(ch, end="", flush=True); time.sleep(delay)
    print()
def dots(label, n, color):
    print(f"{color}{label}{C.reset}", end="", flush=True)
    for _ in range(n): print(".", end="", flush=True); time.sleep(0.03)
    print()
def boot_sequence():
    clr()
    banner = rf"""{C.c3}{C.bold}
  /$$$$$$$  /$$                     /$$       /$$$$$$                    
| $$__  $$| $$                    | $$      |_  $$_/                    
| $  \\ $$| $$  /$$$$$$   /$$$$$$$| $$   /$$  | $$    /$$$$$$$  /$$$$$$ 
| $$$$$$$ | $$ |____  $$ /$$_____/| $$  /$$/  | $$   /$$_____/ /$$__  $$
| $$__  $$| $$  /$$$$$$$| $$      | $$$$$$/   | $$  | $$      | $$$$$$$$
| $$  \\$$| $$ /$$__  $$| $$      | $$_ $$   |  $$  | $$      | $$_____/
| $$$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$ \\ $$ /$$$$$$|  $$$$$$$|  $$$$$$$
|_______/ |__/ \\_______/ \\_______/|__/  \\/|_____/ \\______/ \\______/
{C.reset}{C.c4}Cyberpunk Offensive Console — BlackIce v1.8.1
{C.grey}BIOS: NX-7 Phantom  •  Firmware: Quicksilver/β  •  Owner: Null_Lyfe{C.reset}
"""
    print(banner)
    slowprint(f"{C.c1}[BOOT]{C.reset} Initializing quantum entropy pools ……", 0.01); dots("     seeding RNG", 24, C.c4)
    slowprint(f"{C.c1}[HW]{C.reset} Scanning bus: PCIe/USB/WiFi/BLE/HackRF ……", 0.01); dots("     devices online", 18, C.c5)
    slowprint(f"{C.c1}[FS]{C.reset} Mounting encrypted vaults ……", 0.01); dots("     OK", 10, C.c3)
    slowprint(f"{C.c1}[NET]{C.reset} Negotiating shadow uplink via onion relays ……", 0.01); dots("     established", 20, C.c0)
    slowprint(f"{C.c1}[AI]{C.reset} Loading heuristics & threat taxonomy ……", 0.01); dots("     ready", 12, C.c2)
    print(random.choice([
        f"{C.grey}:: Stay hidden. Strike silently.{C.reset}",
        f"{C.grey}:: No gods. No kings. Only packets.{C.reset}",
        f"{C.grey}:: The quiet blade cuts the deepest.{C.reset}",
        f"{C.grey}:: Skills pay the bills; logs tell the tales.{C.reset}",
    ])); time.sleep(0.3)

# ---------------------- Logging / Utils ----------------------
def log_global(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with GLOBAL_LOG.open("a", encoding="utf-8") as f: f.write(f"[{ts}] {msg}\n")

def which(name: str) -> bool: return shutil.which(name) is not None

def ask(prompt: str, default: str = "") -> str:
    try: s = input(C.c1 + "» " + C.reset + prompt + " ").strip(); return s or default
    except EOFError: return default

def neon_ok(msg:str):   print(f"{C.c1}[+]{C.reset} {msg}")
def neon_warn(msg:str): print(f"{C.c3}[!]{C.reset} {msg}")
def neon_info(msg:str): print(f"{C.c4}[i]{C.reset} {msg}")

def safe_name(s: str) -> str: return re.sub(r"[^a-zA-Z0-9_.-]+", "_", s)[:120]

def is_ip(s: str) -> bool:
    try: ipaddress.ip_address(s); return True
    except Exception: return False

# -------- Case-aware paths --------
def ensure_case_dirs(case: str):
    croot = CASES_DIR / case
    (croot / "scans").mkdir(parents=True, exist_ok=True)
    (croot / "reports").mkdir(parents=True, exist_ok=True)
    (croot / "logs").mkdir(parents=True, exist_ok=True)
    return croot

def case_paths(case: str):
    croot = ensure_case_dirs(case)
    return {
        "root": croot,
        "scans": croot / "scans",
        "reports": croot / "reports",
        "logs": croot / "logs",
        "session_log": croot / "logs" / "session.log",
    }

def case_log(case: str, msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    p = case_paths(case)["session_log"]
    with p.open("a", encoding="utf-8") as f: f.write(f"[{ts}] {msg}\n")

def run_cmd(cmd: list[str], outfile: Path | None = None, timeout: int = 240, case: str | None = None) -> str:
    cmd_str = " ".join(cmd)
    log_global(f"RUN[{case or '-'}]: {cmd_str}")
    if case: case_log(case, f"RUN: {cmd_str}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        neon_warn(f"Command not found: {cmd[0]}"); return ""
    except Exception as e:
        neon_warn(f"Failed to start: {e}"); return ""
    captured, start = [], time.time()
    try:
        while True:
            if proc.poll() is not None: break
            line = proc.stdout.readline()
            if line: captured.append(line); print(C.grey+"│ "+C.reset+line, end="")
            if time.time() - start > timeout:
                proc.kill(); print(f"\n{C.c3}[!] Killed after {timeout}s timeout.{C.reset}")
                log_global(f"TIMEOUT: {cmd_str}")
                if case: case_log(case, f"TIMEOUT: {cmd_str}")
                break
        rest = proc.stdout.read() or ""
        if rest:
            captured.append(rest)
            for ln in rest.splitlines(True): print(C.grey+"│ "+C.reset+ln, end="")
    finally:
        try: proc.stdout.close()
        except Exception: pass
    out = "".join(captured)
    if outfile:
        try:
            outfile.write_text(out, encoding="utf-8", errors="ignore")
            neon_ok(f"Saved → {outfile}")
            if case: case_log(case, f"SAVED: {outfile}")
        except Exception as e:
            neon_warn(f"Could not write {outfile}: {e}")
    return out

# ---------------------- Header / Menu ----------------------
def header():
    clr()
    print(f"{C.c2}{'═'*68}{C.reset}")
    print(f"{C.c5}{C.bold} BLACKICE v1.8.1 {C.reset}{C.grey} — Cyberpunk Recon Console{C.reset}")
    print(f"{C.c2}{'═'*68}{C.reset}")
    print(f"{C.grey}Active Case:{C.reset} {C.c1}{ACTIVE_CASE}{C.reset}\n")

def menu() -> str:
    print(f"""
{C.c0}Cases & Logs{C.reset}
  {C.c1}[0]{C.reset} Switch / Manage Case
  {C.c1}[L]{C.reset} View recent session log (active case)

{C.c0}Core Recon{C.reset}
  {C.c1}[1]{C.reset} Ping host
  {C.c1}[2]{C.reset} DNS lookup (quick)
  {C.c1}[4]{C.reset} TLS info (openssl/testssl)
  {C.c1}[5]{C.reset} Port scan (nmap / fallback)
  {C.c1}[9]{C.reset} WHOIS
  {C.c1}[A]{C.reset} IP Intel (GeoIP + ASN)
  {C.c1}[T]{C.reset} Traceroute (+ ASN/Geo + ASCII + HTML)
  {C.c1}[B]{C.reset} Banner Grabber (smart)

{C.c0}Web Intel{C.reset}
  {C.c1}[R]{C.reset} Robots/Sitemap + Quick Dir Probe
  {C.c1}[C]{C.reset} Lite Crawler (depth 1–2)
  {C.c1}[W]{C.reset} Wayback Snapshots

{C.c0}DNS / ASN Extras{C.reset}
  {C.c1}[D]{C.reset} DNS Suite (records + SPF/DMARC + AXFR test)
  {C.c1}[X]{C.reset} ASN → Prefixes (Team Cymru)

{C.c0}Screenshots & Reports{C.reset}
  {C.c1}[G]{C.reset} Batch Screenshots (gowitness)
  {C.c1}[S]{C.reset} Save consolidated JSON report (case)
  {C.c1}[H]{C.reset} Generate neon HTML report (case)

  {C.c1}[q]{C.reset} Quit
""")
    return ask("Select option").strip()

def show_missing_tools():
    optional = [
        "testssl.sh","subfinder","gitleaks","gowitness","nmap","traceroute","mtr",
        "dig","host","curl","whois","openssl","geoiplookup","mmdblookup"
    ]
    missing = [t for t in optional if not which(t)]
    if missing:
        print(f"{C.c3}Optional/used tools not found:{C.reset} " + ", ".join(sorted(set(missing))))
        print(f"{C.grey}Install to enable richer output. Script still runs with fallbacks.{C.reset}\n")

# ---------------------- Case Management ----------------------
def action_switch_case():
    global ACTIVE_CASE
    print(frame("CASE MANAGEMENT"))
    print(f"{C.grey}Location:{C.reset} {CASES_DIR}")
    existing = sorted([p.name for p in CASES_DIR.iterdir() if p.is_dir()])
    if existing:
        print(f"{C.c4}Existing cases:{C.reset} " + ", ".join(existing))
    new = ask("Enter case name (create/switch):", ACTIVE_CASE).strip()
    if not new:
        neon_warn("No change."); return
    ACTIVE_CASE = safe_name(new)
    ensure_case_dirs(ACTIVE_CASE)
    neon_ok(f"Active case set → {ACTIVE_CASE}")

def action_view_session_log():
    paths = case_paths(ACTIVE_CASE); slog = paths["session_log"]
    print(frame(f"SESSION LOG — {ACTIVE_CASE}"))
    if not slog.exists(): print(C.grey+"(no entries yet)"+C.reset); return
    try:
        lines = slog.read_text(encoding="utf-8", errors="ignore").splitlines()
        for ln in lines[-200:]:
            print(C.grey+"│ "+C.reset+ln)
    except Exception as e:
        neon_warn(f"Could not read log: {e}")

# ---------------------- Standard Tasks (kept) ----------------------
def task_ping():
    header(); print(frame("PING"))
    target = ask("Target host/IP to ping:"); 
    if not target: return
    paths = case_paths(ACTIVE_CASE)
    run_cmd(["ping","-c","4",target], paths["scans"] / f"ping_{safe_name(target)}.txt", case=ACTIVE_CASE)

def task_dns_lookup_quick():
    header(); print(frame("DNS LOOKUP — QUICK"))
    target = ask("Domain or host:"); 
    if not target: return
    paths = case_paths(ACTIVE_CASE)
    outfile = paths["scans"] / f"dns_quick_{safe_name(target)}.txt"
    if which("dig"): run_cmd(["dig","+nocmd",target,"any","+multiline","+noall","+answer"], outfile, case=ACTIVE_CASE)
    elif which("host"): run_cmd(["host","-a",target], outfile, case=ACTIVE_CASE)
    else:
        try:
            ips = socket.getaddrinfo(target, None)
            lines = "\n".join(sorted({ai[4][0] for ai in ips}))
            print(C.grey + lines + C.reset)
            outfile.write_text(lines + "\n"); neon_ok(f"Saved → {outfile}"); case_log(ACTIVE_CASE, f"SAVED: {outfile}")
        except Exception as e: neon_warn(f"DNS error: {e}")

def task_tls_info():
    header(); print(frame("TLS INFO"))
    host = ask("Hostname (SNI):"); 
    if not host: return
    port = ask("Port [443]:","443")
    paths = case_paths(ACTIVE_CASE)
    outfile = paths["scans"] / f"tls_{safe_name(host)}_{port}.txt"
    if which("openssl"):
        cmd=["sh","-c",f"echo | openssl s_client -servername {host} -connect {host}:{port} 2>/dev/null | openssl x509 -noout -issuer -subject -dates -fingerprint -serial"]
        run_cmd(cmd, outfile, case=ACTIVE_CASE)
    elif which("testssl.sh"): run_cmd(["testssl.sh",f"{host}:{port}"], outfile, timeout=600, case=ACTIVE_CASE)
    else: neon_warn("Need openssl or testssl.sh for TLS info.")

def task_port_scan():
    header(); print(frame("PORT SCAN"))
    target = ask("Target (IP/CIDR/host):"); 
    if not target: return
    paths = case_paths(ACTIVE_CASE)
    outfile = paths["scans"] / f"nmap_{safe_name(target)}.txt"
    if which("nmap"):
        profile = ask("Profile: [1] quick top100  [2] 1-1024  [3] service -sV ->","1")
        if   profile=="2": run_cmd(["nmap","-Pn","-p","1-1024",target], outfile, case=ACTIVE_CASE)
        elif profile=="3": run_cmd(["nmap","-Pn","-sV","--version-light",target], outfile, case=ACTIVE_CASE)
        else:               run_cmd(["nmap","-Pn","--top-ports","100",target], outfile, case=ACTIVE_CASE)
    else:
        ports=[80,443,22,21,25,53,110,143,3306,6379,8080]
        neon_info("nmap not found. Basic socket check on common ports:")
        results=[]
        for p in ports:
            s=socket.socket(); s.settimeout(0.8)
            try: s.connect((target,p)); s.close(); print(f"{C.c1}{target}:{p} open{C.reset}"); results.append(f"{p} open")
            except Exception: pass
        text="\n".join(results) or "No common ports open (or host unreachable)."
        outfile.write_text(text+"\n"); neon_ok(f"Saved → {outfile}"); case_log(ACTIVE_CASE, f"SAVED: {outfile}")

def task_whois():
    header(); print(frame("WHOIS"))
    target = ask("Domain/IP:"); 
    if not target: return
    paths = case_paths(ACTIVE_CASE)
    if which("whois"): run_cmd(["whois",target], paths["scans"] / f"whois_{safe_name(target)}.txt", case=ACTIVE_CASE)
    else: neon_warn("whois not installed.")

# ---------------------- IP Intel (kept) ----------------------
def parse_cymru_whois(text:str):
    asn, prefix, cc, registry, asname = None, None, None, None, None
    for ln in text.splitlines():
        if ln.strip().startswith("AS") and "BGP" in ln: continue
        parts = [p.strip() for p in ln.split("|")]
        if len(parts) >= 7 and parts[0].isdigit():
            asn = "AS"+parts[0]; prefix = parts[2]; cc = parts[3]; registry = parts[4]; asname = parts[6]; break
    return {"asn": asn, "prefix": prefix, "cc": cc, "registry": registry, "asname": asname}

def parse_standard_whois(text:str):
    d = {}
    m = re.search(r'origin(?:AS)?:\s*(AS?\d+)', text, re.IGNORECASE)
    if m: d["asn"] = m.group(1) if m.group(1).startswith("AS") else "AS"+m.group(1)
    m = re.search(r'(?:netname|org-name|OrgName):\s*(.+)', text, re.IGNORECASE)
    if m: d["asname"] = m.group(1).strip()
    m = re.search(r'country:\s*([A-Z]{2})', text, re.IGNORECASE)
    if m: d["cc"] = m.group(1).upper()
    m = re.search(r'route(?:6)?:\s*([0-9a-fA-F\.:/]+)', text)
    if m: d["prefix"] = m.group(1)
    return d

def resolve_to_ips(host_or_ip:str):
    try:
        if is_ip(host_or_ip): return [host_or_ip]
        infos = socket.getaddrinfo(host_or_ip, None)
        return sorted({ai[4][0] for ai in infos})
    except Exception:
        return []

def run_geoip_command(ip:str):
    if which("geoiplookup"):
        try: return subprocess.check_output(["geoiplookup", ip], text=True, stderr=subprocess.STDOUT, timeout=8).strip()
        except Exception: pass
    if which("mmdblookup"):
        try: return subprocess.check_output(["mmdblookup","--file","/usr/share/GeoIP/GeoLite2-City.mmdb","--ip",ip], text=True, stderr=subprocess.STDOUT, timeout=8).strip()
        except Exception: pass
    return None

def intel_for_ip(ip:str):
    cymru, std, geo = {}, {}, None
    if which("whois"):
        try:
            cymru_txt = subprocess.check_output(["whois","-h","whois.cymru.com","-v",ip], text=True, stderr=subprocess.STDOUT, timeout=10)
            cymru = parse_cymru_whois(cymru_txt) or {}
        except Exception: pass
        try:
            w = subprocess.check_output(["whois", ip], text=True, stderr=subprocess.STDOUT, timeout=10)
            std = parse_standard_whois(w) or {}
        except Exception: pass
    geo = run_geoip_command(ip)
    return {
        "ip": ip,
        "asn": cymru.get("asn") or std.get("asn"),
        "prefix": cymru.get("prefix") or std.get("prefix"),
        "cc": cymru.get("cc") or std.get("cc"),
        "registry": cymru.get("registry"),
        "asname": cymru.get("asname") or std.get("asname"),
        "geoip": geo
    }

def ip_intel_text(host_or_ip:str):
    ips = resolve_to_ips(host_or_ip)
    if not ips: return f"{host_or_ip}: could not resolve."
    lines=[]
    for ip in ips:
        rec = intel_for_ip(ip)
        line = f"{ip} :: {rec.get('asn') or 'AS?'} | {rec.get('asname') or 'Unknown AS'}"
        if rec.get("prefix"): line += f" | {rec['prefix']}"
        if rec.get("cc"): line += f" | {rec['cc']}"
        if rec.get("geoip"): line += f"\n    GeoIP: {rec['geoip']}"
        lines.append(line)
    return "\n".join(lines) + "\n"

def task_ip_intel():
    header(); print(frame("IP INTEL — GeoIP + ASN"))
    h = ask("IP or Host:"); 
    if not h: return
    paths = case_paths(ACTIVE_CASE)
    out_text = ip_intel_text(h)
    of = paths["scans"] / f"ip_intel_{safe_name(h)}.txt"
    of.write_text(out_text, encoding="utf-8")
    print(C.grey + out_text + C.reset)
    neon_ok(f"Saved → {of}"); case_log(ACTIVE_CASE, f"SAVED: {of}")

# ---------------------- Traceroute (+ ASN/Geo + ASCII + HTML graph) ----------------------
def parse_traceroute_lines(text:str):
    ips=[]
    for ln in text.splitlines():
        if re.match(r"^\s*\d+\s", ln):
            hop_ips = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)", ln)
            hop_ips = [h for h in hop_ips if ':' in h or h.count('.')==3]
            if hop_ips:
                candidate = hop_ips[0]
                if candidate != "*" : ips.append(candidate)
            else:
                ips.append("*")
    return ips

def do_traceroute(target:str):
    if which("traceroute"):
        try:
            txt = subprocess.check_output(["traceroute","-n","-w","2","-q","1",target], text=True, stderr=subprocess.STDOUT, timeout=60)
            return txt
        except Exception as e:
            return f"[traceroute error] {e}\n"
    if which("mtr"):
        try:
            txt = subprocess.check_output(["mtr","-nrbwc","1","-z",target], text=True, stderr=subprocess.STDOUT, timeout=60)
            return txt
        except Exception as e:
            return f"[mtr error] {e}\n"
    return "[!] No traceroute/mtr available on this system.\n"

def ascii_as_path(hops_enriched:list[dict]) -> str:
    lines = ["You"]
    total = len(hops_enriched)
    for i, rec in enumerate(hops_enriched, 1):
        branch = "└─" if i == total else "├─"
        ip = rec.get("ip","*")
        asn = rec.get("asn") or "AS?"
        name = (rec.get("asname") or "Unknown AS").strip()
        cc = (rec.get("cc") or "??").strip()
        lines.append(f"  {branch} {i:>2}: {ip:<39} {asn:<8} {name} [{cc}]")
    return "\n".join(lines) + "\n"

def svg_escape(s:str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;").replace("'","&#39;")

def build_traceroute_svg(hops_enriched:list[dict], title:str="Traceroute Graph") -> str:
    if not hops_enriched:
        return "<svg xmlns='http://www.w3.org/2000/svg' width='800' height='120'></svg>"
    n = len(hops_enriched)
    w = max(900, 160 * (n+1))
    h = 260
    margin_x = 80
    step = (w - 2*margin_x) // (n+1)
    y = h//2
    circles = []
    lines = []
    labels = []
    x0 = margin_x
    circles.append(f"<circle cx='{x0}' cy='{y}' r='18' fill='#11162a' stroke='#21d4fd' stroke-width='2'/>")
    labels.append(f"<text x='{x0}' y='{y-28}' text-anchor='middle' fill='#21d4fd' font-size='12'>You</text>")
    last_x, last_y = x0, y
    for i, rec in enumerate(hops_enriched, 1):
        x = margin_x + step*i
        lines.append(f"<line x1='{last_x}' y1='{last_y}' x2='{x}' y2='{y}' stroke='url(#grad)' stroke-width='3' stroke-linecap='round'/>")
        circles.append(f"<circle cx='{x}' cy='{y}' r='18' fill='#0f1320' stroke='#ff6ec7' stroke-width='2'/>")
        t1 = svg_escape(f"#{i} {rec.get('ip','*')}")
        t2 = svg_escape(f"{rec.get('asn') or 'AS?'}  { (rec.get('asname') or 'Unknown AS')[:28] }")
        t3 = svg_escape(f"{rec.get('cc') or '??'}  { (rec.get('prefix') or '') }")
        labels.append(f"<text x='{x}' y='{y-34}' text-anchor='middle' fill='#b0baf5' font-size='11'>{t1}</text>")
        labels.append(f"<text x='{x}' y='{y+40}' text-anchor='middle' fill='#8e98c3' font-size='10'>{t2}</text>")
        labels.append(f"<text x='{x}' y='{y+56}' text-anchor='middle' fill='#667' font-size='9'>{t3}</text>")
        last_x, last_y = x, y
    svg = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' style='background:#0b0e14'>",
        "<defs>",
        "<linearGradient id='grad' x1='0%' y1='0%' x2='100%' y2='0%'>",
        "<stop offset='0%' stop-color='#21d4fd'/>",
        "<stop offset='100%' stop-color='#ff6ec7'/>",
        "</linearGradient>",
        "</defs>",
        f"<text x='{w/2}' y='28' text-anchor='middle' fill='#21d4fd' font-size='16' font-weight='700'>{svg_escape(title)}</text>",
        *lines, *circles, *labels,
        "</svg>"
    ]
    return "\n".join(svg)

def build_traceroute_html(hops_enriched:list[dict], target:str, case:str) -> str:
    svg = build_traceroute_svg(hops_enriched, f"Traceroute → {target}  (case: {case})")
    css = """
body{background:#0b0e14;color:#c8d3f5;font-family:ui-monospace,Menlo,Consolas,monospace;margin:0}
.header{padding:22px 26px;background:linear-gradient(90deg,#ff6ec7,#21d4fd 70%);-webkit-background-clip:text;background-clip:text;color:transparent;font-weight:800;font-size:22px;letter-spacing:.4px}
.sub{color:#8e98c3;margin:-8px 26px 12px 26px;font-size:12px}
.card{border:1px solid #2a2f45;border-radius:10px;margin:18px 26px;background:#0f1320;box-shadow:0 0 20px rgba(33,212,253,.05)}
.card h3{margin:0;padding:12px 16px;background:#11162a;border-bottom:1px solid #2a2f45;color:#21d4fd}
pre{margin:0;padding:14px 16px;white-space:pre-wrap;word-wrap:break-word;color:#c8d3f5}
.footer{color:#667;font-size:11px;margin:24px 26px 40px 26px}
svg{display:block;margin:10px auto;border:1px solid #2a2f45;border-radius:8px;box-shadow:0 0 30px rgba(255,110,199,.08)}
"""
    ascii_block = html_escape(ascii_as_path(hops_enriched))
    html = [
        "<!doctype html><meta charset='utf-8'>",
        f"<title>BlackIce Traceroute — {html_escape(target)}</title>",
        f"<style>{css}</style>",
        f"<div class='header'>BLACKICE — Traceroute Graph</div>",
        f"<div class='sub'>target: {html_escape(target)}  •  case: {html_escape(case)}  •  generated: {html_escape(datetime.utcnow().isoformat()+'Z')}</div>",
        f"<div class='card'><h3>Path Graph</h3>{svg}</div>",
        f"<div class='card'><h3>ASCII AS-Path</h3><pre>{ascii_block}</pre></div>",
        "<div class='footer'>BlackIce v1.8.1 — neon traceroute view</div>"
    ]
    return "\n".join(html)

def task_traceroute():
    header(); print(frame("TRACEROUTE + HOP ASN/GEO + ASCII + HTML"))
    target = ask("Target host/IP for traceroute:")
    if not target: return
    paths = case_paths(ACTIVE_CASE)
    base_out = paths["scans"] / f"traceroute_{safe_name(target)}.txt"
    raw = do_traceroute(target)
    base_out.write_text(raw, encoding="utf-8")
    neon_ok(f"Saved raw traceroute → {base_out}")
    hops = parse_traceroute_lines(raw)
    enriched=[]
    for ip in hops:
        if ip == "*" or ip.strip()=="*":
            enriched.append({"ip":"*", "asn":None, "asname":None, "cc":None, "prefix":None})
        else:
            enriched.append(intel_for_ip(ip))
    lines=["# Hop | IP | ASN | AS Name | CC | Prefix",
           "-"*72]
    for i, rec in enumerate(enriched, 1):
        if rec.get("ip") == "*":
            lines.append(f"{i:>3}  *")
            continue
        line = f"{i:>3}  {rec.get('ip')}  {rec.get('asn') or 'AS?'}  {rec.get('asname') or 'Unknown AS'}  {rec.get('cc') or '?'}  {rec.get('prefix') or ''}"
        lines.append(line)
        if rec.get("geoip"): lines.append(f"     GeoIP: {rec['geoip']}")
    analysis = "\n".join(lines) + "\n"
    ana_out = paths["scans"] / f"traceroute_{safe_name(target)}_analysis.txt"
    ana_out.write_text(analysis, encoding="utf-8")
    print(C.grey + analysis + C.reset)
    neon_ok(f"Saved hop analysis → {ana_out}")
    case_log(ACTIVE_CASE, f"SAVED: {ana_out}")
    ascii_map = ascii_as_path([r for r in enriched if r.get("ip")!="*"])
    ascii_out = paths["scans"] / f"traceroute_{safe_name(target)}_asciipath.txt"
    ascii_out.write_text(ascii_map, encoding="utf-8")
    print(C.c4 + "ASCII AS-Path:\n" + C.reset + C.grey + ascii_map + C.reset)
    neon_ok(f"Saved ASCII path → {ascii_out}")
    html = build_traceroute_html([r for r in enriched if r.get("ip")!="*"], target, ACTIVE_CASE)
    html_out = paths["reports"] / f"traceroute_graph_{safe_name(target)}_{int(time.time())}.html"
    html_out.write_text(html, encoding="utf-8")
    neon_ok(f"Saved neon graph → {html_out}")
    case_log(ACTIVE_CASE, f"SAVED: {html_out}")

# ---------------------- Banner Grabber (kept) ----------------------
TLS_PORTS = {443, 8443, 993, 995, 465, 587}
def grab_banner(host:str, port:int, timeout:float=3.0) -> str:
    data=""
    try:
        addr = (host, port)
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            with socket.create_connection(addr, timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    try:
                        ssock.settimeout(timeout)
                        ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: "+host.encode()+b"\r\n\r\n")
                        data = ssock.recv(2048).decode("utf-8", "ignore")
                    except Exception: pass
        else:
            with socket.create_connection(addr, timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port == 80: sock.sendall(b"HEAD / HTTP/1.0\r\nHost: "+host.encode()+b"\r\n\r\n")
                else: sock.sendall(b"\r\n\r\n")
                try: data = sock.recv(2048).decode("utf-8", "ignore")
                except Exception: data = ""
    except Exception as e:
        data = f"[error] {e}"
    if port == 22 and (not data or "SSH" not in data.upper()):
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout); data2 = s.recv(2048).decode("utf-8", "ignore")
                if data2: data = data2
        except Exception: pass
    return data.strip()

def task_banner_grabber():
    header(); print(frame("BANNER GRABBER"))
    host = ask("Host/IP:"); 
    if not host: return
    portstr = ask("Port(s) (e.g. 80 or 22,80,443) [80]:","80")
    try: ports = [int(x) for x in re.split(r"[,\s]+", portstr.strip()) if x]
    except Exception: neon_warn("Ports parse error."); return
    paths = case_paths(ACTIVE_CASE)
    outpath = paths["scans"] / f"banners_{safe_name(host)}_{int(time.time())}.txt"
    lines=[]
    for p in ports:
        print(f"{C.c4}▶ {host}:{p}{C.reset}")
        banner = grab_banner(host, p, timeout=3.0) or "(no banner / silent)"
        lines.append(f"## {host}:{p}\n{banner}\n")
        for ln in banner.splitlines(): print(C.grey+"│ "+C.reset+ln)
    out_text = "\n".join(lines); outpath.write_text(out_text, encoding="utf-8")
    neon_ok(f"Saved banners → {outpath}"); case_log(ACTIVE_CASE, f"SAVED: {outpath}")

# ====================== NEW MODULES (v1.8) ======================

# --- D) DNS Suite: records + SPF/DMARC + AXFR test ---
def task_dns_suite():
    header(); print(frame("DNS SUITE — Records + SPF/DMARC + AXFR"))
    domain = ask("Domain:"); 
    if not domain: return
    paths = case_paths(ACTIVE_CASE); outdir = paths["scans"]; base = safe_name(domain)
    outpath = outdir / f"dns_suite_{base}.txt"
    lines=[]
    def run_or_note(cmd):
        if which(cmd[0]):
            try: return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=20)
            except Exception as e: return f"[{cmd[0]} error] {e}\n"
        return f"[!] {cmd[0]} not installed\n"
    if which("dig"):
        for rr in ["A","AAAA","CNAME","MX","TXT","NS","SOA"]:
            lines.append(f";; {rr}\n")
            lines.append(run_or_note(["dig","+short",domain,rr]))
    elif which("host"):
        for rr in ["A","AAAA","CNAME","MX","TXT","NS","SOA"]:
            lines.append(f";; {rr}\n")
            lines.append(run_or_note(["host","-t",rr,domain]))
    else:
        lines.append("[!] Neither dig nor host is installed.\n")
    txt_blob = "".join([x for x in lines if "v=spf1" in x or "_dmarc" in x or "v=DMARC1" in x])
    spf = re.findall(r'v=spf1[^\n"]+', txt_blob, flags=re.I)
    dmarc = re.findall(r'v=DMARC1[^\n"]+', "".join(lines), flags=re.I)
    lines.append("\n;; SPF records\n" + ("\n".join(spf) if spf else "(none)\n"))
    lines.append("\n;; DMARC records\n" + ("\n".join(dmarc) if dmarc else "(none)\n"))
    ns_records = []
    if which("dig"):
        try:
            nslist = subprocess.check_output(["dig","+short",domain,"NS"], text=True, timeout=10).strip().splitlines()
            ns_records = [n.strip().rstrip('.') for n in nslist if n.strip()]
        except Exception: pass
    if ns_records:
        lines.append("\n;; AXFR attempts\n")
        for ns in ns_records:
            try:
                out = subprocess.check_output(["dig","@"+ns,domain,"AXFR"], text=True, stderr=subprocess.STDOUT, timeout=15)
                if out.strip():
                    lines.append(f"@{ns} — POSSIBLE TRANSFER!\n{out}\n")
                else:
                    lines.append(f"@{ns} — refused / empty\n")
            except Exception as e:
                lines.append(f"@{ns} — {e}\n")
    else:
        lines.append("\n;; AXFR attempts\n(no NS found or dig missing)\n")
    text="".join(lines); outpath.write_text(text, encoding="utf-8")
    print(C.grey+text+C.reset); neon_ok(f"Saved → {outpath}"); case_log(ACTIVE_CASE, f"SAVED: {outpath}")

# --- R) Robots + Sitemap + Quick Dir Probe ---
COMMON_PATHS = [
    "admin/","login/","administrator/","_admin/","console/","cpanel/","server-status",
    ".git/HEAD",".env","phpinfo.php",".well-known/security.txt",".well-known/change-password"
]
def http_get(url:str, ua:str="BlackIce/1.8.1", timeout:int=10):
    req = Request(url, headers={"User-Agent": ua})
    try:
        with urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.getcode(), r.headers, body
    except Exception as e:
        return None, {}, b"[error] "+str(e).encode()

def task_web_robots_sitemap_probe():
    header(); print(frame("ROBOTS / SITEMAP / DIR PROBE"))
    base = ask("Base URL (e.g. https://example.com):")
    if not base: return
    if not re.match(r"^https?://", base): base = "http://" + base
    paths = case_paths(ACTIVE_CASE); outdir = paths["scans"]
    hosttag = safe_name(urlparse(base).netloc)
    out = outdir / f"web_probe_{hosttag}.txt"
    lines=[]
    for path in ["/robots.txt","/sitemap.xml","/sitemap_index.xml"]:
        url = urljoin(base, path)
        code, headers, body = http_get(url, timeout=12)
        lines.append(f"== {url} ==\n")
        lines.append(f"HTTP {code}\n")
        if code and code < 400 and body:
            txt = body.decode("utf-8","ignore")
            lines.append(txt[:20000] + ("\n...\n" if len(txt)>20000 else "\n"))
        else:
            lines.append("(no body)\n")
        lines.append("\n")
    lines.append("== Quick Dir Probe ==\n")
    for p in COMMON_PATHS:
        url = urljoin(base, "/"+p)
        code, headers, body = http_get(url, timeout=8)
        lines.append(f"{code or 'ERR'}  {url}\n")
    text="".join(lines); out.write_text(text, encoding="utf-8")
    print(C.grey+text+C.reset); neon_ok(f"Saved → {out}"); case_log(ACTIVE_CASE, f"SAVED: {out}")

# --- C) Lite Crawler (depth 1–2) ---
class LinkParser(HTMLParser):
    def __init__(self): super().__init__(); self.links=[]; self.title=None
    def handle_starttag(self, tag, attrs):
        if tag.lower()=="a":
            href = dict(attrs).get("href")
            if href: self.links.append(href)
    def handle_data(self, data):
        if self.lasttag and self.lasttag.lower()=="title":
            s = (self.title or "") + data.strip()
            self.title = s[:200]

def fetch_url(u:str, base_host:str, timeout:int=10):
    code, headers, body = http_get(u, timeout=timeout)
    title=""; links=[]
    if code and body and b"<" in body[:4096]:
        p=LinkParser()
        try: p.feed(body.decode("utf-8","ignore"))
        except Exception: pass
        title = (p.title or "").strip()
        norm=[]
        for href in p.links:
            try:
                full = urljoin(u, href)
                if urlparse(full).netloc == base_host:
                    norm.append(full)
            except Exception:
                pass
        links = sorted(set(norm))
    tech=[]
    sv = (headers.get("server") or "").strip()
    if sv: tech.append(f"Server:{sv}")
    xpb = headers.get("x-powered-by")
    if xpb: tech.append(f"X-Powered-By:{xpb.strip()}")
    return {"url": u, "code": code, "title": title, "links": links, "tech": tech}

def task_crawler_lite():
    header(); print(frame("LITE CRAWLER"))
    start = ask("Start URL (e.g. https://example.com):")
    depth = ask("Depth [1-2] (default 1):","1")
    try: depth = max(1, min(2, int(depth)))
    except Exception: depth=1
    if not start: return
    if not re.match(r"^https?://", start): start = "http://" + start
    host = urlparse(start).netloc
    paths = case_paths(ACTIVE_CASE); out = paths["scans"] / f"crawl_{safe_name(host)}.txt"
    seen=set(); frontier=[start]; results=[]
    for d in range(depth):
        next_frontier=[]
        for u in frontier:
            if u in seen: continue
            seen.add(u)
            r = fetch_url(u, host, timeout=12)
            results.append(r)
            for l in r["links"]:
                if l not in seen and len(next_frontier)<200: next_frontier.append(l)
        frontier = next_frontier
    lines=[]
    for r in results:
        lines.append(f"URL: {r['url']}\nHTTP: {r['code']}\nTitle: {r['title']}\nTech: {', '.join(r['tech'])}\nLinks ({len(r['links'])}):")
        for l in r["links"]: lines.append("  - "+l)
        lines.append("\n")
    text="\n".join(lines); out.write_text(text, encoding="utf-8")
    print(C.grey+text+C.reset); neon_ok(f"Saved → {out}"); case_log(ACTIVE_CASE, f"SAVED: {out}")

# --- W) Wayback Snapshots ---
def fetch_json(url:str, timeout:int=12):
    try:
        req = Request(url, headers={"User-Agent":"BlackIce/1.8.1"})
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8","ignore"))
    except Exception as e:
        return {"error": str(e)}

def task_wayback():
    header(); print(frame("WAYBACK SNAPSHOTS"))
    target = ask("Domain or URL (e.g. example.com or https://example.com):")
    if not target: return
    domain = target
    if re.match(r"^https?://", target):
        domain = urlparse(target).netloc
    api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50&filter=statuscode:200&collapse=digest"
    data = fetch_json(api)
    paths = case_paths(ACTIVE_CASE); out = paths["scans"] / f"wayback_{safe_name(domain)}.txt"
    lines=[]
    if isinstance(data, list) and data:
        head = data[0]; rows = data[1:]
        idx = {name:i for i,name in enumerate(head)}
        for row in rows[:50]:
            try:
                ts = row[idx.get("timestamp",1)]
                url = row[idx.get("original",2)]
                year = ts[:4]; snap = f"https://web.archive.org/web/{ts}/{url}"
                lines.append(f"{year}  {snap}")
            except Exception:
                pass
    else:
        lines.append(str(data))
    text="\n".join(lines) if lines else "(no snapshots found)"
    out.write_text(text, encoding="utf-8"); print(C.grey+text+C.reset)
    neon_ok(f"Saved → {out}"); case_log(ACTIVE_CASE, f"SAVED: {out}")

# --- X) ASN → Prefixes (Team Cymru) ---
def task_asn_prefixes():
    header(); print(frame("ASN → PREFIXES (Team Cymru)"))
    asn = ask("ASN (e.g. AS13335 or 13335):")
    if not asn: return
    asn = asn.upper()
    if not asn.startswith("AS"):
        asn = "AS"+re.sub(r"\D","",asn)
    paths = case_paths(ACTIVE_CASE); out = paths["scans"] / f"asn_{safe_name(asn)}_prefixes.txt"
    if which("whois"):
        try:
            txt = subprocess.check_output(["whois","-h","whois.cymru.com","-v",asn], text=True, stderr=subprocess.STDOUT, timeout=20)
        except Exception as e:
            txt = f"[whois error] {e}\n"
    else:
        txt = "[!] whois not installed.\n"
    out.write_text(txt, encoding="utf-8"); print(C.grey+txt+C.reset)
    neon_ok(f"Saved → {out}"); case_log(ACTIVE_CASE, f"SAVED: {out}")

# --- G) Batch Screenshots (gowitness) ---
def task_gowitness_batch():
    header(); print(frame("BATCH SCREENSHOTS — GOWITNESS"))
    if not which("gowitness"):
        neon_warn("gowitness not installed."); return
    mode = ask("Mode: [1] comma list  [2] file with URLs ->","1")
    urls=[]
    if mode=="2":
        f = ask("Path to file with one URL per line:")
        if not f or not Path(f).exists():
            neon_warn("File not found."); return
        urls = [ln.strip() for ln in Path(f).read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    else:
        s = ask("Enter comma-separated URLs:")
        urls = [u.strip() for u in s.split(",") if u.strip()]
    if not urls:
        neon_warn("No URLs provided."); return
    paths = case_paths(ACTIVE_CASE); outdir = paths["scans"] / "gowitness"; outdir.mkdir(exist_ok=True)
    tmp = outdir / f"urls_{int(time.time())}.txt"
    tmp.write_text("\n".join(urls), encoding="utf-8")
    run_cmd(["gowitness","file","-f",str(tmp),"--destination",str(outdir)], None, timeout=600, case=ACTIVE_CASE)
    neon_ok(f"Screenshots → {outdir}"); case_log(ACTIVE_CASE, f"SAVED: {outdir}")

# ---------------------- Reports (kept) ----------------------
def task_save_report_json():
    header(); print(frame(f"CONSOLIDATED REPORT — {ACTIVE_CASE} (JSON)"))
    paths = case_paths(ACTIVE_CASE)
    report = {
        "case": ACTIVE_CASE,
        "generated_at": datetime.utcnow().isoformat()+"Z",
        "scans_dir": str(paths["scans"]),
        "files": sorted([str(p) for p in paths["scans"].glob('**/*') if p.is_file()])
    }
    fpath = paths["reports"] / f"blackice_report_{int(time.time())}.json"
    fpath.write_text(json.dumps(report, indent=2), encoding="utf-8")
    neon_ok(f"Wrote report → {fpath}"); case_log(ACTIVE_CASE, f"SAVED: {fpath}")

def html_escape(s:str) -> str:
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

def build_html_report(case:str) -> Path:
    paths = case_paths(case)
    now = datetime.utcnow().isoformat()+"Z"
    files = sorted([p for p in paths["scans"].glob("**/*") if p.is_file()])
    css = """
body{background:#0b0e14;color:#c8d3f5;font-family:ui-monospace,Menlo,Consolas,monospace;margin:0;padding:0}
.header{padding:24px 28px;background:linear-gradient(90deg,#ff6ec7, #21d4fd 70%);-webkit-background-clip:text;background-clip:text;color:transparent;font-weight:800;font-size:24px;letter-spacing:.5px}
.sub{color:#8e98c3;margin:-10px 28px 12px 28px;font-size:12px}
.card{border:1px solid #2a2f45;border-radius:10px;margin:18px 28px;background:#0f1320;box-shadow:0 0 20px rgba(33,212,253,.05)}
.card h3{margin:0;padding:12px 16px;background:#11162a;border-bottom:1px solid #2a2f45;color:#21d4fd}
pre{margin:0;padding:14px 16px;white-space:pre-wrap;word-wrap:break-word;color:#c8d3f5}
.kv{display:flex;gap:16px;flex-wrap:wrap;margin:8px 28px}
.kv div{background:#0f1320;border:1px solid #2a2f45;border-radius:8px;padding:10px 12px;color:#a5b0e0}
.footer{color:#667; font-size:11px;margin:24px 28px 40px 28px}
"""
    html = [f"<!doctype html><meta charset='utf-8'><title>BlackIce Report — {case}</title><style>{css}</style>"]
    html.append(f"<div class='header'>BLACKICE REPORT<span style='border:1px solid #384063;border-radius:999px;padding:2px 8px;margin-left:8px;color:#b0baf5'>case:{html_escape(case)}</span></div>")
    html.append(f"<div class='sub'>generated: {html_escape(now)}</div>")
    html.append("<div class='kv'>")
    html.append(f"<div>scan files: {len(files)}</div>")
    slog = paths['session_log']; entries = 0
    if slog.exists():
        try: entries = len(slog.read_text(encoding='utf-8', errors='ignore').splitlines())
        except Exception: entries = 0
    html.append(f"<div>session entries: {entries}</div>")
    html.append("</div>")
    if slog.exists():
        try:
            logtxt = "\n".join(slog.read_text(encoding='utf-8', errors='ignore').splitlines()[-200:])
            html.append("<div class='card'><h3>Session Log (last 200)</h3><pre>"+html_escape(logtxt)+"</pre></div>")
        except Exception: pass
    for p in files:
        try: txt = p.read_text(encoding='utf-8', errors='ignore')
        except Exception as e: txt = f"[error reading {p.name}: {e}]"
        html.append(f"<div class='card'><h3>{html_escape(str(p.relative_to(paths['root'])) )}</h3><pre>{html_escape(txt)}</pre></div>")
    html.append("<div class='footer'>Made with ♥ in the neon dusk — BlackIce v1.8.1</div>")
    out = paths["reports"] / f"blackice_report_{int(time.time())}.html"
    out.write_text("\n".join(html), encoding="utf-8")
    return out

def task_generate_html_report():
    header(); print(frame(f"NEON HTML REPORT — {ACTIVE_CASE}"))
    out = build_html_report(ACTIVE_CASE)
    neon_ok(f"Wrote HTML → {out}"); case_log(ACTIVE_CASE, f"SAVED: {out}")

# ---------------------- Main ----------------------
def main():
    # Self-strip BOM if saved as UTF-8 with BOM
    try:
        with open(__file__, "rb") as f:
            b = f.read()
        if b.startswith(b"\xef\xbb\xbf"):
            with open(__file__, "wb") as f: f.write(b.lstrip(b"\xef\xbb\xbf"))
    except Exception:
        pass

    boot_sequence(); ensure_case_dirs(ACTIVE_CASE)

    while True:
        header(); show_missing_tools()
        choice = menu().lower()
        if   choice=="0": action_switch_case()
        elif choice=="l": action_view_session_log()
        elif choice=="1": task_ping()
        elif choice=="2": task_dns_lookup_quick()
        elif choice=="4": task_tls_info()
        elif choice=="5": task_port_scan()
        elif choice=="9": task_whois()
        elif choice=="a": task_ip_intel()
        elif choice=="t": task_traceroute()
        elif choice=="b": task_banner_grabber()
        elif choice=="r": task_web_robots_sitemap_probe()
        elif choice=="c": task_crawler_lite()
        elif choice=="w": task_wayback()
        elif choice=="d": task_dns_suite()
        elif choice=="x": task_asn_prefixes()
        elif choice=="g": task_gowitness_batch()
        elif choice=="s": task_save_report_json()
        elif choice=="h": task_generate_html_report()
        elif choice=="q":
            clr(); print(f"{C.c5}Shutting down BlackIce subsystems…{C.reset}")
            dots("Saving session", 18, C.c4); print(f"{C.c3}Good hunting, operator.{C.reset}"); break
        else:
            neon_warn("Unknown option.")
        input(f"\n{C.c0}↩  Press Enter to return to menu…{C.reset}")

if __name__ == "__main__":
    main()