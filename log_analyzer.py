#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           MULTI-FORMAT LOG ANALYZER  v1.0                       ║
║           Cybersecurity Portfolio — Don-cybertech                ║
╠══════════════════════════════════════════════════════════════════╣
║  Supports : Apache/Nginx, Syslog/Auth, Windows Event, JSON      ║
║  Detects  : Brute Force · SQLi · XSS · LFI · Command Injection  ║
║  Features : GeoIP Lookup · Anomaly Detection · Real-Time Watch  ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python log_analyzer.py --demo
  python log_analyzer.py --file access.log
  python log_analyzer.py --file auth.log --watch
  python log_analyzer.py --file access.log --report report.html
  python log_analyzer.py --file access.log --geoip
"""

import re
import sys
import os
import json
import time
import threading
import argparse
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.request import urlopen
from urllib.error import URLError

# ── Windows: Enable VT100/ANSI terminal colors ────────────────────────────────
if sys.platform == "win32":
    import ctypes
    try:
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        pass

# ── Terminal color palette ────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

# ── Detection thresholds ──────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 5    # failed attempts in window
BRUTE_FORCE_WINDOW     = 300  # 5-minute sliding window (seconds)
SCAN_404_THRESHOLD     = 10   # 404s from one IP = scanner
ANOMALY_SPIKE          = 3.0  # request spike multiplier
ANOMALY_MIN_BASELINE   = 5    # min hourly avg before spiking logic applies
GEOIP_MAX_LOOKUPS      = 20   # cap free API calls per run

# ── Log format regex patterns ─────────────────────────────────────────────────
APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
SYSLOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)'
)
WINEVENT_RE = re.compile(
    r'(?P<level>Information|Warning|Error|Critical|Audit\s+(?:Success|Failure))\s+'
    r'(?P<dt>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)\s+'
    r'(?P<source>\S+)\s+(?P<evid>\d+)\s*(?P<msg>.*)'
)
IP_RE      = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
FAILED_RE  = re.compile(
    r'(?i)(?:failed|failure|invalid|incorrect|bad)\s*(?:password|auth|login|user|credential)'
)

# ── Web attack signatures ─────────────────────────────────────────────────────
ATTACK_SIGS = [
    (re.compile(r"(?i)(union[\s+/*]+select|drop[\s+/*]+table|1\s*=\s*1|--\s*$|;\s*--|\bxp_\w+|\bexec\s*\()"),
     "SQL Injection", "HIGH"),
    (re.compile(r"(?i)(<\s*script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)"),
     "XSS Attack", "HIGH"),
    (re.compile(r"(?:%2e%2e[%/\\]|%252e|\.\.\/|\.\.\\|\.\./\./|\.%2f)"),
     "Path Traversal", "HIGH"),
    (re.compile(r"(?i)(\/etc\/passwd|\/etc\/shadow|\/proc\/self|win\.ini|boot\.ini)"),
     "LFI Attempt", "HIGH"),
    (re.compile(r"(?i)(cmd\.exe|\/bin\/(?:sh|bash)|powershell(?:\.exe)?|wget\s+https?|curl\s+-[so])"),
     "Command Injection", "HIGH"),
    (re.compile(r"(?i)(nikto|sqlmap|nmap\s|masscan|gobuster|dirbuster|wfuzz|ffuf|nuclei|zgrab)"),
     "Scanner Detected", "MEDIUM"),
    (re.compile(r"(?i)(\.env$|wp-admin|phpinfo|admin/config|\.git/HEAD|\.svn/)"),
     "Sensitive Path Probe", "MEDIUM"),
]

BOT_AGENT_RE = re.compile(
    r"(?i)(python-requests|go-http-client|curl\/|wget\/|scrapy|libwww|zgrab|"
    r"masscan|nmap|nuclei|sqlmap|nikto|dirbuster)"
)

# ─────────────────────────────────────────────────────────────────────────────
#  DATA MODEL
# ─────────────────────────────────────────────────────────────────────────────
class LogEntry:
    __slots__ = ["raw","timestamp","ip","method","path","status",
                 "size","agent","msg","fmt","source"]
    def __init__(self, raw="", timestamp=None, ip=None, method=None,
                 path=None, status=None, size=0, agent=None,
                 msg=None, fmt="unknown", source=None):
        self.raw       = raw
        self.timestamp = timestamp or datetime.now()
        self.ip        = ip
        self.method    = method
        self.path      = path
        self.status    = status
        self.size      = size
        self.agent     = agent or ""
        self.msg       = msg or ""
        self.fmt       = fmt
        self.source    = source or ""

# ─────────────────────────────────────────────────────────────────────────────
#  LOG PARSER
# ─────────────────────────────────────────────────────────────────────────────
class LogParser:
    """Auto-detects format then parses Apache/Nginx, Syslog, Windows Event, JSON."""

    @staticmethod
    def detect_format(lines):
        sample = [l for l in lines[:30] if l.strip()]
        scores = {"apache": 0, "syslog": 0, "windows": 0, "json": 0}
        for line in sample:
            if APACHE_RE.match(line):   scores["apache"]  += 2
            if SYSLOG_RE.match(line):   scores["syslog"]  += 2
            if WINEVENT_RE.match(line): scores["windows"] += 2
            try:
                json.loads(line);       scores["json"]    += 2
            except Exception:
                pass
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "unknown"

    @staticmethod
    def _parse_ts_apache(raw):
        try:
            return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except Exception:
            return datetime.now()

    @staticmethod
    def _parse_ts_syslog(month, day, timestr):
        try:
            return datetime.strptime(
                f"{datetime.now().year} {month} {int(day):02d} {timestr}",
                "%Y %b %d %H:%M:%S"
            )
        except Exception:
            return datetime.now()

    @staticmethod
    def _parse_ts_win(raw):
        raw = raw.strip()
        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p",
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return datetime.strptime(raw, fmt)
            except Exception:
                continue
        return datetime.now()

    @classmethod
    def parse_line(cls, line, fmt):
        line = line.rstrip()
        if not line or line.startswith("#"):
            return None
        e = LogEntry(raw=line, fmt=fmt)

        if fmt == "apache":
            m = APACHE_RE.match(line)
            if not m: return None
            e.timestamp = cls._parse_ts_apache(m.group("dt"))
            e.ip     = m.group("ip")
            e.method = m.group("method")
            e.path   = m.group("path")
            e.status = int(m.group("status"))
            sz = m.group("size")
            e.size   = int(sz) if sz and sz != '-' else 0
            e.agent  = m.group("agent") or ""
            return e

        elif fmt == "syslog":
            m = SYSLOG_RE.match(line)
            if not m: return None
            e.timestamp = cls._parse_ts_syslog(m.group("month"), m.group("day"), m.group("time"))
            e.source    = m.group("proc").strip()
            e.msg       = m.group("msg")
            ips = IP_RE.findall(e.msg)
            e.ip = ips[0] if ips else None
            return e

        elif fmt == "windows":
            m = WINEVENT_RE.match(line)
            if not m: return None
            e.timestamp = cls._parse_ts_win(m.group("dt"))
            e.source    = m.group("source")
            e.status    = int(m.group("evid"))
            e.msg       = m.group("msg")
            ips = IP_RE.findall(e.msg)
            e.ip = ips[0] if ips else None
            return e

        elif fmt == "json":
            try:
                d = json.loads(line)
                e.ip     = d.get("client_ip") or d.get("ip") or d.get("src_ip")
                e.method = d.get("method") or d.get("request_method")
                e.path   = d.get("request") or d.get("path") or d.get("uri")
                raw_st   = d.get("status") or d.get("response_code") or d.get("status_code")
                e.status = int(raw_st) if raw_st else None
                e.agent  = d.get("user_agent") or d.get("http_user_agent") or ""
                e.msg    = json.dumps(d)
                ts = d.get("time") or d.get("timestamp") or d.get("@timestamp")
                if ts:
                    for f in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                        try:
                            e.timestamp = datetime.strptime(str(ts)[:19], f)
                            break
                        except Exception:
                            continue
                return e
            except Exception:
                return None

        # unknown: try to extract IP at minimum
        ips = IP_RE.findall(line)
        if ips: e.ip = ips[0]
        e.msg = line
        return e

    @classmethod
    def parse_file(cls, filepath):
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        fmt = cls.detect_format(lines)
        entries = []
        for line in lines:
            ent = cls.parse_line(line, fmt)
            if ent:
                entries.append(ent)
        return entries, fmt

# ─────────────────────────────────────────────────────────────────────────────
#  THREAT DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class ThreatDetector:
    def __init__(self, entries):
        self.entries = entries
        self.threats = []

    def run_all(self):
        self._brute_force()
        self._web_attacks()
        self._directory_scan()
        return self.threats

    def _brute_force(self):
        fail_times = defaultdict(list)
        for e in self.entries:
            is_fail = (e.status in (401, 403)) or FAILED_RE.search(e.msg)
            if is_fail and e.ip:
                fail_times[e.ip].append(e.timestamp)

        for ip, times in fail_times.items():
            times.sort()
            max_window = 0
            for i, t0 in enumerate(times):
                window = sum(1 for t in times if 0 <= (t - t0).total_seconds() <= BRUTE_FORCE_WINDOW)
                max_window = max(max_window, window)
            if max_window >= BRUTE_FORCE_THRESHOLD:
                self.threats.append({
                    "severity": "HIGH",
                    "type": "Brute Force Attack",
                    "ip": ip,
                    "count": len(times),
                    "detail": f"{len(times)} failed auth attempts "
                              f"(peak {max_window} in {BRUTE_FORCE_WINDOW//60}min window)"
                })

    def _web_attacks(self):
        seen = set()
        for e in self.entries:
            target = (e.path or "") + " " + (e.msg or "")
            for pattern, name, severity in ATTACK_SIGS:
                key = (e.ip, name, (e.path or "")[:60])
                if key in seen:
                    continue
                if pattern.search(target):
                    seen.add(key)
                    self.threats.append({
                        "severity": severity,
                        "type": name,
                        "ip": e.ip or "N/A",
                        "count": 1,
                        "detail": f'Matched in: "{(e.path or e.msg or "")[:90]}"'
                    })
                    break

    def _directory_scan(self):
        ip_404  = Counter(e.ip for e in self.entries if e.status == 404 and e.ip)
        ip_paths = defaultdict(set)
        for e in self.entries:
            if e.status == 404 and e.ip and e.path:
                ip_paths[e.ip].add(e.path)

        for ip, count in ip_404.items():
            if count >= SCAN_404_THRESHOLD:
                unique = len(ip_paths[ip])
                self.threats.append({
                    "severity": "MEDIUM",
                    "type": "Directory / File Enumeration",
                    "ip": ip,
                    "count": count,
                    "detail": f"{count} HTTP 404s across {unique} unique paths"
                })

# ─────────────────────────────────────────────────────────────────────────────
#  ANOMALY DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self, entries):
        self.entries  = entries
        self.anomalies = []

    def run_all(self):
        self._traffic_spike()
        self._odd_hour_activity()
        self._suspicious_agents()
        self._error_rate_spike()
        return self.anomalies

    def _traffic_spike(self):
        hourly = Counter()
        for e in self.entries:
            hourly[e.timestamp.replace(minute=0, second=0, microsecond=0)] += 1
        if len(hourly) < 2:
            return
        vals  = list(hourly.values())
        avg   = sum(vals) / len(vals)
        if avg < ANOMALY_MIN_BASELINE:
            return
        for hour, count in hourly.items():
            if count >= avg * ANOMALY_SPIKE:
                self.anomalies.append({
                    "type": "Traffic Spike",
                    "detail": f"{count} requests at {hour.strftime('%H:00')} "
                              f"(avg baseline: {avg:.0f} req/hr, "
                              f"{count/avg:.1f}x spike)"
                })

    def _odd_hour_activity(self):
        odd = defaultdict(int)
        for e in self.entries:
            if 1 <= e.timestamp.hour <= 5 and e.ip:
                odd[e.ip] += 1
        for ip, count in sorted(odd.items(), key=lambda x: -x[1])[:5]:
            if count >= 5:
                self.anomalies.append({
                    "type": "Odd-Hours Activity (01:00–05:00)",
                    "detail": f"{ip} — {count} requests during off-hours window"
                })

    def _suspicious_agents(self):
        agent_ips = defaultdict(set)
        for e in self.entries:
            if e.agent and BOT_AGENT_RE.search(e.agent) and e.ip:
                agent_ips[e.agent[:80]].add(e.ip)
        for agent, ips in agent_ips.items():
            self.anomalies.append({
                "type": "Suspicious User-Agent",
                "detail": f'"{agent}" seen from {len(ips)} IP(s)'
            })

    def _error_rate_spike(self):
        hourly_total  = Counter()
        hourly_errors = Counter()
        for e in self.entries:
            h = e.timestamp.replace(minute=0, second=0, microsecond=0)
            hourly_total[h]  += 1
            if e.status and e.status >= 400:
                hourly_errors[h] += 1
        for h, total in hourly_total.items():
            if total < 10:
                continue
            err_rate = hourly_errors[h] / total
            if err_rate > 0.5:
                self.anomalies.append({
                    "type": "High Error Rate",
                    "detail": f"{err_rate*100:.0f}% error rate at "
                              f"{h.strftime('%Y-%m-%d %H:00')} "
                              f"({hourly_errors[h]}/{total} requests)"
                })

# ─────────────────────────────────────────────────────────────────────────────
#  GEOIP LOOKUP  (ip-api.com — free, no key, ~45 req/min)
# ─────────────────────────────────────────────────────────────────────────────
class GeoIP:
    _cache = {}

    @classmethod
    def lookup(cls, ip):
        if not ip:
            return None
        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.is_private or parsed.is_loopback:
                return {"country": "Private/Local", "city": "—", "org": "—", "flag": "🏠"}
        except ValueError:
            return None
        if ip in cls._cache:
            return cls._cache[ip]
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp"
            with urlopen(url, timeout=4) as resp:
                d = json.loads(resp.read().decode())
            if d.get("status") == "success":
                result = {
                    "country": d.get("country", "Unknown"),
                    "city":    d.get("city", "Unknown"),
                    "org":     d.get("org") or d.get("isp", "Unknown"),
                    "flag":    cls._flag(d.get("countryCode", ""))
                }
                cls._cache[ip] = result
                return result
        except Exception:
            pass
        return {"country": "Unknown", "city": "Unknown", "org": "Unknown", "flag": "?"}

    @staticmethod
    def _flag(cc):
        if not cc or len(cc) != 2:
            return ""
        return chr(0x1F1E0 + ord(cc[0]) - ord('A')) + chr(0x1F1E0 + ord(cc[1]) - ord('A'))

    @classmethod
    def bulk(cls, ips, limit=GEOIP_MAX_LOOKUPS):
        results = {}
        count   = 0
        unique  = list(dict.fromkeys(ips))          # preserve order, deduplicate
        for ip in unique:
            if ip in cls._cache:
                results[ip] = cls._cache[ip]
            elif count < limit:
                geo = cls.lookup(ip)
                if geo:
                    results[ip] = geo
                count += 1
                time.sleep(0.08)
        return results

# ─────────────────────────────────────────────────────────────────────────────
#  STATS
# ─────────────────────────────────────────────────────────────────────────────
def compute_stats(entries):
    total  = len(entries)
    ips    = Counter(e.ip for e in entries if e.ip)
    codes  = Counter(e.status for e in entries if e.status)
    meths  = Counter(e.method for e in entries if e.method)
    errors = sum(1 for e in entries if e.status and e.status >= 400)
    hourly = Counter(
        e.timestamp.replace(minute=0, second=0, microsecond=0)
        for e in entries
    )
    return {
        "total":      total,
        "unique_ips": len(ips),
        "top_ips":    ips.most_common(10),
        "codes":      dict(sorted(codes.items())),
        "methods":    dict(meths),
        "error_rate": round(errors / total * 100, 1) if total else 0,
        "hourly":     {k.strftime("%Y-%m-%d %H:00"): v
                       for k, v in sorted(hourly.items())},
    }

# ─────────────────────────────────────────────────────────────────────────────
#  TERMINAL OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║       MULTI-FORMAT LOG ANALYZER  v1.0                       ║
  ║       Cybersecurity Portfolio — Don-cybertech                ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Supports : Apache/Nginx · Syslog · Windows Event · JSON    ║
  ║  Features : Threat Detection · GeoIP · Anomaly · Watch      ║
  ╚══════════════════════════════════════════════════════════════╝
{C.RESET}""")

def _sev_color(sev):
    return C.RED if sev == "HIGH" else C.YELLOW

def print_summary(stats, threats, anomalies, fmt, filepath=None, geoip=None):
    LINE = f"{C.CYAN}{'─'*66}{C.RESET}"
    print(f"\n{C.CYAN}{C.BOLD}{'═'*66}")
    print(f"  LOG ANALYSIS REPORT")
    if filepath:
        print(f"  File     : {filepath}")
    print(f"  Format   : {fmt.upper()}")
    print(f"  Analyzed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*66}{C.RESET}")

    # ── Overview ──────────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}{C.WHITE}  OVERVIEW{C.RESET}")
    print(LINE)
    print(f"  {'Total Entries':<20} {C.CYAN}{stats['total']}{C.RESET}")
    print(f"  {'Unique IPs':<20} {C.CYAN}{stats['unique_ips']}{C.RESET}")
    print(f"  {'Error Rate':<20} {C.YELLOW}{stats['error_rate']}%{C.RESET}")
    threats_c = f"{C.RED}{len(threats)}{C.RESET}" if threats else f"{C.GREEN}0{C.RESET}"
    anomaly_c = f"{C.YELLOW}{len(anomalies)}{C.RESET}" if anomalies else f"{C.GREEN}0{C.RESET}"
    print(f"  {'Threats Found':<20} {threats_c}")
    print(f"  {'Anomalies Found':<20} {anomaly_c}")

    # ── HTTP methods ──────────────────────────────────────────────────────────
    if stats["methods"]:
        print(f"\n{C.BOLD}{C.WHITE}  HTTP METHODS{C.RESET}")
        print(LINE)
        for meth, count in sorted(stats["methods"].items(), key=lambda x: -x[1]):
            bar = f"{C.DIM}{'|' * min(count, 40)}{C.RESET}"
            print(f"  {C.CYAN}{meth:<8}{C.RESET}  {count:>6}   {bar}")

    # ── HTTP status codes ─────────────────────────────────────────────────────
    if stats["codes"]:
        print(f"\n{C.BOLD}{C.WHITE}  HTTP STATUS CODES{C.RESET}")
        print(LINE)
        for code, count in sorted(stats["codes"].items()):
            color = C.GREEN if code < 400 else (C.YELLOW if code < 500 else C.RED)
            bar   = f"{C.DIM}{'|' * min(count, 40)}{C.RESET}"
            print(f"  {color}{code}{C.RESET}  {count:>6}   {bar}")

    # ── Top IPs ───────────────────────────────────────────────────────────────
    if stats["top_ips"]:
        print(f"\n{C.BOLD}{C.WHITE}  TOP SOURCE IPs{C.RESET}")
        print(LINE)
        for rank, (ip, count) in enumerate(stats["top_ips"], 1):
            geo_str = ""
            if geoip and ip in geoip:
                g = geoip[ip]
                geo_str = f"  {g.get('flag','')} {g['country']}, {g['city']} | {g['org'][:28]}"
            bar = f"{C.DIM}{'|' * min(count, 30)}{C.RESET}"
            print(f"  {rank:>2}. {C.CYAN}{ip:<18}{C.RESET} {count:>6} req  {bar}")
            if geo_str:
                print(f"      {C.DIM}{geo_str}{C.RESET}")

    # ── Threats ───────────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}{C.WHITE}  THREATS DETECTED{C.RESET}")
    print(LINE)
    if threats:
        for t in threats:
            sc = _sev_color(t["severity"])
            print(f"  {sc}[{t['severity']}]{C.RESET}  {C.BOLD}{t['type']}{C.RESET}")
            print(f"           IP     : {C.CYAN}{t['ip']}{C.RESET}")
            print(f"           Detail : {t['detail']}")
            print()
    else:
        print(f"  {C.GREEN}No threats detected.{C.RESET}\n")

    # ── Anomalies ─────────────────────────────────────────────────────────────
    print(f"{C.BOLD}{C.WHITE}  ANOMALIES{C.RESET}")
    print(LINE)
    if anomalies:
        for a in anomalies:
            print(f"  {C.YELLOW}[ANOMALY]{C.RESET}  {C.BOLD}{a['type']}{C.RESET}")
            print(f"            {a['detail']}\n")
    else:
        print(f"  {C.GREEN}No anomalies detected.{C.RESET}\n")

    print(f"{C.CYAN}{'═'*66}{C.RESET}\n")

# ─────────────────────────────────────────────────────────────────────────────
#  HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────
def generate_html(stats, threats, anomalies, fmt, filepath=None, geoip=None):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src  = filepath or "Demo / Stdin"

    def sev_badge(sev):
        color = "#ef4444" if sev == "HIGH" else "#f59e0b"
        return f'<span class="badge" style="background:{color}">{sev}</span>'

    def stat_card(label, value, color="#06b6d4"):
        return f"""
        <div class="card">
          <div class="stat-val" style="color:{color}">{value}</div>
          <div class="stat-label">{label}</div>
        </div>"""

    # Build hourly sparkline data
    hours  = list(stats["hourly"].keys())
    counts = list(stats["hourly"].values())
    max_c  = max(counts, default=1)
    sparkline_bars = "".join(
        f'<div class="spark-bar" style="height:{int(c/max_c*50)+4}px" '
        f'title="{h}: {c} req"></div>'
        for h, c in zip(hours, counts)
    ) if counts else "<em style='color:#666'>No data</em>"

    # Build top-IP rows
    ip_rows = ""
    for rank, (ip, count) in enumerate(stats["top_ips"], 1):
        geo_cell = ""
        if geoip and ip in geoip:
            g = geoip[ip]
            geo_cell = f"{g.get('flag','')} {g['country']}, {g['city']}<br><small>{g['org'][:40]}</small>"
        else:
            geo_cell = '<span style="color:#666">—</span>'
        pct = round(count / stats["total"] * 100, 1) if stats["total"] else 0
        ip_rows += f"""
        <tr>
          <td style="color:#6366f1">{rank}</td>
          <td style="color:#06b6d4;font-family:monospace">{ip}</td>
          <td>{count:,}</td>
          <td>
            <div class="bar-bg">
              <div class="bar-fill" style="width:{pct}%;background:#06b6d4"></div>
            </div>
            <span style="font-size:0.75rem;color:#94a3b8">{pct}%</span>
          </td>
          <td>{geo_cell}</td>
        </tr>"""

    # Build status code rows
    code_rows = ""
    for code, cnt in sorted(stats["codes"].items()):
        if not code: continue
        pct = round(cnt / stats["total"] * 100, 1) if stats["total"] else 0
        if code < 400:   color = "#22c55e"
        elif code < 500: color = "#f59e0b"
        else:            color = "#ef4444"
        code_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{code}</span></td>
          <td>{cnt:,}</td>
          <td>
            <div class="bar-bg">
              <div class="bar-fill" style="width:{pct}%;background:{color}"></div>
            </div>
            <span style="font-size:0.75rem;color:#94a3b8">{pct}%</span>
          </td>
        </tr>"""

    # Build threat rows
    threat_rows = ""
    if threats:
        for t in threats:
            color = "#ef4444" if t["severity"] == "HIGH" else "#f59e0b"
            threat_rows += f"""
            <tr>
              <td>{sev_badge(t["severity"])}</td>
              <td style="font-weight:600;color:#f1f5f9">{t["type"]}</td>
              <td style="color:#06b6d4;font-family:monospace">{t["ip"]}</td>
              <td style="color:#94a3b8;font-size:0.85rem">{t["detail"]}</td>
            </tr>"""
    else:
        threat_rows = '<tr><td colspan="4" style="text-align:center;color:#22c55e">No threats detected</td></tr>'

    # Build anomaly rows
    anomaly_rows = ""
    if anomalies:
        for a in anomalies:
            anomaly_rows += f"""
            <tr>
              <td><span class="badge" style="background:#f59e0b">ANOMALY</span></td>
              <td style="font-weight:600;color:#f1f5f9">{a["type"]}</td>
              <td style="color:#94a3b8;font-size:0.85rem">{a["detail"]}</td>
            </tr>"""
    else:
        anomaly_rows = '<tr><td colspan="3" style="text-align:center;color:#22c55e">No anomalies detected</td></tr>'

    tc = len([t for t in threats if t["severity"]=="HIGH"])
    mc = len([t for t in threats if t["severity"]=="MEDIUM"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Log Analyzer Report — {src}</title>
  <style>
    :root {{
      --bg:      #0a0a0f;
      --surface: #111827;
      --card:    #1e293b;
      --border:  #2d3748;
      --text:    #f1f5f9;
      --muted:   #94a3b8;
      --cyan:    #06b6d4;
      --green:   #22c55e;
      --yellow:  #f59e0b;
      --red:     #ef4444;
      --purple:  #6366f1;
    }}
    * {{ box-sizing: border-box; margin:0; padding:0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, sans-serif;
      padding: 2rem;
      min-height: 100vh;
    }}
    header {{
      text-align: center;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }}
    header h1 {{
      font-size: 1.9rem;
      font-weight: 700;
      color: var(--cyan);
      letter-spacing: 0.05em;
    }}
    header .sub {{
      color: var(--muted);
      font-size: 0.9rem;
      margin-top: 0.4rem;
    }}
    .meta-grid {{
      display: flex;
      gap: 2rem;
      justify-content: center;
      flex-wrap: wrap;
      margin-top: 0.8rem;
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .meta-grid span b {{ color: var(--text); }}

    /* stat cards */
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.2rem 1rem;
      text-align: center;
    }}
    .stat-val   {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
    .stat-label {{ font-size: 0.78rem; color: var(--muted); margin-top: 0.4rem; text-transform: uppercase; letter-spacing: 0.06em; }}

    /* section */
    section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}
    section h2 {{
      font-size: 1rem;
      font-weight: 600;
      color: var(--cyan);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    th {{ text-align: left; color: var(--muted); font-weight: 500; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255,255,255,0.02); }}

    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      color: #fff;
    }}
    .bar-bg {{ display: inline-block; width: 100px; height: 6px; background: var(--border); border-radius: 3px; vertical-align: middle; margin-right: 0.4rem; }}
    .bar-fill {{ height: 100%; border-radius: 3px; }}

    /* sparkline */
    .sparkline {{
      display: flex;
      align-items: flex-end;
      gap: 2px;
      height: 60px;
      overflow-x: auto;
      padding-top: 6px;
    }}
    .spark-bar {{
      flex: 0 0 6px;
      background: var(--cyan);
      border-radius: 2px 2px 0 0;
      opacity: 0.75;
      cursor: pointer;
      transition: opacity .15s;
    }}
    .spark-bar:hover {{ opacity: 1; }}

    footer {{
      text-align: center;
      margin-top: 2.5rem;
      color: var(--muted);
      font-size: 0.8rem;
    }}
  </style>
</head>
<body>

<header>
  <h1>&#128196; MULTI-FORMAT LOG ANALYZER</h1>
  <p class="sub">Cybersecurity Portfolio &mdash; Don-cybertech</p>
  <div class="meta-grid">
    <span>Source: <b>{src}</b></span>
    <span>Format: <b>{fmt.upper()}</b></span>
    <span>Generated: <b>{ts}</b></span>
  </div>
</header>

<div class="cards">
  {stat_card("Total Entries",   f"{stats['total']:,}")}
  {stat_card("Unique IPs",      stats['unique_ips'])}
  {stat_card("Error Rate",      f"{stats['error_rate']}%", "#f59e0b")}
  {stat_card("HIGH Threats",    tc,  "#ef4444")}
  {stat_card("MED Threats",     mc,  "#f59e0b")}
  {stat_card("Anomalies",       len(anomalies), "#6366f1")}
</div>

<!-- Traffic Timeline -->
<section>
  <h2>&#128200; Traffic Timeline (Hourly)</h2>
  <div class="sparkline">
    {sparkline_bars}
  </div>
  <p style="font-size:0.75rem;color:var(--muted);margin-top:0.5rem">
    Hover bars to see count per hour &nbsp;|&nbsp; {len(hours)} hour intervals recorded
  </p>
</section>

<!-- Threats -->
<section>
  <h2>&#128680; Threats Detected</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Detail</th></tr></thead>
    <tbody>{threat_rows}</tbody>
  </table>
</section>

<!-- Anomalies -->
<section>
  <h2>&#9888; Anomalies</h2>
  <table>
    <thead><tr><th>Category</th><th>Type</th><th>Detail</th></tr></thead>
    <tbody>{anomaly_rows}</tbody>
  </table>
</section>

<!-- Top IPs -->
<section>
  <h2>&#127758; Top Source IPs</h2>
  <table>
    <thead><tr><th>#</th><th>IP Address</th><th>Requests</th><th>Share</th><th>GeoIP</th></tr></thead>
    <tbody>{ip_rows}</tbody>
  </table>
</section>

<!-- Status Codes -->
<section>
  <h2>&#128203; HTTP Status Distribution</h2>
  <table>
    <thead><tr><th>Code</th><th>Count</th><th>Share</th></tr></thead>
    <tbody>{code_rows}</tbody>
  </table>
</section>

<footer>
  Generated by Multi-Format Log Analyzer v1.0 &bull; Don-cybertech &bull; {ts}
</footer>

</body>
</html>"""
    return html

# ─────────────────────────────────────────────────────────────────────────────
#  REAL-TIME FILE MONITOR
# ─────────────────────────────────────────────────────────────────────────────
class RealTimeMonitor:
    """Tails a log file and analyzes new lines as they arrive."""

    def __init__(self, filepath, fmt):
        self.filepath = filepath
        self.fmt      = fmt
        self._stop    = threading.Event()

    def start(self):
        t = threading.Thread(target=self._tail, daemon=True)
        t.start()
        print(f"{C.GREEN}[WATCH]{C.RESET} Monitoring {C.CYAN}{self.filepath}{C.RESET}")
        print(f"{C.DIM}  Press Ctrl+C to stop...{C.RESET}\n")
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self._stop.set()
            print(f"\n{C.YELLOW}[WATCH]{C.RESET} Monitor stopped.")

    def _tail(self):
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)          # jump to end of file
            while not self._stop.is_set():
                line = f.readline()
                if line:
                    entry = LogParser.parse_line(line, self.fmt)
                    if entry:
                        self._process(entry)
                else:
                    time.sleep(0.2)

    def _process(self, e):
        ts  = e.timestamp.strftime("%H:%M:%S")
        ip  = e.ip or "N/A"
        # Quick threat check
        target = (e.path or "") + " " + (e.msg or "")
        for pattern, name, severity in ATTACK_SIGS:
            if pattern.search(target):
                sc = C.RED if severity == "HIGH" else C.YELLOW
                print(f"  {C.DIM}{ts}{C.RESET} {sc}[{severity}]{C.RESET} {C.BOLD}{name}{C.RESET} "
                      f"from {C.CYAN}{ip}{C.RESET} — {(e.path or e.msg or '')[:60]}")
                return
        is_fail = (e.status in (401, 403)) or FAILED_RE.search(e.msg)
        if is_fail:
            print(f"  {C.DIM}{ts}{C.RESET} {C.YELLOW}[AUTH FAIL]{C.RESET} "
                  f"{C.CYAN}{ip}{C.RESET} — {e.msg[:70] or f'HTTP {e.status}'}")
            return
        # Normal entry
        status_color = C.GREEN if (e.status or 0) < 400 else C.RED
        method = e.method or e.source or "—"
        path   = (e.path or e.msg or "")[:60]
        code   = f" {status_color}{e.status}{C.RESET}" if e.status else ""
        print(f"  {C.DIM}{ts}{C.RESET} {C.CYAN}{ip:<16}{C.RESET} "
              f"{C.MAGENTA}{method:<6}{C.RESET} {path}{code}")

# ─────────────────────────────────────────────────────────────────────────────
#  DEMO MODE
# ─────────────────────────────────────────────────────────────────────────────
DEMO_LINES = [
    # Normal traffic
    '203.0.113.42 - - [05/Apr/2024:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"',
    '203.0.113.42 - - [05/Apr/2024:09:00:02 +0000] "GET /api/users HTTP/1.1" 200 8192 "-" "Mozilla/5.0"',
    '203.0.113.42 - - [05/Apr/2024:09:00:04 +0000] "GET /api/data HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
    '172.16.0.5 - - [05/Apr/2024:09:30:00 +0000] "GET /dashboard HTTP/1.1" 200 12288 "-" "Mozilla/5.0"',
    # Brute force (6 x 401 within 5-min window at 02:xx)
    '198.51.100.7 - - [05/Apr/2024:02:15:01 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '198.51.100.7 - - [05/Apr/2024:02:15:04 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '198.51.100.7 - - [05/Apr/2024:02:15:08 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '198.51.100.7 - - [05/Apr/2024:02:15:11 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '198.51.100.7 - - [05/Apr/2024:02:15:15 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '198.51.100.7 - - [05/Apr/2024:02:15:20 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    # SQL Injection (URL-encoded, no spaces in path)
    '192.0.2.99 - - [05/Apr/2024:02:16:02 +0000] "GET /search?q=1%27+UNION+SELECT+*+FROM+users-- HTTP/1.1" 400 256 "-" "sqlmap/1.7"',
    '192.0.2.99 - - [05/Apr/2024:02:16:05 +0000] "GET /page?id=1+OR+1=1-- HTTP/1.1" 200 2048 "-" "sqlmap/1.7"',
    # LFI / Path traversal
    '10.0.0.2 - - [05/Apr/2024:02:17:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 180 "-" "curl/7.88"',
    # XSS
    '10.0.0.2 - - [05/Apr/2024:02:17:01 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 180 "-" "Mozilla/5.0"',
    # Command injection
    '203.0.113.42 - - [05/Apr/2024:10:00:00 +0000] "GET /cmd.php?cmd=/bin/sh+-c+id HTTP/1.1" 500 256 "-" "curl/7.88"',
    # Directory enumeration (gobuster — 10 x 404)
    '185.220.101.5 - - [05/Apr/2024:02:18:00 +0000] "GET /admin HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:01 +0000] "GET /admin/config HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:02 +0000] "GET /.env HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:03 +0000] "GET /wp-admin HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:04 +0000] "GET /.git/HEAD HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:05 +0000] "GET /phpinfo.php HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:06 +0000] "GET /backup.zip HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:07 +0000] "GET /config.php HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:08 +0000] "GET /database.sql HTTP/1.1" 404 256 "-" "gobuster/3.5"',
    '185.220.101.5 - - [05/Apr/2024:02:18:09 +0000] "GET /old_site.bak HTTP/1.1" 404 256 "-" "gobuster/3.5"',
]

def run_demo():
    print(f"{C.CYAN}[DEMO]{C.RESET} Generating synthetic multi-format log data...\n")
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                    delete=False, encoding="utf-8") as f:
        f.write("\n".join(DEMO_LINES))
        tmp = f.name

    entries, fmt = LogParser.parse_file(tmp)
    os.unlink(tmp)

    stats     = compute_stats(entries)
    threats   = ThreatDetector(entries).run_all()
    anomalies = AnomalyDetector(entries).run_all()
    print_summary(stats, threats, anomalies, fmt, filepath="[DEMO DATA]")
    return stats, threats, anomalies, fmt

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Multi-Format Log Analyzer — Cybersecurity Portfolio",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--demo",   action="store_true",
                        help="Run with built-in demo log data")
    parser.add_argument("--file",   metavar="PATH",
                        help="Path to log file to analyze")
    parser.add_argument("--watch",  action="store_true",
                        help="Watch file in real time (requires --file)")
    parser.add_argument("--report", metavar="OUTPUT.html",
                        help="Save dark-themed HTML report to file")
    parser.add_argument("--geoip",  action="store_true",
                        help="Enrich top IPs with GeoIP data (requires internet)")
    args = parser.parse_args()

    # ── Demo ──────────────────────────────────────────────────────────────────
    if args.demo:
        stats, threats, anomalies, fmt = run_demo()
        if args.report:
            html = generate_html(stats, threats, anomalies, fmt,
                                 filepath="Demo Data")
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"{C.GREEN}[OK]{C.RESET} HTML report saved: {C.CYAN}{args.report}{C.RESET}\n")
        return

    # ── File mode ─────────────────────────────────────────────────────────────
    if not args.file:
        parser.print_help()
        return

    if not os.path.isfile(args.file):
        print(f"{C.RED}[ERROR]{C.RESET} File not found: {args.file}\n")
        sys.exit(1)

    print(f"{C.CYAN}[*]{C.RESET} Loading: {C.BOLD}{args.file}{C.RESET}")
    entries, fmt = LogParser.parse_file(args.file)
    print(f"{C.GREEN}[OK]{C.RESET} Detected format: {C.BOLD}{fmt.upper()}{C.RESET}  "
          f"| Parsed {C.CYAN}{len(entries):,}{C.RESET} entries\n")

    if not entries:
        print(f"{C.YELLOW}[!]{C.RESET} No parseable entries found.\n")
        return

    # ── GeoIP ─────────────────────────────────────────────────────────────────
    geoip_data = None
    if args.geoip:
        top_ips = [ip for ip, _ in Counter(e.ip for e in entries if e.ip)
                   .most_common(GEOIP_MAX_LOOKUPS)]
        print(f"{C.CYAN}[*]{C.RESET} GeoIP lookup for top {len(top_ips)} IPs...")
        geoip_data = GeoIP.bulk(top_ips)
        print(f"{C.GREEN}[OK]{C.RESET} GeoIP complete ({len(geoip_data)} resolved)\n")

    # ── Analyze ───────────────────────────────────────────────────────────────
    stats     = compute_stats(entries)
    threats   = ThreatDetector(entries).run_all()
    anomalies = AnomalyDetector(entries).run_all()
    print_summary(stats, threats, anomalies, fmt,
                  filepath=args.file, geoip=geoip_data)

    # ── HTML report ───────────────────────────────────────────────────────────
    if args.report:
        html = generate_html(stats, threats, anomalies, fmt,
                             filepath=args.file, geoip=geoip_data)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"{C.GREEN}[OK]{C.RESET} HTML report saved: {C.CYAN}{args.report}{C.RESET}\n")

    # ── Real-time watch ───────────────────────────────────────────────────────
    if args.watch:
        monitor = RealTimeMonitor(args.file, fmt)
        monitor.start()

if __name__ == "__main__":
    main()
