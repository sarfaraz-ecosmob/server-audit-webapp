#!/usr/bin/env python3
"""Security Audit HTML Report Generator - v3.0 (Linux & macOS)"""
import os, sys, re, json, html, subprocess, platform, traceback as _tb

# Global exception hook: catches ANY unhandled Python error and prints
# to stdout (the SSH output) so the dashboard log_tail shows the error.
def _gen_report_excepthook(t, v, tb):
    print(f"[FATAL] gen_report.py crashed: {v}")
    _tb.print_exception(t, v, tb)
    sys.exit(1)
sys.excepthook = _gen_report_excepthook

TMP_DIR     = os.environ.get('TMP_DIR', '/tmp/audit/tmp')
HTML_REPORT = os.environ.get('HTML_REPORT', '/tmp/audit_report.html')
TIMESTAMP   = os.environ.get('TIMESTAMP', 'unknown')
WEB_TARGETS = [t for t in os.environ.get('WEB_TARGETS', '').split('\x00') if t]
IS_MAC      = platform.system() == 'Darwin'

H = html  # alias

def sh(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                       timeout=timeout, text=True).strip()
        return out if out else 'N/A'
    except: return 'N/A'

def sh_first(cmds, timeout=5):
    """Try each shell command in order, return the first non-N/A result."""
    for c in cmds:
        v = sh(c, timeout)
        if v and v != 'N/A':
            return v
    return 'N/A'

def rf(path, limit=500):
    try:
        with open(path, 'r', errors='ignore') as f:
            lines = [re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',l) for i,l in enumerate(f) if i<limit]
        return H.escape(''.join(lines))
    except: return '(no data)'

def rlines(path):
    try:
        with open(path,'r',errors='ignore') as f:
            return [re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',l.rstrip()) for l in f]
    except: return []

def load_json(path, default):
    try:
        with open(path, 'r', errors='ignore') as f:
            return json.load(f)
    except: return default

# ── OS / tool status (written by server_audit.sh) ────────────────────────────
OS_INFO = load_json(os.path.join(TMP_DIR, 'os_info.json'), {})
TOOL_STATUS = load_json(os.path.join(TMP_DIR, 'tool_status.json'), [])
os_pretty_from_scan = OS_INFO.get('os_pretty', '')

# ── Trivy kernel vulnerability scan ──────────────────────────────────────
KERNEL_VULNS = load_json(os.path.join(TMP_DIR, 'kernel-vulnerabilities.json'), [])
kv_total = len(KERNEL_VULNS)
kv_critical = sum(1 for v in KERNEL_VULNS if v.get('Severity') == 'CRITICAL')
kv_high = sum(1 for v in KERNEL_VULNS if v.get('Severity') == 'HIGH')

# ── System info (OS-aware: works on Linux and macOS) ─────────────────────────
hostname  = sh('hostname')
if IS_MAC:
    os_name = os_pretty_from_scan or sh_first(["sw_vers -productName", "uname -s"]) + ' ' + sh("sw_vers -productVersion")
    cpu     = sh("sysctl -n hw.ncpu")
    mem_b   = sh("sysctl -n hw.memsize")
    mem     = f"{int(mem_b)/1073741824:.1f} GB" if mem_b.replace('.','',1).isdigit() else 'N/A'
else:
    os_name = os_pretty_from_scan or sh("grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'\"' -f2") or sh('uname -s')
    cpu     = sh("lscpu 2>/dev/null | grep '^CPU(s):' | awk '{print $2}'")
    mem     = sh("free -h 2>/dev/null | awk '/^Mem:/{print $2}'")
kernel    = sh('uname -r')
uptime_v  = sh_first(["uptime -p", "uptime | awk -F, '{print $1}' | sed 's/.*up /up /'"])
disk      = sh("df -h / | awk 'NR==2{print $5\" used (\"$3\"/\"$2\")\"}'")
datestamp = sh('date "+%d %b %Y, %H:%M %Z"')

# ── Lynis ────────────────────────────────────────────────────────────────────
lynis_score = 'N/A'; lynis_warn = 0; lynis_sugg = 0; lynis_findings = []
clean_path = os.path.join(TMP_DIR,'lynis_clean.txt')
dat_path   = os.path.join(TMP_DIR,'lynis_report.dat')

raw_lynis = os.path.join(TMP_DIR,'lynis_report.txt')
if os.path.exists(raw_lynis):
    ansi = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
    clean = ansi.sub('', open(raw_lynis,'r',errors='ignore').read())
    open(clean_path,'w').write(clean)
    m = re.search(r'Hardening index\s*:\s*(\d+)', clean)
    if m: lynis_score = int(m.group(1))
    m = re.search(r'Warnings \((\d+)\)', clean)
    if m: lynis_warn = int(m.group(1))
    m = re.search(r'Suggestions \((\d+)\)', clean)
    if m: lynis_sugg = int(m.group(1))

if os.path.exists(dat_path):
    dat = open(dat_path,'r',errors='ignore').read()
    if lynis_score=='N/A':
        m=re.search(r'^hardening_index=(\d+)',dat,re.M)
        if m: lynis_score=int(m.group(1))
    if lynis_warn==0:  lynis_warn  = len(re.findall(r'^warning=',dat,re.M))
    if lynis_sugg==0:  lynis_sugg  = len(re.findall(r'^suggestion=',dat,re.M))
    for line in dat.split('\n'):
        if line.startswith('warning='):
            p=line[8:].split('|'); tid=p[0]; msg=p[1] if len(p)>1 else line[8:]
            lynis_findings.append({'sev':'warning','id':tid,'msg':msg.strip()})
        elif line.startswith('suggestion='):
            p=line[11:].split('|'); tid=p[0]; msg=p[1] if len(p)>1 else line[11:]
            lynis_findings.append({'sev':'suggestion','id':tid,'msg':msg.strip()})

if not lynis_findings and os.path.exists(clean_path):
    for line in open(clean_path,'r',errors='ignore'):
        m=re.match(r'^\s+!\s+(.+?)\s*(\[[-A-Z0-9]+\])?\s*$',line)
        if m: lynis_findings.append({'sev':'warning','id':(m.group(2) or '').strip('[]'),'msg':m.group(1).strip()})
        m=re.match(r'^\s+\*\s+(.+?)\s*(\[[-A-Z0-9]+\])?\s*$',line)
        if m: lynis_findings.append({'sev':'suggestion','id':(m.group(2) or '').strip('[]'),'msg':m.group(1).strip()})

lynis_pct = lynis_score if isinstance(lynis_score,int) else 0
if isinstance(lynis_score,int):
    if   lynis_score>=80: sc,sg='#57ab5a','A'
    elif lynis_score>=65: sc,sg='#2ecc71','B'
    elif lynis_score>=50: sc,sg='#c69026','C'
    elif lynis_score>=35: sc,sg='#cc6b2c','D'
    else:                  sc,sg='#e5534b','F'
else: sc,sg='#e5534b','F'

# ── SSH ───────────────────────────────────────────────────────────────────────
ssh_findings = []
SSH_CHECKS = [
    ('PermitRootLogin','yes','high','no',
     'sudo sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('PasswordAuthentication','yes','high','no',
     '# Ensure key-based auth works first!\nsudo sed -i "s/^PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('X11Forwarding','yes','medium','no',
     'sudo sed -i "s/^X11Forwarding.*/X11Forwarding no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('AllowTcpForwarding','yes','medium','no',
     'sudo sed -i "s/^AllowTcpForwarding.*/AllowTcpForwarding no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('AllowAgentForwarding','yes','medium','no',
     'sudo sed -i "s/^AllowAgentForwarding.*/AllowAgentForwarding no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('PermitEmptyPasswords','yes','high','no',
     'sudo sed -i "s/^PermitEmptyPasswords.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('LogLevel','info','low','VERBOSE',
     'sudo sed -i "s/^LogLevel.*/LogLevel VERBOSE/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
    ('UseDNS','yes','low','no',
     'sudo sed -i "s/^UseDNS.*/UseDNS no/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'),
]
SSH_CFG = os.path.join(TMP_DIR,'sshd_config.txt')
if os.path.exists(SSH_CFG):
    cfg = open(SSH_CFG,'r',errors='ignore').read().lower()
    for param,bad,sev,rec,fix in SSH_CHECKS:
        m=re.search(r'^'+param.lower()+r'\s+(\S+)',cfg,re.M)
        cur = m.group(1).strip() if m else 'default'
        if not m or cur.lower()==bad.lower():
            ssh_findings.append({'sev':sev,'param':param,'current':cur,'recommend':rec,'fix':fix})
    m=re.search(r'^port\s+(\d+)',cfg,re.M); pv=m.group(1) if m else '22'
    if pv=='22':
        ssh_findings.append({'sev':'low','param':'Port','current':'22','recommend':'non-standard port',
            'fix':'# Edit /etc/ssh/sshd_config:\nPort 2222\n# Update firewall:\nsudo ufw allow 2222/tcp\nsudo ufw deny 22/tcp\nsudo systemctl restart sshd'})
    m=re.search(r'^maxauthtries\s+(\d+)',cfg,re.M)
    mat=int(m.group(1)) if m else 6
    if mat>3:
        ssh_findings.append({'sev':'medium','param':'MaxAuthTries','current':str(mat),'recommend':'3',
            'fix':'sudo sed -i "s/^MaxAuthTries.*/MaxAuthTries 3/" /etc/ssh/sshd_config\nsudo systemctl restart sshd'})

# ── Ports ─────────────────────────────────────────────────────────────────────
port_findings = []
HR = {'3306','5432','27017','6379','11211','9200','5672'}
MR = {'21','23','25','110','143','3389','5900'}
PL = {'22':'SSH','80':'HTTP','443':'HTTPS','3306':'MySQL','5432':'PostgreSQL',
      '27017':'MongoDB','6379':'Redis','21':'FTP','23':'Telnet','25':'SMTP',
      '3389':'RDP','8080':'HTTP-alt','8443':'HTTPS-alt','33060':'MySQL-X','9200':'Elasticsearch'}
seen=set()
for line in rlines(os.path.join(TMP_DIR,'listening_ports.txt')):
    if 'LISTEN' not in line: continue
    parts=line.split()
    addr=parts[4] if len(parts)>4 else ''
    m=re.search(r'[:\[](\d+)\]?\s*$',addr)
    if not m: continue
    port=m.group(1)
    if port in seen: continue
    seen.add(port)
    risk='high' if port in HR else ('medium' if port in MR else 'low')
    port_findings.append({'port':port,'addr':addr,'svc':PL.get(port,''),'risk':risk})
port_findings.sort(key=lambda x:{'high':0,'medium':1,'low':2}[x['risk']])

# ── ZAP ───────────────────────────────────────────────────────────────────────
zc={'high':0,'medium':0,'low':0,'info':0}
for tgt in WEB_TARGETS:
    s=re.sub(r'[^a-zA-Z0-9._-]','_',re.sub(r'https?://','',tgt))
    xp=os.path.join(TMP_DIR,'zap',s,'zap_report.xml')
    if os.path.exists(xp):
        x=open(xp,'r',errors='ignore').read()
        zc['high']+=len(re.findall(r'riskcode="3"',x))
        zc['medium']+=len(re.findall(r'riskcode="2"',x))
        zc['low']+=len(re.findall(r'riskcode="1"',x))
        zc['info']+=len(re.findall(r'riskcode="0"',x))
zt=sum(zc.values())

# ── Linux Health Check (CSV from linux_health_check.sh) ──────────────────────
import csv as _csv
HEALTH_SECTIONS = []   # [{'title':..., 'rows':[{'check','status','comment'}]}]
health_counts = {'ok':0,'notok':0,'info':0,'other':0}
BAD_STATUSES  = ('NOT OK','NOTOK','FAIL','FAILED','ENABLED','CRITICAL')
GOOD_STATUSES = ('OK','DISABLED','PASS','ACTIVE','RUNNING')
hc_path = os.path.join(TMP_DIR,'health_check.csv')
if os.path.exists(hc_path):
    cur = None
    for raw in open(hc_path,'r',errors='ignore'):
        line = raw.strip()
        if not line: continue
        if ',' not in line:
            # bare line = section title ("Linux-OS global check points", "Nginx", ...)
            cur = {'title': line, 'rows': []}
            HEALTH_SECTIONS.append(cur)
            continue
        try:
            cells = next(_csv.reader([line]))
        except Exception:
            continue
        if not cells: continue
        if cells[0].strip().lower() in ('sr no','sr','no.','no'):
            # header row; "Check Point For sysctl.conf" style headers open a sub-section
            hdr = cells[1].strip() if len(cells) > 1 else ''
            m = re.match(r'check point for\s+(.+)', hdr, re.I)
            if m:
                cur = {'title': m.group(1).strip(), 'rows': []}
                HEALTH_SECTIONS.append(cur)
            continue
        check   = cells[1].strip() if len(cells) > 1 else ''
        status  = cells[2].strip() if len(cells) > 2 else ''
        comment = ', '.join(c.strip() for c in cells[3:]) if len(cells) > 3 else ''
        if not check: continue
        if cur is None:
            cur = {'title':'Health Checks','rows':[]}
            HEALTH_SECTIONS.append(cur)
        cur['rows'].append({'check':check,'status':status,'comment':comment})
        k = status.upper()
        if   k in GOOD_STATUSES: health_counts['ok']    += 1
        elif k in BAD_STATUSES:  health_counts['notok'] += 1
        elif k == 'INFO':        health_counts['info']  += 1
        else:                    health_counts['other'] += 1
HEALTH_SECTIONS = [s for s in HEALTH_SECTIONS if s['rows']]
health_total = sum(health_counts.values())
health_notok = health_counts['notok']

def health_badge(s):
    k = (s or '').upper()
    if   k in GOOD_STATUSES: cls = 'bl'
    elif k in BAD_STATUSES:  cls = 'bw'
    elif k == 'INFO':        cls = 'bi'
    else:                    cls = 'bm'
    return f'<span class="badge {cls}">{H.escape(s or "?")}</span>'

health_html = ''
if not HEALTH_SECTIONS:
    health_html = '''<div class="empty">
  <div style="font-size:40px;margin-bottom:10px">&#129658;</div>
  <div style="font-size:15px;font-weight:600;margin-bottom:6px">No Health Check Data</div>
  <div>The Linux service &amp; OS health check did not run (Linux-only, or
  <code style="background:var(--bg3);padding:2px 8px;border-radius:4px">linux-health/linux_health_check.sh</code> is missing,
  or it was skipped with <code style="background:var(--bg3);padding:2px 8px;border-radius:4px">-H</code>).</div>
</div>'''
else:
    chips = (f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px">'
             f'<span class="badge bl">OK: {health_counts["ok"]}</span>'
             f'<span class="badge bw">NOT OK: {health_counts["notok"]}</span>'
             f'<span class="badge bi">INFO / MANUAL: {health_counts["info"]}</span>'
             f'<span class="badge bm">OTHER: {health_counts["other"]}</span>'
             f'<span class="badge bs">TOTAL: {health_total}</span></div>')
    health_html = chips
    for sec_i, sec in enumerate(HEALTH_SECTIONS):
        bad = sum(1 for r in sec['rows'] if r['status'].upper() in BAD_STATUSES)
        closed = '' if bad else ' closed'
        hidden = '' if bad else ' hidden'
        cnt_lbl = (f'<span class="badge bw" style="margin-left:8px">{bad} NOT OK</span>' if bad
                   else '<span class="badge bl" style="margin-left:8px">all clear</span>')
        rows_html = ''.join(
            f'<tr><td style="color:var(--tx2);width:40px">{i+1}</td>'
            f'<td><strong>{H.escape(r["check"])}</strong></td>'
            f'<td style="width:110px">{health_badge(r["status"])}</td>'
            f'<td style="color:var(--tx3)">{H.escape(r["comment"])}</td></tr>'
            for i, r in enumerate(sec['rows']))
        health_html += f'''<div class="sec">
  <div class="sec-hdr{closed}" onclick="toggle(this)"><h3>&#129658; {H.escape(sec['title'])} <small style="font-weight:400;color:var(--tx2)">({len(sec['rows'])} checks)</small>{cnt_lbl}</h3><span class="chev">&#9660;</span></div>
  <div class="sec-body{hidden}" style="padding:0">
   <table class="tbl"><thead><tr><th>#</th><th>Check Point</th><th>Status</th><th>Comment / Remediation</th></tr></thead>
   <tbody>{rows_html}</tbody></table>
  </div>
</div>'''

# ── Raw blocks ────────────────────────────────────────────────────────────────
R={k:rf(os.path.join(TMP_DIR,v),lim) for k,v,lim in [
    ('lynis','lynis_clean.txt',600),('nmap','nmap_report.txt',200),
    ('net','network_security.txt',200),('svc','running_services.txt',80),
    ('ports','listening_ports.txt',80),('fw','iptables.txt',80),
    ('disk','disk.txt',30),('sshcfg','sshd_config.txt',80),
    ('users','user_audit.txt',100),('suid','suid_sgid.txt',80),
    ('cron','cron.txt',50),('writable','world_writable.txt',50),
    ('routes','routes.txt',30),('conn','connections.txt',80),
    ('logins','last_logins.txt',30),('osrel','os_release.txt',20),
    ('rkhunter','rkhunter_report.txt',300),
    ('health','health_check.csv',600),
    ('kernel-vulns','kernel-vulnerabilities.json',200),
]}
suid_count = max(0, len(rlines(os.path.join(TMP_DIR,'suid_sgid.txt'))))
open_count  = len(port_findings)

# ── SVG donut ─────────────────────────────────────────────────────────────────
def donut(pct,color):
    p=pct if isinstance(pct,int) else 0
    r=38; circ=2*3.14159*r; dash=circ*p/100
    return (f'<svg width="100" height="100" viewBox="0 0 100 100">'
            f'<circle cx="50" cy="50" r="{r}" fill="none" stroke="#2d333b" stroke-width="11"/>'
            f'<circle cx="50" cy="50" r="{r}" fill="none" stroke="{color}" stroke-width="11" '
            f'stroke-dasharray="{dash:.1f} {circ:.1f}" stroke-linecap="round" '
            f'transform="rotate(-90 50 50)"/>'
            f'<text x="50" y="45" text-anchor="middle" fill="{color}" '
            f'font-size="20" font-weight="800" font-family="system-ui">{p}</text>'
            f'<text x="50" y="60" text-anchor="middle" fill="#768390" '
            f'font-size="10" font-family="system-ui">/100</text></svg>')

score_svg = donut(lynis_pct, sc)

# ── ZAP alert definitions (safe for JSON - no </script>) ─────────────────────
ZAP_DEFS = [
  {"risk":"Medium","name":"Content Security Policy (CSP) Header Not Set",
   "desc":"CSP helps detect and mitigate XSS and data injection attacks. Without it browsers have no policy on which content sources are safe to load.",
   "sol":"Configure your web server to send the Content-Security-Policy response header on all pages.",
   "fix":"# Apache - httpd.conf or .htaccess:\nHeader always set Content-Security-Policy \"default-src 'self'; script-src 'self'\"\n\n# Nginx - server block:\nadd_header Content-Security-Policy \"default-src 'self';\";"},
  {"risk":"Medium","name":"Cross-Domain Misconfiguration (CORS Wildcard)",
   "desc":"The Access-Control-Allow-Origin: * header allows any domain to read responses, potentially leaking sensitive data.",
   "sol":"Restrict CORS to specific trusted domains. Never use wildcard on authenticated endpoints.",
   "fix":"# Nginx:\nadd_header Access-Control-Allow-Origin \"https://yourtrusted.domain\";\n\n# Apache .htaccess:\nHeader set Access-Control-Allow-Origin \"https://yourtrusted.domain\""},
  {"risk":"Medium","name":"Hidden File Found (.env / .git / config)",
   "desc":"A sensitive file is publicly accessible (e.g. .env, .git/config, .htpasswd), potentially leaking credentials or configuration.",
   "sol":"Block access to hidden and configuration files via web server rules.",
   "fix":"# Apache .htaccess:\n<FilesMatch \"^\\.(env|git|htpasswd|htaccess)\">\n  Require all denied\n</FilesMatch>\n\n# Nginx:\nlocation ~ /\\. {\n    deny all;\n    return 404;\n}"},
  {"risk":"Medium","name":"Missing Anti-Clickjacking Header",
   "desc":"No X-Frame-Options or CSP frame-ancestors directive found. The site can be embedded in an iframe for clickjacking attacks.",
   "sol":"Add X-Frame-Options SAMEORIGIN or CSP frame-ancestors directive to all responses.",
   "fix":"# Apache:\nHeader always append X-Frame-Options SAMEORIGIN\n\n# Nginx:\nadd_header X-Frame-Options \"SAMEORIGIN\" always;"},
  {"risk":"Low","name":"Cross-Domain JavaScript Inclusion",
   "desc":"Page loads JavaScript from third-party domains. If those CDN domains are compromised, malicious code runs on your site.",
   "sol":"Use Subresource Integrity (SRI) checksums for all third-party scripts.",
   "fix":"# Add integrity + crossorigin to external scripts:\n# Generate hash at: https://www.srihash.org/\n<link href=\"https://cdn.example.com/style.css\"\n  integrity=\"sha384-HASH\" crossorigin=\"anonymous\">"},
  {"risk":"Low","name":"Server Leaks X-Powered-By Header",
   "desc":"X-Powered-By reveals the tech stack (e.g. PHP/5.6.40), helping attackers find known vulnerabilities for that version.",
   "sol":"Remove or suppress the X-Powered-By header from all responses.",
   "fix":"# PHP - php.ini:\nexpose_php = Off\n\n# Apache - httpd.conf:\nHeader unset X-Powered-By\nHeader always unset X-Powered-By\n\n# Nginx:\nfastcgi_hide_header X-Powered-By;"},
  {"risk":"Low","name":"Server Leaks Version via Server Header",
   "desc":"The Server header exposes web server version (Apache/2.4.6 CentOS PHP/5.6.40). Note: PHP 5.6 is EOL since Dec 2018.",
   "sol":"Configure server to return minimal Server header. Upgrade PHP 5.6 immediately - it has no security patches.",
   "fix":"# Apache - httpd.conf:\nServerTokens Prod\nServerSignature Off\n\n# Nginx:\nserver_tokens off;\n\n# Upgrade PHP 5.6 to PHP 8.x:\n# Ubuntu: apt install php8.2\n# CentOS: yum install php82 remi-release"},
  {"risk":"Low","name":"Strict-Transport-Security (HSTS) Not Set",
   "desc":"Without HSTS, users can be downgraded from HTTPS to HTTP by a man-in-the-middle attacker on their first visit.",
   "sol":"Add HSTS header to all HTTPS responses with a long max-age.",
   "fix":"# Apache:\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n\n# Nginx:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"},
  {"risk":"Low","name":"Timestamp Disclosure",
   "desc":"Unix timestamps in responses could help attackers correlate sessions or predict values in weak PRNG implementations.",
   "sol":"Review API responses and HTML for unnecessary timestamp exposure.",
   "fix":"# Apache - suppress Last-Modified on sensitive pages:\nHeader unset Last-Modified\nFileETag None\n\n# Review API JSON responses and remove unnecessary unix timestamp fields"},
  {"risk":"Low","name":"X-Content-Type-Options Header Missing",
   "desc":"Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and execute files as a different type.",
   "sol":"Set X-Content-Type-Options: nosniff on all HTTP responses.",
   "fix":"# Apache:\nHeader always set X-Content-Type-Options nosniff\n\n# Nginx:\nadd_header X-Content-Type-Options nosniff always;"},
  {"risk":"Informational","name":"Information Disclosure via HTML Comments",
   "desc":"HTML or JS comments reference internal paths, TODO items, or debug info that helps attackers understand the application.",
   "sol":"Strip all debug and internal comments from production builds using a minifier.",
   "fix":"# Webpack - enable minification (removes comments):\noptimization: { minimize: true }\n\n# Never deploy source maps to production\n# Set devtool: false in webpack.config.js"},
  {"risk":"Informational","name":"Modern Web Application (SPA Detected)",
   "desc":"Site uses a JavaScript SPA (React/Vue/Angular). Standard ZAP spider may miss dynamically loaded content and auth areas.",
   "sol":"Use ZAP AJAX Spider or an authenticated scan context for deeper coverage.",
   "fix":"# Run ZAP with AJAX spider:\ndocker run -v $(pwd):/zap/wrk ghcr.io/zaproxy/zaproxy:stable \\\n  zap-full-scan.py -t https://yoursite.com -r report.html"},
  {"risk":"Informational","name":"Cache-Control Directives Need Review",
   "desc":"Cache-Control headers may allow browsers or proxies to cache pages with sensitive or session-specific content.",
   "sol":"Set strict Cache-Control for authenticated pages. Static assets can be cached with long TTLs.",
   "fix":"# Apache - authenticated pages:\nHeader always set Cache-Control \"no-cache, no-store, must-revalidate\"\nHeader always set Pragma \"no-cache\"\n\n# Nginx:\nadd_header Cache-Control \"no-cache, no-store, must-revalidate\" always;"},
]

LYNIS_FIXES = {
    "GEN-0010": "# CRITICAL: OS is end-of-life - upgrade immediately!\n# CentOS 7 EOL June 2024: migrate to AlmaLinux/Rocky Linux\n# sudo yum update  (only temporary - must migrate OS)",
    "KRNL-5820": "# /etc/security/limits.conf:\n* hard core 0\n* soft core 0\n# /etc/sysctl.conf:\nfs.suid_dumpable = 0\n# Apply: sudo sysctl -p",
    "AUTH-9229": "# /etc/pam.d/common-password - add rounds=65536 to sha512 line:\n# password [success=1] pam_unix.so sha512 shadow rounds=65536",
    "AUTH-9230": "# /etc/login.defs:\nSHA_CRYPT_MIN_ROUNDS 65536\nSHA_CRYPT_MAX_ROUNDS 65536",
    "AUTH-9282": "# Set expiry per user:\nsudo chage -M 90 USERNAME\n# Or globally /etc/login.defs:\nPASS_MAX_DAYS 90",
    "AUTH-9286": "# /etc/login.defs:\nPASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 14",
    "AUTH-9328": "# /etc/profile.d/umask.sh:\numask 027",
    "SSH-7408": "# See SSH tab for specific sshd_config changes",
    "HTTP-6640": "# CentOS: sudo yum install mod_evasive\n# Ubuntu: sudo apt install libapache2-mod-evasive\n# Configure: /etc/httpd/conf.d/mod_evasive.conf",
    "HTTP-6643": "# CentOS: sudo yum install mod_security\n# Ubuntu: sudo apt install libapache2-mod-security2\n# OWASP CRS: git clone https://github.com/coreruleset/coreruleset",
    "PHP-2372": "# php.ini (locate with: php --ini):\nexpose_php = Off\nsudo systemctl restart apache2",
    "PHP-2376": "# php.ini:\nallow_url_fopen = Off\nallow_url_include = Off\nsudo systemctl restart apache2",
    "FIRE-4513": "# Review rules:\nsudo iptables -L -n -v --line-numbers\n# Remove unused rule:\nsudo iptables -D CHAIN_NAME LINE_NUMBER\n# Save: sudo iptables-save > /etc/iptables/rules.v4",
    "HRDN-7222": "sudo chmod 750 /usr/bin/gcc /usr/bin/g++ /usr/bin/cc\nsudo chown root:root /usr/bin/gcc",
    "HRDN-7230": "# Ubuntu: sudo apt install clamav && sudo freshclam\n# CentOS: sudo yum install clamav && sudo freshclam\n# Schedule: echo '0 2 * * * clamscan -r /home' | crontab -",
    "LOGG-2154": "# /etc/rsyslog.conf:\n*.* @@logserver.yourdomain.com:514\nsudo systemctl restart rsyslog",
    "BANN-7126": "echo 'Authorized access only. Unauthorized access is prohibited.' | sudo tee /etc/issue",
    "BANN-7130": "echo 'Authorized access only. All activity is monitored.' | sudo tee /etc/issue.net",
    "FINT-4350": "# Ubuntu: sudo apt install aide\n# CentOS: sudo yum install aide\nsudo aideinit\nsudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz\n# Cron: 0 5 * * * aide --check",
    "KRNL-6000": "# /etc/sysctl.conf:\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.send_redirects = 0\nkernel.dmesg_restrict = 1\nsudo sysctl -p",
    "CONT-8104": "docker info 2>&1 | grep -i warn\n# Harden: https://docs.docker.com/engine/security/\n# Audit: docker-bench-security",
    "NETW-3200": "# /etc/modprobe.d/disable-protos.conf:\ninstall dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true\ninstall tipc /bin/true",
    "PKGS-7420": "# Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades\n# CentOS: sudo yum install yum-cron && sudo systemctl enable yum-cron --now",
    "ACCT-9622": "# Ubuntu: sudo apt install acct && sudo systemctl enable acct --now\n# CentOS: sudo yum install psacct && sudo systemctl enable psacct --now",
    "ACCT-9626": "# Ubuntu: sudo apt install sysstat\n# CentOS: sudo yum install sysstat\nsudo systemctl enable sysstat --now",
    "ACCT-9630": "# /etc/audit/rules.d/audit.rules:\n-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/sudoers -p wa -k sudoers\n# Reload: sudo augenrules --load",
    "FILE-6310": "# Use separate LVM partitions for /home /tmp /var\n# Best done at install time or with LVM tools",
    "FILE-6354": "find /tmp -mtime +90 -delete\n# Or: sudo systemd-tmpfiles --clean",
    "USB-1000": "echo 'install usb-storage /bin/true' | sudo tee /etc/modprobe.d/disable-usb-storage.conf\nsudo update-initramfs -u",
    "STRG-1846": "echo 'install firewire-core /bin/true' | sudo tee /etc/modprobe.d/disable-firewire.conf",
    "TOOL-5002": "# Install Ansible for config management:\nsudo apt install ansible  # or: yum install ansible",
}

# Ensure ALL strings are safe - no literal </script> or </
def js_safe(s):
    return s.replace('</', '<\\/')

lynis_json  = js_safe(json.dumps(lynis_findings, ensure_ascii=False))
ssh_json    = js_safe(json.dumps(ssh_findings,   ensure_ascii=False))
ports_json  = js_safe(json.dumps(port_findings,  ensure_ascii=False))
zap_json    = js_safe(json.dumps(ZAP_DEFS,       ensure_ascii=False))
fixes_json  = js_safe(json.dumps(LYNIS_FIXES,    ensure_ascii=False))
tools_json  = js_safe(json.dumps(TOOL_STATUS,    ensure_ascii=False))
health_json = js_safe(json.dumps(HEALTH_SECTIONS, ensure_ascii=False))
kernel_json = js_safe(json.dumps(KERNEL_VULNS, ensure_ascii=False))

tools_found   = [t for t in TOOL_STATUS if t.get('status') == 'found']
tools_skipped = [t for t in TOOL_STATUS if t.get('status') != 'found']
tools_pill    = ' &middot; '.join(H.escape(t['name']) for t in tools_found) or 'none detected'

# ── ZAP target cards HTML ─────────────────────────────────────────────────────
zap_cards = ''
if not WEB_TARGETS:
    zap_cards = '''<div class="empty">
  <div style="font-size:40px;margin-bottom:10px">🔬</div>
  <div style="font-size:15px;font-weight:600;margin-bottom:6px">No Web Targets Scanned</div>
  <div>Run with <code style="background:var(--bg3);padding:2px 8px;border-radius:4px">-u https://yoursite.com</code> to include a ZAP web application scan.</div>
</div>'''
else:
    for tgt in WEB_TARGETS:
        s=re.sub(r'[^a-zA-Z0-9._-]','_',re.sub(r'https?://','',tgt))
        xp=os.path.join(TMP_DIR,'zap',s,'zap_report.xml')
        hp=os.path.join(TMP_DIR,'zap',s,'zap_report.html')
        th=tm=tl=ti=0
        if os.path.exists(xp):
            x=open(xp,'r',errors='ignore').read()
            th=len(re.findall(r'riskcode="3"',x)); tm=len(re.findall(r'riskcode="2"',x))
            tl=len(re.findall(r'riskcode="1"',x)); ti=len(re.findall(r'riskcode="0"',x))
        link = f'<p style="margin-top:8px"><a href="{H.escape(hp)}" target="_blank">📄 Open full ZAP HTML report</a></p>' if os.path.exists(hp) else ''
        zap_cards += f'''<div class="zcard">
  <h4>🌐 <a href="{H.escape(tgt)}" target="_blank">{H.escape(tgt)}</a></h4>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
    <span class="badge bw">HIGH: {th}</span>
    <span class="badge bm">MEDIUM: {tm}</span>
    <span class="badge bl">LOW: {tl}</span>
    <span class="badge bi">INFO: {ti}</span>
  </div>
  {link}
</div>'''

# ── Raw section helper ────────────────────────────────────────────────────────
def raw_sec(title, key, closed=False):
    cc = ' closed' if closed else ''
    hh = ' hidden' if closed else ''
    return f'''<div class="sec">
  <div class="sec-hdr{cc}" onclick="toggle(this)"><h3>{title}</h3><span class="chev">&#9660;</span></div>
  <div class="sec-body{hh}"><pre class="raw">{R[key]}</pre></div>
</div>'''

# ── Build the complete HTML ───────────────────────────────────────────────────
page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit &mdash; {H.escape(hostname)} &mdash; {TIMESTAMP}</title>
<style>
:root{{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --bd:#30363d;--bd2:#444c56;
  --tx:#cdd9e5;--tx2:#768390;--tx3:#adbac7;
  --blue:#539bf5;--green:#57ab5a;--yellow:#c69026;
  --red:#e5534b;--orange:#cc6b2c;--purple:#986ee2;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.6}}
a{{color:var(--blue)}}a:hover{{text-decoration:underline}}

/* Header */
.hdr{{background:linear-gradient(135deg,#0d1117,#1c2128,#0d1117);border-bottom:1px solid var(--bd);padding:24px 0}}
.hdr h1{{font-size:24px;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px}}
.hdr .sub{{color:var(--tx2);font-size:12px;margin-top:4px}}
.meta-row{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.pill{{background:var(--bg3);border:1px solid var(--bd);border-radius:20px;padding:3px 12px;font-size:11px;color:var(--tx2);display:flex;align-items:center;gap:5px}}
.pill b{{color:var(--tx3)}}
.wrap{{max-width:1440px;margin:0 auto;padding:0 20px}}

/* Nav */
.nav{{background:var(--bg2);border-bottom:1px solid var(--bd);position:sticky;top:0;z-index:200;display:flex;overflow-x:auto}}
.nav button{{background:none;border:none;border-bottom:3px solid transparent;color:var(--tx2);
  padding:12px 18px;cursor:pointer;font-size:13px;font-weight:500;white-space:nowrap;
  transition:all .15s;display:flex;align-items:center;gap:6px}}
.nav button:hover{{color:var(--tx3);background:rgba(255,255,255,.04)}}
.nav button.active{{color:var(--blue);border-bottom-color:var(--blue);background:rgba(83,155,245,.06)}}
.nb{{background:var(--red);color:#fff;border-radius:10px;padding:1px 7px;font-size:10px;font-weight:700}}
.nb.o{{background:var(--orange)}}.nb.b{{background:var(--blue)}}

/* Tabs */
.tab{{display:none;padding:22px 0 60px}}.tab.active{{display:block}}

/* Score cards */
.sg{{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin-bottom:20px}}
.sc{{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:18px;
  cursor:pointer;transition:border-color .2s,box-shadow .2s;user-select:none}}
.sc:hover{{border-color:var(--bd2);box-shadow:0 4px 20px rgba(0,0,0,.3)}}
.sc .sl{{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--tx2);margin-bottom:8px;font-weight:600}}
.sc .sv{{font-size:36px;font-weight:800;line-height:1;margin-bottom:4px}}
.sc .ss{{font-size:11px;color:var(--tx2)}}

/* Sections */
.sec{{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;margin-bottom:12px;overflow:hidden}}
.sec-hdr{{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;
  cursor:pointer;background:var(--bg3);border-bottom:1px solid var(--bd);user-select:none;
  transition:background .15s}}
.sec-hdr:hover{{background:var(--bg4)}}
.sec-hdr h3{{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--tx)}}
.chev{{color:var(--tx2);font-size:12px;transition:transform .2s;flex-shrink:0}}
.sec-hdr.closed .chev{{transform:rotate(-90deg)}}
.sec-body{{padding:14px 16px}}.sec-body.hidden{{display:none}}

/* Tables */
.tbl{{width:100%;border-collapse:collapse;font-size:13px}}
.tbl th{{background:var(--bg3);color:var(--tx2);text-align:left;padding:8px 12px;
  font-size:11px;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--bd);font-weight:600}}
.tbl td{{padding:9px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}
.tbl tr:last-child td{{border-bottom:none}}
.frow{{cursor:pointer;transition:background .1s}}
.frow:hover td,.frow.open td{{background:var(--bg3)}}
.drow{{display:none;background:var(--bg4)!important;cursor:default}}
.drow.show{{display:table-row}}
.drow td{{padding:14px 16px;border-bottom:1px solid var(--bd)}}
.dbox{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.dlbl{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--tx2);margin-bottom:5px}}
.dval{{font-size:13px;color:var(--tx3);line-height:1.6}}
.fixcode{{background:var(--bg);border:1px solid var(--bd);border-radius:6px;
  padding:10px 12px;font-family:"Cascadia Code","Fira Code",Consolas,monospace;
  font-size:11.5px;color:#57ab5a;margin-top:8px;overflow-x:auto;white-space:pre;line-height:1.6}}

/* Severity badges */
.badge{{display:inline-flex;align-items:center;padding:3px 9px;border-radius:4px;
  font-size:11px;font-weight:700;letter-spacing:.3px;white-space:nowrap}}
.bw{{background:rgba(229,83,75,.15);color:#e5534b;border:1px solid rgba(229,83,75,.3)}}
.bh{{background:rgba(204,107,44,.15);color:#cc6b2c;border:1px solid rgba(204,107,44,.3)}}
.bm{{background:rgba(198,144,38,.15);color:#c69026;border:1px solid rgba(198,144,38,.3)}}
.bl{{background:rgba(87,171,90,.15);color:#57ab5a;border:1px solid rgba(87,171,90,.3)}}
.bi,.bn{{background:rgba(83,155,245,.12);color:#539bf5;border:1px solid rgba(83,155,245,.25)}}
.bs{{background:rgba(152,110,226,.12);color:#986ee2;border:1px solid rgba(152,110,226,.25)}}

/* Filter bar */
.fbar{{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:14px}}
.fbtn{{background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:5px 13px;
  font-size:12px;color:var(--tx2);cursor:pointer;transition:all .15s;user-select:none}}
.fbtn:hover{{background:var(--bg4);color:var(--tx)}}
.fbtn.on{{background:var(--bg4);border-color:var(--bd2);color:var(--tx)}}
.fbtn.on.fw{{border-color:var(--red);color:var(--red)}}
.fbtn.on.fh{{border-color:var(--orange);color:var(--orange)}}
.fbtn.on.fm{{border-color:var(--yellow);color:var(--yellow)}}
.fbtn.on.fl{{border-color:var(--green);color:var(--green)}}
.fbtn.on.fs{{border-color:var(--purple);color:var(--purple)}}
.fsrch{{background:var(--bg3);border:1px solid var(--bd);border-radius:6px;
  padding:5px 12px;font-size:12px;color:var(--tx);outline:none;min-width:220px;margin-left:auto}}
.fsrch:focus{{border-color:var(--blue)}}
.nores{{display:none;text-align:center;padding:32px;color:var(--tx2)}}

/* Info grid */
.ig{{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}}
.ii{{background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:12px 14px}}
.ik{{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--tx2);margin-bottom:3px;font-weight:600}}
.iv{{color:var(--tx3);font-size:13px;font-weight:500}}

/* Risk grid */
.rg{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}}
.rc{{background:var(--bg3);border:1px solid var(--bd);border-radius:8px;padding:14px;
  display:flex;align-items:center;gap:12px;cursor:pointer;transition:border-color .15s,transform .1s;user-select:none}}
.rc:hover{{border-color:var(--bd2);transform:translateY(-1px)}}
.ri{{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}}
.rname{{font-size:13px;font-weight:600;margin-bottom:2px;color:var(--tx)}}
.rcnt{{font-size:11px;color:var(--tx2)}}

/* ZAP */
.zcard{{background:var(--bg3);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;margin-bottom:10px}}
.zcard h4{{font-size:13px;font-weight:600;margin-bottom:10px}}

/* Pre */
pre.raw{{background:var(--bg);border:1px solid var(--bd);border-radius:6px;
  padding:12px 14px;font-family:"Cascadia Code","Fira Code",Consolas,monospace;
  font-size:11.5px;color:#adbac7;overflow:auto;max-height:450px;
  white-space:pre;line-height:1.5;tab-size:2}}

.empty{{text-align:center;padding:40px;color:var(--tx2)}}
.foot{{background:var(--bg2);border-top:1px solid var(--bd);padding:12px 0;
  text-align:center;font-size:11px;color:var(--tx2)}}
@media(max-width:600px){{.dbox{{grid-template-columns:1fr}}}}
</style>
</head>
<body>

<div class="hdr">
 <div class="wrap">
  <h1>&#127282; Security Audit Dashboard</h1>
  <div class="sub">Server Infrastructure &middot; Web Applications &middot; Network Security</div>
  <div class="meta-row">
   <div class="pill">&#128421; Host: <b>{H.escape(hostname)}</b></div>
   <div class="pill">&#128190; OS: <b>{H.escape(os_name)}</b></div>
   <div class="pill">&#128039; Kernel: <b>{H.escape(kernel)}</b></div>
   <div class="pill">&#128197; <b>{H.escape(datestamp)}</b></div>
   <div class="pill">&#128296; Active tools: <b>{tools_pill}</b></div>
  </div>
 </div>
</div>

<nav class="nav" id="main-nav">
 <div class="wrap" style="display:flex;width:100%;padding:0">
  <button data-tab="overview" class="active">&#128202; Overview</button>
  <button data-tab="findings">&#128680; All Findings <span class="nb" id="fcnt">&#8230;</span></button>
  <button data-tab="infra">&#128737; Infrastructure</button>
  <button data-tab="network">&#127760; Network</button>
  <button data-tab="webapp">&#128300; Web App <span class="nb o" id="zcnt">{zt}</span></button>
  <button data-tab="health">&#129658; Health <span class="nb {'' if health_notok else 'b'}" id="hcnt">{health_notok}</span></button>
  <button data-tab="users">&#128100; Users</button>
  <button data-tab="tools">&#128295; Tools <span class="nb {'o' if tools_skipped else 'b'}" id="tcnt">{len(tools_skipped)}</span></button>
  <button data-tab="raw">&#128196; Raw Data</button>
 </div>
</nav>

<div class="wrap">

<!-- OVERVIEW -->
<div id="t-overview" class="tab active">
 <div class="sg" style="margin-top:20px">
  <div class="sc" data-goto="infra" style="display:flex;align-items:center;gap:14px">
   {score_svg}
   <div>
    <div class="sl">Lynis Hardening</div>
    <div style="font-size:12px;color:var(--tx2);margin-top:2px">Grade: <b style="color:{sc}">{sg}</b></div>
    <div style="font-size:11px;color:var(--tx2);margin-top:2px">{lynis_warn} warnings &middot; {lynis_sugg} suggestions</div>
   </div>
  </div>
  <div class="sc" data-goto="findings" data-filter="warning">
   <div class="sl">Critical Warnings</div>
   <div class="sv" style="color:var(--red)">{lynis_warn}</div>
   <div class="ss">Infrastructure warnings (Lynis)</div>
  </div>
  <div class="sc" data-goto="findings" data-filter="suggestion">
   <div class="sl">Suggestions</div>
   <div class="sv" style="color:var(--purple)">{lynis_sugg}</div>
   <div class="ss">Hardening improvements</div>
  </div>
  <div class="sc" data-goto="network">
   <div class="sl">Open Ports</div>
   <div class="sv" style="color:var(--blue)">{open_count}</div>
   <div class="ss">Listening services detected</div>
  </div>
  <div class="sc" data-goto="webapp">
   <div class="sl">Web App Alerts</div>
   <div class="sv" style="color:var(--orange)">{zt}</div>
   <div class="ss">ZAP: {zc['high']} high &middot; {zc['medium']} med &middot; {zc['low']} low</div>
  </div>
  <div class="sc">
   <div class="sl">SUID/SGID Files</div>
   <div class="sv" style="color:var(--yellow)">{suid_count}</div>
   <div class="ss">Privileged binaries found</div>
  </div>
  <div class="sc" data-goto="health">
   <div class="sl">Health Checks</div>
   <div class="sv" style="color:{'var(--red)' if health_notok else 'var(--green)'}">{health_notok}</div>
   <div class="ss">failed of {health_total} service &amp; OS checks</div>
  </div>
  <div class="sc" data-goto="infra">
   <div class="sl">Kernel Vulns</div>
   <div class="sv" style="color:{'var(--red)' if kv_critical else 'var(--tx2)'}">{kv_total}</div>
   <div class="ss">Trivy: {kv_critical} critical &middot; {kv_high} high</div>
  </div>
 </div>

 <div class="sec">
  <div class="sec-hdr" onclick="toggle(this)"><h3>&#127919; Risk Areas At a Glance</h3><span class="chev">&#9660;</span></div>
  <div class="sec-body"><div class="rg" id="risk-grid"></div></div>
 </div>

 <div class="sec">
  <div class="sec-hdr" onclick="toggle(this)"><h3>&#128421; System Information</h3><span class="chev">&#9660;</span></div>
  <div class="sec-body">
   <div class="ig">
    <div class="ii"><div class="ik">Hostname</div><div class="iv">{H.escape(hostname)}</div></div>
    <div class="ii"><div class="ik">Operating System</div><div class="iv">{H.escape(os_name)}</div></div>
    <div class="ii"><div class="ik">Kernel</div><div class="iv">{H.escape(kernel)}</div></div>
    <div class="ii"><div class="ik">Uptime</div><div class="iv">{H.escape(uptime_v)}</div></div>
    <div class="ii"><div class="ik">CPU Cores</div><div class="iv">{H.escape(cpu)}</div></div>
    <div class="ii"><div class="ik">Total RAM</div><div class="iv">{H.escape(mem)}</div></div>
    <div class="ii"><div class="ik">Root Disk</div><div class="iv">{H.escape(disk)}</div></div>
    <div class="ii"><div class="ik">Audit Timestamp</div><div class="iv">{TIMESTAMP}</div></div>
   </div>
  </div>
 </div>
</div>

<!-- ALL FINDINGS -->
<div id="t-findings" class="tab">
 <div style="margin-top:20px">
  <div class="fbar">
   <button class="fbtn on" id="fb-all"     data-f="all">All</button>
   <button class="fbtn fw" id="fb-warning"  data-f="warning">&#9888; Warnings</button>
   <button class="fbtn fh" id="fb-high"     data-f="high">&#128308; High</button>
   <button class="fbtn fm" id="fb-medium"   data-f="medium">&#128992; Medium</button>
   <button class="fbtn fl" id="fb-low"      data-f="low">&#128993; Low</button>
   <button class="fbtn fs" id="fb-suggestion" data-f="suggestion">&#128161; Suggestions</button>
   <input class="fsrch" type="text" placeholder="&#128269;  Search findings&#8230;" id="fsrch" oninput="srch(this.value)">
  </div>
  <div class="sec">
   <div class="sec-hdr" style="cursor:default">
    <h3 id="fhdr">All Findings</h3>
    <span id="fshown" style="color:var(--tx2);font-size:12px"></span>
   </div>
   <div class="sec-body" style="padding:0">
    <table class="tbl">
     <thead><tr>
      <th style="width:110px">Severity</th>
      <th>Finding</th>
      <th style="width:120px">Category</th>
      <th style="width:90px">ID</th>
      <th style="width:34px"></th>
     </tr></thead>
     <tbody id="ftbody"></tbody>
    </table>
    <div class="nores" id="nores">No findings match this filter.</div>
   </div>
  </div>
 </div>
</div>

<!-- INFRASTRUCTURE -->
<div id="t-infra" class="tab">
 <div style="margin-top:20px">
  {raw_sec(f"&#128737; Lynis Infrastructure Audit &nbsp;<small style='font-weight:400;color:var(--tx2)'>Score: {lynis_score}/100 &middot; Grade {sg}</small>", 'lynis')}
  <div class="sec">
   <div class="sec-hdr" onclick="toggle(this)"><h3>&#128273; SSH Configuration Analysis</h3><span class="chev">&#9660;</span></div>
   <div class="sec-body">
    <div id="ssh-tbl"></div>
    <details style="margin-top:12px">
     <summary style="cursor:pointer;color:var(--tx2);font-size:12px">&#9654; View raw sshd_config</summary>
     <pre class="raw" style="margin-top:8px">{R['sshcfg']}</pre>
    </details>
   </div>
  </div>
  {raw_sec(f"&#9888; SUID / SGID Binaries ({suid_count} found)", 'suid')}
  {raw_sec("&#128197; Cron Jobs / Scheduled Tasks", 'cron')}
  {raw_sec("&#129417; Rootkit Scan (rkhunter)", 'rkhunter', True)}
  <div class="sec">
   <div class="sec-hdr" onclick="toggle(this)"><h3>&#128220; Kernel Vulnerability Scan (Trivy) &nbsp;<small style='font-weight:400;color:var(--tx2)'>{kv_total} total &middot; {kv_critical} critical</small></h3><span class="chev">&#9660;</span></div>
   <div class="sec-body" style="padding:0">
    <table class="tbl"><thead><tr>
     <th style="width:90px">Severity</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Vulnerability ID</th><th style="width:34px"></th>
    </tr></thead><tbody id="kvtbody"></tbody></table>
   </div>
  </div>
  <span style="display:none">Kernel Vulns <span id="kvcnt">{kv_total}</span></span>
  <span style="display:none">Trivy: <span id="kvcrit">{kv_critical}</span> critical</span>
 </div>
</div>

<!-- NETWORK -->
<div id="t-network" class="tab">
 <div style="margin-top:20px">
  <div class="sec">
   <div class="sec-hdr" onclick="toggle(this)">
    <h3>&#128225; Open Ports ({open_count} listening)</h3><span class="chev">&#9660;</span>
   </div>
   <div class="sec-body" style="padding:0">
    <table class="tbl"><thead><tr>
     <th style="width:80px">Port</th><th>Address</th><th style="width:160px">Service</th><th>Risk</th>
    </tr></thead><tbody id="ptbody"></tbody></table>
   </div>
  </div>
  {raw_sec("&#128269; Nmap Scan Results", 'nmap')}
  {raw_sec("&#129393; Firewall Rules", 'fw')}
  {raw_sec("&#127760; Full Network Assessment", 'net')}
 </div>
</div>

<!-- WEB APP -->
<div id="t-webapp" class="tab">
 <div style="margin-top:20px">
  {zap_cards}
  <div class="sec">
   <div class="sec-hdr" onclick="toggle(this)"><h3>&#128270; ZAP Alert Details &amp; Fix Commands</h3><span class="chev">&#9660;</span></div>
   <div class="sec-body" style="padding:0">
    <table class="tbl"><thead><tr>
     <th style="width:110px">Risk</th><th>Alert Name</th><th style="width:34px"></th>
    </tr></thead><tbody id="ztbody"></tbody></table>
   </div>
  </div>
 </div>
</div>

<!-- HEALTH (linux_health_check.sh) -->
<div id="t-health" class="tab">
 <div style="margin-top:20px">
  {health_html}
 </div>
</div>

<!-- USERS -->
<div id="t-users" class="tab">
 <div style="margin-top:20px">
  {raw_sec("&#128100; User &amp; Authentication Assessment", 'users')}
  {raw_sec("&#128275; World-Writable Files", 'writable')}
  {raw_sec("&#9881; Running Services", 'svc')}
 </div>
</div>

<!-- TOOLS -->
<div id="t-tools" class="tab">
 <div style="margin-top:20px">
  <div class="sec">
   <div class="sec-hdr" style="cursor:default">
    <h3>&#128295; Scanner Tool Availability</h3>
    <span style="color:var(--tx2);font-size:12px">{len(tools_found)} active &middot; {len(tools_skipped)} skipped</span>
   </div>
   <div class="sec-body" style="padding:0">
    <table class="tbl"><thead><tr>
     <th style="width:130px">Status</th><th style="width:160px">Tool</th><th>Path / Version</th><th>Install Command (if skipped)</th>
    </tr></thead><tbody id="tlbody"></tbody></table>
   </div>
  </div>
  <div class="empty" style="text-align:left;padding:14px 16px">
   Tools are <b>never auto-installed</b> by the scan itself. A skipped tool simply
   means that section of the dashboard has no data this run. To stage a missing
   tool, review and run <code style="background:var(--bg3);padding:2px 8px;border-radius:4px">./install_tools.sh</code>
   (dry-run by default) on this host, then re-run the audit.
  </div>
 </div>
</div>

<!-- RAW DATA -->
<div id="t-raw" class="tab">
 <div style="margin-top:20px">
  {raw_sec("&#127760; Network Config", 'routes', True)}
  {raw_sec("&#128190; Disk Usage", 'disk', True)}
  {raw_sec("&#128101; Active Connections", 'conn', True)}
  {raw_sec("&#128197; Recent Logins", 'logins', True)}
  {raw_sec("&#128295; OS Release", 'osrel', True)}
  {raw_sec("&#128220; Kernel Vulnerability Scan JSON (Trivy)", 'kernel-vulns', True)}
  {raw_sec("&#129658; Health Check CSV (linux_health_check.sh)", 'health', True)}
 </div>
</div>

</div><!-- /wrap -->
<div class="foot">Security Audit Report &nbsp;&middot;&nbsp; {H.escape(hostname)} &nbsp;&middot;&nbsp; {H.escape(datestamp)} &nbsp;&middot;&nbsp; For authorized use only</div>

<script>
var LYNIS={lynis_json};
var SSH={ssh_json};
var PORTS={ports_json};
var ZDEFS={zap_json};
var LFIXES={fixes_json};
var TOOLS={tools_json};
var HEALTH={health_json};
var KERNEL_VULNS={kernel_json};
var K_COUNT={kv_total};
var K_CRITICAL={kv_critical};
var HBAD=['NOT OK','NOTOK','FAIL','FAILED','ENABLED','CRITICAL'];

/* ---- Navigation ---- */
(function(){{
  // Nav tab buttons use data-tab attribute - no onclick needed
  document.getElementById('main-nav').addEventListener('click', function(e){{
    var btn = e.target.closest('button[data-tab]');
    if(!btn) return;
    goTab(btn.getAttribute('data-tab'), btn);
  }});

  // Score cards use data-goto
  document.addEventListener('click', function(e){{
    var card = e.target.closest('.sc[data-goto]');
    if(!card) return;
    var tab = card.getAttribute('data-goto');
    var filter = card.getAttribute('data-filter');
    var navBtn = document.querySelector('#main-nav button[data-tab="'+tab+'"]');
    goTab(tab, navBtn);
    if(filter) setFilter(filter);
  }});

  // Risk grid cards use data-goto too (set in buildRiskGrid)
  document.addEventListener('click', function(e){{
    var rc = e.target.closest('.rc[data-goto]');
    if(!rc) return;
    var tab = rc.getAttribute('data-goto');
    var navBtn = document.querySelector('#main-nav button[data-tab="'+tab+'"]');
    goTab(tab, navBtn);
  }});

  // Filter buttons use data-f attribute
  document.addEventListener('click', function(e){{
    var btn = e.target.closest('.fbtn[data-f]');
    if(!btn) return;
    setFilter(btn.getAttribute('data-f'));
  }});
}})();

function goTab(id, btn){{
  document.querySelectorAll('.tab').forEach(function(t){{t.classList.remove('active')}});
  document.querySelectorAll('#main-nav button').forEach(function(b){{b.classList.remove('active')}});
  var t = document.getElementById('t-'+id);
  if(t) t.classList.add('active');
  if(btn) btn.classList.add('active');
  window.scrollTo(0,0);
}}

function toggle(hdr){{
  hdr.classList.toggle('closed');
  hdr.nextElementSibling.classList.toggle('hidden');
}}

/* ---- Helpers ---- */
function esc(s){{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
function badge(s){{
  var map={{'warning':'bw','critical':'bw','high':'bh','medium':'bm','low':'bl',
            'suggestion':'bs','informational':'bi','info':'bi'}};
  var lbl={{'warning':'&#9888; WARNING','critical':'&#9888; CRITICAL','high':'&#128308; HIGH',
            'medium':'&#128992; MEDIUM','low':'&#128993; LOW',
            'suggestion':'&#128161; SUGGEST','informational':'&#8505; INFO','info':'&#8505; INFO'}};
  var k=s.toLowerCase();
  return '<span class="badge '+(map[k]||'bi')+'">'+(lbl[k]||s.toUpperCase())+'</span>';
}}
function sevOrd(s){{
  return {{'warning':0,'critical':0,'high':1,'medium':2,'low':3,'suggestion':4,'info':5,'informational':5}}[s.toLowerCase()]||6;
}}

/* ---- All Findings ---- */
var AF=[], curF='all', curS='';
function buildAF(){{
  AF=[];
  LYNIS.forEach(function(f){{
    AF.push({{sev:f.sev,cat:'Infrastructure',id:f.id||'',
      msg:f.msg,
      desc:'Lynis detected: '+f.msg,
      sol:LFIXES[f.id]?'See fix command below.':'Follow Lynis recommendation.',
      fix:LFIXES[f.id]||''}});
  }});
  SSH.forEach(function(f){{
    AF.push({{sev:f.sev,cat:'SSH Config',id:'SSH-7408',
      msg:f.param+' = "'+f.current+'" (should be "'+f.recommend+'")',
      desc:'SSH parameter '+f.param+' has insecure value "'+f.current+'". Recommended: "'+f.recommend+'".',
      sol:'Edit /etc/ssh/sshd_config then run: sudo systemctl restart sshd',
      fix:f.fix}});
  }});
  ZDEFS.forEach(function(a){{
    AF.push({{sev:a.risk.toLowerCase(),cat:'Web App',id:'ZAP',
      msg:a.name,desc:a.desc,sol:a.sol,fix:a.fix||''}});
  }});
  HEALTH.forEach(function(sec){{
    sec.rows.forEach(function(r){{
      if(HBAD.indexOf((r.status||'').toUpperCase())<0) return;
      AF.push({{sev:'medium',cat:'Health Check',id:'HEALTH',
        msg:sec.title+': '+r.check+' ('+r.status+')',
        desc:'linux_health_check.sh reported "'+r.status+'" for "'+r.check+'" in section "'+sec.title+'".',
        sol:r.comment||'Review this check on the host (see Health tab).',fix:''}});
    }});
  }});
  KERNEL_VULNS.forEach(function(v){{
    var sev=(v.Severity||'HIGH').toLowerCase();
    var pkg=v.PkgName||'?';
    var ver=v.InstalledVersion||'?';
    var fixed=v.FixedVersion||'?';
    var vid=v.VulnerabilityID||'TRIVY';
    var title=v.Title||(pkg+' - '+vid);
    var desc='Package: '+pkg+' '+ver+' → '+fixed+'<br>'+(v.Description||'');
    AF.push({{sev:sev,cat:'Kernel Vulnerability',id:vid,
      msg:title,
      desc:desc,
      sol:'Update the kernel package with: sudo apt update && sudo apt upgrade -y && reboot (or yum equivalent).',fix:''}});
  }});
  AF.sort(function(a,b){{return sevOrd(a.sev)-sevOrd(b.sev)}});
  document.getElementById('fcnt').textContent=AF.length;
  renderAF();
}}
function renderAF(){{
  var tbody=document.getElementById('ftbody');
  var s=curS.toLowerCase(); var shown=0; var h='';
  AF.forEach(function(f,i){{
    var sm=curF==='all'||f.sev.toLowerCase()===curF;
    var tm=!s||f.msg.toLowerCase().indexOf(s)>=0||f.cat.toLowerCase().indexOf(s)>=0;
    if(!sm||!tm) return;
    shown++;
    var fix=f.fix?'<div class="fixcode">'+esc(f.fix)+'</div>':'';
    h+='<tr class="frow" data-i="'+i+'">'
      +'<td>'+badge(f.sev)+'</td>'
      +'<td><strong>'+esc(f.msg)+'</strong></td>'
      +'<td style="color:var(--tx2)">'+esc(f.cat)+'</td>'
      +'<td><code style="font-size:11px;color:var(--tx2)">'+esc(f.id)+'</code></td>'
      +'<td style="text-align:center;color:var(--tx2);font-size:16px">&#9656;</td>'
      +'</tr>'
      +'<tr class="drow" id="fd'+i+'"><td colspan="5">'
      +'<div class="dbox">'
      +'<div><div class="dlbl">Description</div><div class="dval">'+esc(f.desc)+'</div></div>'
      +'<div><div class="dlbl">Recommended Fix</div><div class="dval">'+esc(f.sol)+fix+'</div></div>'
      +'</div></td></tr>';
  }});
  tbody.innerHTML=h;
  document.getElementById('nores').style.display=shown?'none':'block';
  document.getElementById('fshown').textContent=shown+' of '+AF.length+' findings';
  document.getElementById('fhdr').textContent=
    curF==='all'?'All Findings':
    ({{warning:'Warnings',high:'High Risk',medium:'Medium Risk',low:'Low Risk',suggestion:'Suggestions'}}[curF]||curF)+' Findings';
  // Click delegation for finding rows
  tbody.onclick=function(e){{
    var row=e.target.closest('tr.frow');if(!row)return;
    var i=parseInt(row.getAttribute('data-i'));
    var d=document.getElementById('fd'+i);
    var open=d.classList.contains('show');
    document.querySelectorAll('.drow').forEach(function(r){{r.classList.remove('show')}});
    document.querySelectorAll('tr.frow').forEach(function(r){{r.classList.remove('open')}});
    if(!open){{d.classList.add('show');row.classList.add('open');}}
  }};
}}
function setFilter(v){{
  curF=v;
  document.querySelectorAll('.fbtn[data-f]').forEach(function(b){{
    b.classList.toggle('on',b.getAttribute('data-f')===v);
  }});
  renderAF();
}}
function srch(v){{curS=v;renderAF();}}

/* ---- SSH Table ---- */
function buildSSH(){{
  var el=document.getElementById('ssh-tbl');if(!el)return;
  if(!SSH.length){{el.innerHTML='<p style="color:var(--green);padding:8px 0">&#10003; No SSH configuration issues detected.</p>';return;}}
  var h='<table class="tbl"><thead><tr><th>Severity</th><th>Parameter</th><th>Current</th><th>Recommended</th><th style="width:34px"></th></tr></thead><tbody>';
  SSH.forEach(function(f,i){{
    h+='<tr class="frow" data-si="'+i+'">'
      +'<td>'+badge(f.sev)+'</td>'
      +'<td><code>'+esc(f.param)+'</code></td>'
      +'<td><span style="color:var(--red)">'+esc(f.current)+'</span></td>'
      +'<td><span style="color:var(--green)">'+esc(f.recommend)+'</span></td>'
      +'<td style="text-align:center;color:var(--tx2);font-size:16px">&#9656;</td></tr>'
      +'<tr class="drow" id="sd'+i+'"><td colspan="5">'
      +(f.fix?'<div class="fixcode">'+esc(f.fix)+'</div>':'<span style="color:var(--tx2)">No automated fix.</span>')
      +'</td></tr>';
  }});
  h+='</tbody></table>';
  el.innerHTML=h;
  el.querySelector('tbody').onclick=function(e){{
    var row=e.target.closest('tr.frow');if(!row)return;
    var i=parseInt(row.getAttribute('data-si'));
    var d=document.getElementById('sd'+i);
    var open=d.classList.contains('show');
    document.querySelectorAll('[id^="sd"]').forEach(function(r){{r.classList.remove('show')}});
    document.querySelectorAll('tr.frow').forEach(function(r){{r.classList.remove('open')}});
    if(!open){{d.classList.add('show');row.classList.add('open');}}
  }};
}}

/* ---- Ports Table ---- */
function buildPorts(){{
  var tb=document.getElementById('ptbody');if(!tb)return;
  if(!PORTS.length){{tb.innerHTML='<tr><td colspan="4" class="empty">No port data available.</td></tr>';return;}}
  var colors={{'high':'var(--red)','medium':'var(--orange)','low':'var(--blue)'}};
  tb.innerHTML=PORTS.map(function(p){{
    var warn=p.risk==='high'?' <small style="color:var(--orange)">&#9888; Restrict to localhost</small>':
             p.risk==='medium'?' <small style="color:var(--yellow)">&#9888; Legacy protocol</small>':'';
    return '<tr style="border-left:3px solid '+colors[p.risk]+'">'
      +'<td><strong>'+esc(p.port)+'</strong></td>'
      +'<td style="color:var(--tx2);font-size:12px">'+esc(p.addr)+'</td>'
      +'<td>'+esc(p.svc||'unknown')+'</td>'
      +'<td>'+badge(p.risk)+warn+'</td></tr>';
  }}).join('');
}}

/* ---- ZAP Table ---- */
function buildZAP(){{
  var tb=document.getElementById('ztbody');if(!tb)return;
  var h=ZDEFS.map(function(a,i){{
    var fix=a.fix?'<div class="fixcode">'+esc(a.fix)+'</div>':'';
    return '<tr class="frow" data-zi="'+i+'">'
      +'<td>'+badge(a.risk)+'</td>'
      +'<td><strong>'+esc(a.name)+'</strong></td>'
      +'<td style="text-align:center;color:var(--tx2);font-size:16px">&#9656;</td></tr>'
      +'<tr class="drow" id="zd'+i+'"><td colspan="3">'
      +'<div class="dbox">'
      +'<div><div class="dlbl">Description</div><div class="dval">'+esc(a.desc)+'</div></div>'
      +'<div><div class="dlbl">Solution &amp; Fix Command</div><div class="dval">'+esc(a.sol)+fix+'</div></div>'
      +'</div></td></tr>';
  }}).join('');
  tb.innerHTML=h||'<tr><td colspan="3" class="empty">No ZAP data.</td></tr>';
  tb.onclick=function(e){{
    var row=e.target.closest('tr.frow');if(!row)return;
    var i=parseInt(row.getAttribute('data-zi'));
    var d=document.getElementById('zd'+i);
    var open=d.classList.contains('show');
    document.querySelectorAll('[id^="zd"]').forEach(function(r){{r.classList.remove('show')}});
    document.querySelectorAll('tr.frow').forEach(function(r){{r.classList.remove('open')}});
    if(!open){{d.classList.add('show');row.classList.add('open');}}
  }};
}}

/* ---- Risk Grid ---- */
function buildRisk(){{
  var g=document.getElementById('risk-grid');if(!g)return;
  var areas=[
    {{icon:'&#128273;',name:'SSH Security',   sub:'ri-r',bg:'rgba(229,83,75,.12)',
      cnt:SSH.filter(function(f){{return f.sev==='high'}}).length+' high &middot; '+SSH.length+' total',goto:'infra'}},
    {{icon:'&#127760;',name:'Web App (ZAP)',  sub:'ri-o',bg:'rgba(204,107,44,.12)',
      cnt:ZDEFS.filter(function(a){{return a.risk==='Medium'}}).length+' medium &middot; '+ZDEFS.length+' alerts',goto:'webapp'}},
    {{icon:'&#128737;',name:'Infrastructure', sub:'ri-y',bg:'rgba(198,144,38,.12)',
      cnt:LYNIS.filter(function(f){{return f.sev==='warning'}}).length+' warnings &middot; '+LYNIS.filter(function(f){{return f.sev==='suggestion'}}).length+' suggestions',goto:'findings'}},
    {{icon:'&#128225;',name:'Open Ports',     sub:'ri-b',bg:'rgba(83,155,245,.1)',
      cnt:PORTS.filter(function(p){{return p.risk==='high'}}).length+' high-risk &middot; '+PORTS.length+' total',goto:'network'}},
    {{icon:'&#129658;',name:'Service Health', sub:'ri-r',bg:'rgba(229,83,75,.08)',
      cnt:(function(){{var b=0,t=0;HEALTH.forEach(function(s){{s.rows.forEach(function(r){{t++;if(HBAD.indexOf((r.status||'').toUpperCase())>=0)b++;}})}});return b+' failed &middot; '+t+' checks';}})(),goto:'health'}},
    {{icon:'&#128100;',name:'User &amp; Auth',sub:'ri-p',bg:'rgba(152,110,226,.1)',
      cnt:'Review accounts &amp; sudo config',goto:'users'}},
    {{icon:'&#128190;',name:'OS / Packages', sub:'ri-g',bg:'rgba(87,171,90,.1)',
      cnt:'Check Lynis package &amp; kernel findings',goto:'infra'}},
    {{icon:'&#128220;',name:'Kernel Vulns',  sub:'ri-r',bg:'rgba(229,83,75,.1)',
      cnt:K_CRITICAL+' critical &middot; '+K_COUNT+' total',goto:'infra'}},
  ];
  g.innerHTML=areas.map(function(a){{
    return '<div class="rc" data-goto="'+a.goto+'">'
      +'<div class="ri" style="background:'+a.bg+'">'+a.icon+'</div>'
      +'<div><div class="rname">'+a.name+'</div><div class="rcnt">'+a.cnt+'</div></div>'
      +'</div>';
  }}).join('');
}}

/* ---- Tools table ---- */
/* ---- Kernel Vulns Table ---- */
function buildKV(){{
  var tb=document.getElementById('kvtbody');if(!tb)return;
  if(!KERNEL_VULNS.length){{tb.innerHTML='<tr><td colspan="6" class="empty">No Trivy data available (tool may not be installed, or no kernel vulnerabilities found).</td></tr>';return;}}
  tb.innerHTML=KERNEL_VULNS.map(function(v,i){{
    var sev=v.Severity||'HIGH';
    var pkg=v.PkgName||'?';
    var ver=v.InstalledVersion||'?';
    var fixed=v.FixedVersion||'?';
    var vid=v.VulnerabilityID||'?';
    var title=v.Title||(pkg+' - '+vid);
    var desc=(v.Description||'No description.')+'<br><br>Installed: '+ver+' → Fixed: '+fixed;
    return '<tr class="frow" data-kvi="'+i+'">'
      +'<td>'+badge(sev.toLowerCase())+'</td>'
      +'<td><strong>'+esc(pkg)+'</strong></td>'
      +'<td style="color:var(--tx2);font-size:12px">'+esc(ver)+'</td>'
      +'<td style="color:var(--green);font-size:12px">'+esc(fixed)+'</td>'
      +'<td><code style="font-size:11px;color:var(--tx2)">'+esc(vid)+'</code></td>'
      +'<td style="text-align:center;color:var(--tx2);font-size:16px">&#9656;</td></tr>'
      +'<tr class="drow" id="kd'+i+'"><td colspan="6">'
      +'<div><div class="dlbl">'+(sev==='CRITICAL'?'&#128308; ':'&#128992; ')+'Description</div><div class="dval">'+esc(desc)+'</div>'
      +'<div style="margin-top:12px"><div class="dlbl">Remediation</div><div class="dval">Update the kernel: <code style="background:var(--bg3);padding:2px 8px;border-radius:4px">sudo apt update && sudo apt upgrade -y && sudo reboot</code> (or yum equivalent). A reboot is required for the new kernel to take effect.</div></div>'
      +'</div></td></tr>';
  }}).join('');
  tb.onclick=function(e){{
    var row=e.target.closest('tr.frow');if(!row)return;
    var i=parseInt(row.getAttribute('data-kvi'));
    var d=document.getElementById('kd'+i);
    var open=d.classList.contains('show');
    document.querySelectorAll('[id^="kd"]').forEach(function(r){{r.classList.remove('show')}});
    document.querySelectorAll('tr.frow').forEach(function(r){{r.classList.remove('open')}});
    if(!open){{d.classList.add('show');row.classList.add('open');}}
  }};
}}

function buildTools(){{
  var tb=document.getElementById('tlbody');if(!tb)return;
  if(!TOOLS.length){{tb.innerHTML='<tr><td colspan="4" class="empty">No tool status data available.</td></tr>';return;}}
  tb.innerHTML=TOOLS.map(function(t){{
    var found=t.status==='found';
    var status=found?'<span class="badge bl">&#10003; ACTIVE</span>':'<span class="badge bh">&#9888; SKIPPED</span>';
    var detail=found?(esc(t.path)+(t.version?' <span style="color:var(--tx2)">'+esc(t.version)+'</span>':'')):
                      '<span style="color:var(--tx2)">'+esc(t.reason||'Not installed')+'</span>';
    var install=(!found&&t.install_cmd)?'<code style="font-size:11.5px;color:#57ab5a">'+esc(t.install_cmd)+'</code>':'<span style="color:var(--tx2)">&mdash;</span>';
    return '<tr><td>'+status+'</td><td><strong>'+esc(t.name)+'</strong></td><td>'+detail+'</td><td>'+install+'</td></tr>';
  }}).join('');
}}

/* ---- Highlight keywords in pre blocks ---- */
function hlPre(){{
  document.querySelectorAll('pre.raw').forEach(function(p){{
    p.innerHTML=p.innerHTML
      .replace(/\\b(WARNING|CRITICAL|DANGER|FAIL|ERROR)\\b/g,'<span style="color:#e5534b;font-weight:600">$1</span>')
      .replace(/\\b(SUGGESTION|WARN)\\b/gi,'<span style="color:#c69026;font-weight:600">$1</span>')
      .replace(/\\b(OK|PASS|DONE|SUCCESS)\\b/g,'<span style="color:#57ab5a">$1</span>');
  }});
}}

/* ---- Init ---- */
window.addEventListener('DOMContentLoaded',function(){{
  buildAF(); buildSSH(); buildPorts(); buildZAP(); buildKV(); buildRisk(); buildTools(); hlPre();
}});
</script>
</body>
</html>"""

with open(HTML_REPORT,'w',encoding='utf-8') as f:
    f.write(page)
print(f"Report: {HTML_REPORT} ({len(page)//1024}KB)")
