"""Generate realistic synthetic logs plus ground truth for evaluation.

Normal traffic comes from ~80 web clients and a few SSH users with browsing sessions,
occasional 404s and login typos. Eight attacker IPs are injected. Everything is
reproducible (fixed seed). Output: sample_data/auth.log, access.log, ground_truth.json"""
import json
import os
import random
from datetime import datetime, timedelta

random.seed(7)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_data")
BASE = datetime(2026, 11, 18, 8, 0, 0)
USERS = ["peter", "anita", "ravi", "deploy", "meena", "sam"]
SSH_IPS = [f"10.0.1.{i}" for i in range(10, 16)]
WEB_IPS = [f"172.16.{random.randint(0, 9)}.{random.randint(2, 250)}" for _ in range(80)]
PAGES = ["/", "/index.html", "/about", "/products", "/products/1", "/products/2", "/contact", "/login", "/blog", "/search?q=shoes"]
ASSETS = ["/static/app.js", "/static/style.css", "/static/logo.png", "/favicon.ico"]
AGENT = "Mozilla/5.0"
ssh, web = [], []


def ssh_line(t, msg):
    ssh.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: {msg}"))


def web_line(t, ip, path, status, method="GET"):
    web.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0530")}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 5000)} "-" "{AGENT}"'))


# ---- normal traffic ----
for ip in WEB_IPS:
    for _ in range(random.randint(2, 8)):                      # browsing sessions
        t0 = BASE + timedelta(seconds=random.randint(0, 36000))
        for k in range(random.randint(3, 14)):
            t = t0 + timedelta(seconds=k * random.randint(2, 25))
            path = random.choice(PAGES) if k % 3 == 0 else random.choice(ASSETS)
            web_line(t, ip, path, random.choices([200, 304, 404, 500], [88, 7, 4, 1])[0])
for _ in range(70):
    t = BASE + timedelta(seconds=random.randint(0, 36000))
    ssh_line(t, f"Accepted password for {random.choice(USERS)} from {random.choice(SSH_IPS)} port {random.randint(30000, 60000)} ssh2")
for _ in range(20):                                              # harmless typos
    t = BASE + timedelta(seconds=random.randint(0, 36000))
    ip = random.choice(SSH_IPS)
    for k in range(random.randint(1, 2)):
        ssh_line(t + timedelta(seconds=k * 6), f"Failed password for {random.choice(USERS)} from {ip} port 40222 ssh2")

# ---- attacks ----
t0 = BASE + timedelta(hours=3)                                   # 1 brute force then success
for i in range(40):
    ssh_line(t0 + timedelta(seconds=i * 4), f"Failed password for root from 203.0.113.45 port {50000 + i} ssh2")
ssh_line(t0 + timedelta(seconds=170), "Accepted password for root from 203.0.113.45 port 51000 ssh2")
t0 = BASE + timedelta(hours=5)                                   # 2 username enumeration
for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "guest", "postgres", "support", "user"]):
    ssh_line(t0 + timedelta(seconds=i * 15), f"Failed password for invalid user {u} from 198.51.100.77 port 4{i}000 ssh2")
t0 = BASE + timedelta(hours=4)                                   # 3 web scanner
for i, p in enumerate(["/admin", "/phpmyadmin", "/wp-login.php", "/.env", "/backup.zip", "/config.php", "/db.sql",
                       "/server-status", "/.git/config", "/test", "/old", "/api/v1/users", "/cgi-bin/x"]):
    web_line(t0 + timedelta(seconds=i * 3), "198.51.100.23", p, 404)
t0 = BASE + timedelta(hours=6)                                   # 4 SQL injection
for i, p in enumerate(["/products?id=1%20OR%201=1", "/products?id=1'--", "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
                       "/products?id=1;SELECT%20sleep(5)"]):
    web_line(t0 + timedelta(seconds=i * 20), "192.0.2.14", p, 200)
t0 = BASE + timedelta(hours=7)                                   # 5 XSS
for i, p in enumerate(["/search?q=<script>alert(1)</script>", "/comment?c=%3Cscript%3Ealert(2)%3C/script%3E"]):
    web_line(t0 + timedelta(seconds=i * 10), "192.0.2.99", p, 200)
t0 = BASE + timedelta(hours=8)                                   # 6 path traversal
for i, p in enumerate(["/download?file=../../etc/passwd", "/download?file=%2e%2e%2f%2e%2e%2fetc/passwd"]):
    web_line(t0 + timedelta(seconds=i * 10), "192.0.2.150", p, 403)
t0 = BASE + timedelta(hours=9)                                   # 7 request flood / scraper (valid requests, no rule)
for i in range(900):
    web_line(t0 + timedelta(milliseconds=i * 130), "198.51.100.200", random.choice(PAGES + ASSETS), 200)

ssh.sort(key=lambda x: x[0]); web.sort(key=lambda x: x[0])
os.makedirs(OUT, exist_ok=True)
open(os.path.join(OUT, "auth.log"), "w").write("\n".join(l for _, l in ssh) + "\n")
open(os.path.join(OUT, "access.log"), "w").write("\n".join(l for _, l in web) + "\n")
json.dump({"attacker_ips": {"203.0.113.45": "ssh brute force then login", "198.51.100.77": "username enumeration",
           "198.51.100.23": "web scanning", "192.0.2.14": "sql injection", "192.0.2.99": "xss",
           "192.0.2.150": "path traversal", "198.51.100.200": "request flood (no rule)"}},
          open(os.path.join(OUT, "ground_truth.json"), "w"), indent=2)
print(f"auth.log: {len(ssh)} lines, access.log: {len(web)} lines")
