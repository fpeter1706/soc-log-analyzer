"""Log parsing: tolerant of bad input, bounded line length, streaming friendly."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

import pandas as pd

MAX_LINE = 4096  # longer lines are skipped (protects the regex engine and memory)
COLUMNS = ["source", "ts", "ip", "username", "event", "method", "path", "status", "raw"]

_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3})"
SSH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED = re.compile(rf"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>{_IP})")
ACCEPTED = re.compile(rf"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>{_IP})")
WEB_LINE = re.compile(
    rf'^(?P<ip>{_IP}) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{{3}}) \S+'
)


@dataclass
class ParseStats:
    parsed: int = 0
    skipped: int = 0
    oversized: int = 0


def _valid_ip(ip: str) -> bool:
    return all(0 <= int(p) <= 255 for p in ip.split("."))


def parse_ssh_line(line: str, year: int) -> Optional[dict]:
    m = SSH_LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    for regex, event in ((FAILED, "failed_login"), (ACCEPTED, "successful_login")):
        hit = regex.search(m["msg"])
        if hit and _valid_ip(hit["ip"]):
            return dict(source="ssh", ts=ts, ip=hit["ip"], username=hit["user"], event=event,
                        method=None, path=None, status=None, raw=line.strip())
    return None


def parse_web_line(line: str) -> Optional[dict]:
    m = WEB_LINE.match(line.strip())
    if not m or not _valid_ip(m["ip"]):
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None
    return dict(source="web", ts=ts, ip=m["ip"], username=None, event="http_request", method=m["method"],
                path=m["path"], status=int(m["status"]), raw=line.strip())


def parse_lines(lines: Iterable[str], kind: str, year: int, stats: ParseStats) -> Iterator[dict]:
    parser = (lambda l: parse_ssh_line(l, year)) if kind == "ssh" else parse_web_line
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if len(line) > MAX_LINE:
            stats.oversized += 1
            stats.skipped += 1
            continue
        rec = parser(line)
        if rec:
            stats.parsed += 1
            yield rec
        else:
            stats.skipped += 1


def _to_frame(rows) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=COLUMNS)
    if len(df):
        df["ts"] = pd.to_datetime(df["ts"])
        df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    return df


def parse_logs(ssh_text: str = "", web_text: str = "", year: int = 2026):
    """Parse text already in memory. Returns (events DataFrame, ParseStats)."""
    stats = ParseStats()
    rows = list(parse_lines(ssh_text.splitlines(), "ssh", year, stats))
    rows += list(parse_lines(web_text.splitlines(), "web", year, stats))
    return _to_frame(rows), stats


def parse_files(ssh_path=None, web_path=None, year: int = 2026, chunk_rows: int = 50_000):
    """Stream files from disk without loading them whole. Undecodable bytes are replaced."""
    stats, frames = ParseStats(), []
    for path, kind in ((ssh_path, "ssh"), (web_path, "web")):
        if not path:
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            buf: list = []
            for rec in parse_lines(fh, kind, year, stats):
                buf.append(rec)
                if len(buf) >= chunk_rows:
                    frames.append(pd.DataFrame(buf, columns=COLUMNS))
                    buf = []
            if buf:
                frames.append(pd.DataFrame(buf, columns=COLUMNS))
    if not frames:
        return pd.DataFrame(columns=COLUMNS), stats
    df = pd.concat(frames, ignore_index=True)
    df["ts"] = pd.to_datetime(df["ts"])
    return df.sort_values("ts", kind="stable").reset_index(drop=True), stats
