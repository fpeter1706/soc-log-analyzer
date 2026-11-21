import pandas as pd
from soc import parser

GOOD_SSH = "Nov 18 10:00:01 server sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2"
GOOD_WEB = '8.8.8.8 - - [18/Nov/2026:10:00:01 +0530] "GET /index.html HTTP/1.1" 200 512 "-" "x"'


def test_parse_failed_login():
    r = parser.parse_ssh_line(GOOD_SSH, 2026)
    assert r["event"] == "failed_login" and r["ip"] == "203.0.113.45" and r["username"] == "root"


def test_parse_invalid_user_login():
    r = parser.parse_ssh_line("Nov 18 10:00:01 h sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", 2026)
    assert r["username"] == "admin"


def test_parse_accepted_login():
    r = parser.parse_ssh_line("Nov 18 10:00:01 h sshd[1]: Accepted publickey for peter from 10.0.0.5 port 22 ssh2", 2026)
    assert r["event"] == "successful_login"


def test_parse_web_line():
    r = parser.parse_web_line(GOOD_WEB)
    assert r["status"] == 200 and r["path"] == "/index.html" and r["ts"].year == 2026


def test_irrelevant_and_garbage_lines_return_none():
    assert parser.parse_ssh_line("Nov 18 10:00:01 h sshd[1]: Connection closed by 1.2.3.4", 2026) is None
    assert parser.parse_ssh_line("total garbage", 2026) is None
    assert parser.parse_web_line("not a web log") is None


def test_impossible_ip_rejected():
    assert parser.parse_ssh_line(GOOD_SSH.replace("203.0.113.45", "999.1.1.1"), 2026) is None
    assert parser.parse_web_line(GOOD_WEB.replace("8.8.8.8", "300.1.1.1")) is None


def test_impossible_date_rejected():
    assert parser.parse_ssh_line(GOOD_SSH.replace("Nov 18", "Feb 30"), 2026) is None


def test_stats_count_skipped_and_oversized():
    text = "\n".join([GOOD_SSH, "garbage", "", "A" * (parser.MAX_LINE + 1)])
    df, st = parser.parse_logs(text, "", 2026)
    assert len(df) == 1 and st.parsed == 1 and st.skipped == 2 and st.oversized == 1


def test_empty_input():
    df, st = parser.parse_logs("", "", 2026)
    assert df.empty and list(df.columns) == parser.COLUMNS and st.parsed == 0


def test_files_survive_invalid_utf8_and_chunk_boundaries(tmp_path):
    p = tmp_path / "access.log"
    lines = [GOOD_WEB.replace("10:00:01", f"10:00:{i:02d}") for i in range(7)]
    p.write_bytes(("\n".join(lines) + "\n").encode() + b"\xff\xfe broken bytes\n")
    df, st = parser.parse_files(web_path=str(p), chunk_rows=3)
    assert len(df) == 7 and st.skipped == 1
    assert df["ts"].is_monotonic_increasing


def test_sample_logs_fully_parsed(sample_logs):
    df, st = sample_logs
    assert st.skipped == 0 and set(df["source"]) == {"ssh", "web"}
