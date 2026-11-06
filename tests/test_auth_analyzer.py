import json
import os
import sys
from datetime import datetime

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auth_analyzer as aa  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "ubuntu_sshd_sample.log")
SAMPLE = os.path.join(ROOT, "sample_auth.log")


def write_log(tmp_path, *lines):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def fail(ts, user, ip="203.0.113.9"):
    return f"{ts} web1 sshd[1]: Failed password for {user} from {ip} port 5000 ssh2"


# --- parsing ---------------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    ("x sshd[1]: Accepted password for bob from 1.2.3.4 port 1 ssh2", "bob"),
    ("x sshd[1]: Accepted publickey for deploy from 1.2.3.4 port 1 ssh2", "deploy"),
    ("x sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 1 ssh2", "admin"),
    ("x sshd[1]: Failed password for john.doe from 1.2.3.4 port 1 ssh2", "john.doe"),
    ("x sudo: pam_unix(sudo:auth): authentication failure; ruser=eve rhost=  user=bob", "bob"),
    ("x su: pam_unix(su:session): session opened for user root(uid=0) by bob(uid=1000)", "root"),
])
def test_extract_user(line, expected):
    assert aa.extract_user(line) == expected


@pytest.mark.parametrize("line, expected", [
    ("x sshd[1]: Failed password for bob from 203.0.113.9 port 22 ssh2", "203.0.113.9"),
    ("x sshd[1]: Failed password for bob from 2001:db8::1 port 22 ssh2", "2001:db8::1"),
    ("x sudo: pam_unix(sudo:auth): authentication failure; rhost=  user=bob", None),
])
def test_extract_ip(line, expected):
    assert aa.extract_ip(line) == expected


def test_iso_timestamp():
    ts = aa.parse_timestamp("2026-11-05T14:02:12.000000-05:00 host sshd: x")
    assert ts == datetime(2026, 11, 5, 14, 2, 12)


def test_traditional_syslog_timestamp():
    ts = aa.parse_timestamp("Nov  5 14:02:12 host sshd[1]: x", year=2025)
    assert ts == datetime(2025, 11, 5, 14, 2, 12)


def test_unparseable_line_is_skipped():
    assert aa.parse_timestamp("garbage line") is None


# --- classification --------------------------------------------------------

def test_pam_sshd_lines_are_not_double_counted(tmp_path):
    path = write_log(
        tmp_path,
        "2026-11-05T14:02:10 web1 sshd[9]: pam_unix(sshd:auth): authentication "
        "failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=deploy",
        fail("2026-11-05T14:02:10", "deploy"),
    )
    events = aa.load_events(path)
    assert len(events) == 1


def test_cron_sessions_are_ignored(tmp_path):
    path = write_log(
        tmp_path,
        "2026-11-05T02:17:01 web1 CRON[1]: pam_unix(cron:session): session "
        "opened for user root(uid=0) by root(uid=0)",
    )
    assert aa.load_events(path) == []


def test_publickey_login_is_a_success(tmp_path):
    path = write_log(
        tmp_path,
        "2026-11-05T14:02:18 web1 sshd[1]: Accepted publickey for deploy from "
        "203.0.113.9 port 51030 ssh2: ED25519 SHA256:abc",
    )
    [ev] = aa.load_events(path)
    assert (ev.kind, ev.user, ev.ip) == ("SUCCESS", "deploy", "203.0.113.9")


# --- detection -------------------------------------------------------------

def test_bruteforce_per_user(tmp_path):
    path = write_log(tmp_path, *[fail(f"2026-11-05T14:00:{s:02d}", "root")
                                 for s in range(0, 10, 2)])
    alerts = aa.detect_bruteforce(aa.load_events(path), 5, 120, by="user")
    assert len(alerts) == 1
    assert alerts[0]["key"] == "root" and alerts[0]["count"] == 5


def test_below_threshold_does_not_alert(tmp_path):
    path = write_log(tmp_path, *[fail(f"2026-11-05T14:00:{s:02d}", "root")
                                 for s in range(0, 8, 2)])
    assert aa.detect_bruteforce(aa.load_events(path), 5, 120) == []


def test_failures_outside_window_do_not_alert(tmp_path):
    path = write_log(tmp_path, *[fail(f"2026-11-05T14:{m:02d}:00", "root")
                                 for m in range(0, 10, 2)])
    assert aa.detect_bruteforce(aa.load_events(path), 5, 60) == []


def test_one_alert_per_burst(tmp_path):
    path = write_log(tmp_path, *[fail(f"2026-11-05T14:00:{s:02d}", "root")
                                 for s in range(0, 40, 2)])
    assert len(aa.detect_bruteforce(aa.load_events(path), 5, 120)) == 1


def test_password_spraying_is_caught_per_ip():
    events = aa.load_events(FIXTURE)
    assert aa.detect_bruteforce(events, 5, 120, by="user") == []
    [alert] = aa.detect_bruteforce(events, 5, 120, by="ip")
    assert alert["key"] == "198.51.100.7"
    assert {"admin", "oracle", "test"} <= set(alert["users"])


def test_success_after_failures():
    events = aa.load_events(SAMPLE)
    [alert] = aa.detect_success_after_failures(events, min_prior_fails=3)
    assert alert["user"] == "testuser" and alert["prior_fails"] == 5


def test_success_after_few_failures_is_not_flagged():
    # fixture: deploy fails twice, then logs in with a key
    events = aa.load_events(FIXTURE)
    assert aa.detect_success_after_failures(events, min_prior_fails=3) == []


def test_off_hours_ignores_cron_noise():
    assert aa.detect_off_hours(aa.load_events(FIXTURE)) == []


@pytest.mark.parametrize("spec, inside, outside", [
    ("0-6", 3, 6),
    ("22-6", 23, 12),
    ("22-6", 2, 7),
])
def test_parse_hours(spec, inside, outside):
    hours = aa.parse_hours(spec)
    assert inside in hours and outside not in hours


# --- CLI -------------------------------------------------------------------

def test_json_output(capsys):
    aa.main(["--file", SAMPLE, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["events_parsed"] == 7
    assert data["bruteforce"][0]["key"] == "testuser"


def test_exit_code_when_alerts(capsys):
    assert aa.main(["--file", SAMPLE, "--exit-code"]) == 1
    assert aa.main(["--file", SAMPLE]) == 0


def test_bad_off_hours_is_rejected():
    with pytest.raises(SystemExit):
        aa.parse_args(["--off-hours", "abc"])
