#!/usr/bin/env python3
"""
Auth Log Analyzer - Brute-Force & Suspicious Login Detector

Parses a Linux authentication log (/var/log/auth.log) and flags:
  1. Brute-force attempts  - many auth failures from the same user in a short window
  2. Possible breach       - a successful auth right after a burst of failures
  3. Off-hours activity    - authentications during unusual hours (configurable)

Detection is time-window based: it counts failures per user inside a sliding
window and alerts when the count crosses a threshold. This is the same core
idea real tools (fail2ban, SIEM correlation rules) use.

Usage:
    python3 auth_analyzer.py                       # reads /var/log/auth.log
    python3 auth_analyzer.py --file sample.log     # read a specific file
    python3 auth_analyzer.py --threshold 4 --window 60
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# --- Configuration defaults -------------------------------------------------
DEFAULT_THRESHOLD = 5        # failures needed to call it a brute-force
DEFAULT_WINDOW_SECONDS = 120 # ...within this many seconds
OFF_HOURS = range(0, 6)      # 12am-6am counts as "off hours"

# --- Log parsing ------------------------------------------------------------
# Matches ISO-style timestamps used by this system's rsyslog, e.g.
# 2026-08-28T18:45:35.490209-04:00 anthony sudo: pam_unix(sudo:auth): ...
TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

FAILURE_MARKERS = ("authentication failure", "Failed password")
SUCCESS_MARKERS = ("session opened", "Accepted password")

# Usernames can contain dots, hyphens, and @ (e.g. john.doe, svc-backup,
# user@domain for AD-joined hosts), so \w+ is not enough.
NAME = r'([\w.@-]+)'
# \b so that "ruser=" (the requesting user) is not mistaken for "user="
USER_RE = re.compile(r'\buser=' + NAME)
SSHD_USER_RE = re.compile(r'(?:Failed|Accepted) \S+ for (?:invalid user )?' + NAME)
SESSION_USER_RE = re.compile(r'session opened for user ' + NAME)


def parse_timestamp(line):
    m = TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def extract_user(line):
    for rx in (SSHD_USER_RE, USER_RE, SESSION_USER_RE):
        m = rx.search(line)
        if m:
            return m.group(1)
    return "unknown"


# sshd writes its own "Failed password" / "Accepted ..." line for every
# attempt AND a matching pam_unix(sshd:...) line. Counting both would turn
# one attempt into two, so the pam_unix lines for sshd are skipped.
DUPLICATE_SOURCES = ("pam_unix(sshd:",)

# Sessions opened by the system itself, not by a person logging in.
# cron opens a root session every time a job runs (often overnight), and
# systemd-user starts a session manager for each real login.
SYSTEM_SESSION_SOURCES = ("pam_unix(cron:session)", "pam_unix(systemd-user:session)")


def classify(line):
    if any(src in line for src in DUPLICATE_SOURCES + SYSTEM_SESSION_SOURCES):
        return None
    if any(mark in line for mark in FAILURE_MARKERS):
        return "FAIL"
    if any(mark in line for mark in SUCCESS_MARKERS):
        return "SUCCESS"
    return None


def load_events(path):
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                kind = classify(line)
                if not kind:
                    continue
                ts = parse_timestamp(line)
                if not ts:
                    continue
                events.append((ts, kind, extract_user(line)))
    except FileNotFoundError:
        print(f"ERROR: log file not found: {path}")
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: no permission to read {path}. Try: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    events.sort(key=lambda e: e[0])
    return events


# --- Detection --------------------------------------------------------------
def detect_bruteforce(events, threshold, window_seconds):
    """Sliding window per user: alert when failures >= threshold within window."""
    window = timedelta(seconds=window_seconds)
    fails_by_user = defaultdict(list)
    alerts = []

    for ts, kind, user in events:
        if kind != "FAIL":
            continue
        bucket = fails_by_user[user]
        bucket.append(ts)
        # drop failures older than the window
        cutoff = ts - window
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) == threshold:  # fire once, when threshold is first hit
            alerts.append({
                "user": user,
                "count": len(bucket),
                "start": bucket[0],
                "end": ts,
                "window_s": window_seconds,
            })
    return alerts


def detect_success_after_failures(events, min_prior_fails=3, window_seconds=120):
    """Flag a success that follows >= min_prior_fails failures for the same user."""
    window = timedelta(seconds=window_seconds)
    recent_fails = defaultdict(list)
    alerts = []

    for ts, kind, user in events:
        cutoff = ts - window
        bucket = recent_fails[user]
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if kind == "FAIL":
            bucket.append(ts)
        elif kind == "SUCCESS" and len(bucket) >= min_prior_fails:
            alerts.append({
                "user": user,
                "prior_fails": len(bucket),
                "success_time": ts,
            })
            bucket.clear()
    return alerts


def detect_off_hours(events):
    alerts = []
    for ts, kind, user in events:
        if kind == "SUCCESS" and ts.hour in OFF_HOURS:
            alerts.append({"user": user, "time": ts})
    return alerts


# --- Reporting --------------------------------------------------------------
def report(events, bf, breach, offh):
    print("=" * 62)
    print("  AUTH LOG SECURITY ANALYSIS")
    print("=" * 62)
    print(f"  Events parsed: {len(events)}  "
          f"(failures + successes with valid timestamps)")
    print("-" * 62)

    print(f"\n[1] BRUTE-FORCE ALERTS: {len(bf)}")
    for a in bf:
        span = (a["end"] - a["start"]).total_seconds()
        print(f"  ! user '{a['user']}': {a['count']} failures in {span:.0f}s "
              f"(window {a['window_s']}s)")
        print(f"      first: {a['start']}   last: {a['end']}")

    print(f"\n[2] SUCCESS-AFTER-FAILURES (possible breach): {len(breach)}")
    for a in breach:
        print(f"  ! user '{a['user']}': login succeeded after "
              f"{a['prior_fails']} failures  at {a['success_time']}")

    print(f"\n[3] OFF-HOURS LOGINS (12am-6am): {len(offh)}")
    for a in offh:
        print(f"  - user '{a['user']}' at {a['time']}")

    print("\n" + "=" * 62)
    total = len(bf) + len(breach)
    if total:
        print(f"  RESULT: {total} security alert(s) require attention.")
    else:
        print("  RESULT: no brute-force or breach patterns detected.")
    print("=" * 62)


def main():
    ap = argparse.ArgumentParser(description="Detect brute-force and suspicious logins in an auth log.")
    ap.add_argument("--file", default="/var/log/auth.log", help="path to auth log")
    ap.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                    help="failures to flag as brute-force")
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS,
                    help="time window in seconds")
    args = ap.parse_args()

    events = load_events(args.file)
    if not events:
        print("No auth events found. Is the log path correct and readable?")
        return

    bf = detect_bruteforce(events, args.threshold, args.window)
    breach = detect_success_after_failures(events, window_seconds=args.window)
    offh = detect_off_hours(events)
    report(events, bf, breach, offh)


if __name__ == "__main__":
    main()
