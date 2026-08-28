# Auth Log Analyzer - Brute-Force & Suspicious Login Detection

A Python tool that parses Linux authentication logs (/var/log/auth.log) and
flags attack patterns the way a SOC analyst or a tool like fail2ban would.

## Detections

1. Brute-force: many authentication failures from one user inside a short time
   window (sliding-window detection).
2. Possible breach: a successful login immediately following a burst of failures
   for the same user.
3. Off-hours activity: successful logins during unusual hours (default 12am-6am).

## Why this matters

Failed-login bursts are one of the earliest signals of an attack. Detecting the
pattern - not just individual failures - is the core of intrusion detection.

## Usage

Run against the included safe sample (no privileges needed):
    python3 auth_analyzer.py --file sample_auth.log

Run against the real system log (needs sudo to read the protected file):
    sudo python3 auth_analyzer.py

Tune sensitivity:
    python3 auth_analyzer.py --threshold 4 --window 60

## How it works

The parser reads each log line, classifies it as a failure or success, extracts
the username and timestamp, then runs three detectors. Brute-force uses a
per-user sliding window: it keeps only failures newer than the window and alerts
when the failure count reaches the threshold.

## Notes

Real logs are never committed - .gitignore excludes all .log files except the
bundled sample_auth.log, since auth logs contain usernames and host data.
Tested against real rsyslog-format entries generated on the author's own test
machine.
