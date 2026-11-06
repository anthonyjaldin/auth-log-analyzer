# Auth Log Analyzer

![tests](https://github.com/anthonyjaldin/auth-log-analyzer/actions/workflows/tests.yml/badge.svg)

Auth Log Analyzer is a Python tool that reads Linux authentication logs and
looks for the patterns an attacker leaves behind when trying to get into a
system. It works the way a SOC analyst or a tool like fail2ban approaches the
problem: instead of reacting to a single failed login, it looks at how
failures and successes cluster together over time.

It has no third party dependencies and runs on any machine with Python 3.8 or
newer.

## What it detects

**Brute force against one account.** Many failed logins for the same username
inside a short time window, which usually means someone is guessing that
user's password.

**Password spraying from one source.** Many failed logins from the same IP
address, even when every attempt uses a different username. Automated bots
commonly cycle through names like `admin`, `oracle`, `test`, and `ubuntu`, so
grouping by account alone would miss them. The alert lists every username
that was tried.

**A successful login right after repeated failures.** If an account fails
several times and then logs in successfully, the password may have been
guessed. This is the alert most worth investigating first.

**Logins during off hours.** Successful logins inside a time range you choose
(midnight to 6am by default). On most systems these are rare enough to be
worth a second look.

## Requirements

* Linux, macOS, or Windows with WSL
* Python 3.8 or newer (check with `python3 --version`)
* Git, to download the project

To analyze the real system log you also need permission to read it, which
usually means running the tool with `sudo`.

## Installation

1. Open a terminal and move to the folder where you keep your projects:

   ```bash
   cd ~
   ```

2. Download the project and move into it:

   ```bash
   git clone https://github.com/anthonyjaldin/auth-log-analyzer.git
   cd auth-log-analyzer
   ```

3. Confirm it runs by printing the help text:

   ```bash
   python3 auth_analyzer.py --help
   ```

There is nothing else to install. The tool only uses the Python standard
library.

## Quick start with the sample log

The repository includes `sample_auth.log`, a small safe example, so you can
see the tool work without touching any real logs:

```bash
python3 auth_analyzer.py --file sample_auth.log
```

You should see one brute force alert for `testuser`, one possible breach
(the same user logging in after five failures), and one off hours login at
3:15am.

A more realistic example lives in `tests/fixtures/ubuntu_sshd_sample.log`.
It includes a nightly cron job, a key based SSH login, and a password
spraying run from a single address:

```bash
python3 auth_analyzer.py --file tests/fixtures/ubuntu_sshd_sample.log
```

```
==============================================================
  AUTH LOG SECURITY ANALYSIS
==============================================================
  Events parsed: 9  (failures + successes with valid timestamps)
--------------------------------------------------------------

[1] BRUTE-FORCE ALERTS: 1
  ! source IP '198.51.100.7': 5 failures in 8s (window 120s)
      usernames tried: admin, oracle, postgres, test, ubuntu
      first: 2026-11-05 14:05:01   last: 2026-11-05 14:05:09

[2] SUCCESS-AFTER-FAILURES (possible breach): 0

[3] OFF-HOURS LOGINS (hours 0-6): 0

==============================================================
  RESULT: 1 security alert(s) require attention.
==============================================================
```

Notice that the 2:17am cron job is not reported as an off hours login, and
that no single username reached the threshold, yet the attacking address is
still caught.

## Analyzing your own system

### Find your log file

Where authentication events are stored depends on the distribution:

| System | Log file |
|---|---|
| Ubuntu, Debian, Kali | `/var/log/auth.log` |
| RHEL, CentOS, Fedora, Rocky, Amazon Linux | `/var/log/secure` |
| Systems that only use journald | No file by default (see below) |

### Run the analysis

The log is readable only by administrators, so use `sudo`:

```bash
sudo python3 auth_analyzer.py
```

With no `--file` option the tool reads `/var/log/auth.log`. On RHEL based
systems point it at the right file:

```bash
sudo python3 auth_analyzer.py --file /var/log/secure
```

### Systems without an auth log file

Some newer distributions keep logs only in the systemd journal. Export the
journal to a file in a format the analyzer understands, then analyze that
file:

```bash
sudo journalctl --output=short-iso > journal_auth.log
python3 auth_analyzer.py --file journal_auth.log
```

The exported file contains sensitive data, so delete it when you are done.
The project's `.gitignore` already prevents `.log` files from being committed.

### Generating test events safely

To see real detections on your own machine, you can create a few failed
logins against your own account. Clear any cached sudo password first, then
enter a wrong password a few times when prompted:

```bash
sudo -k
sudo ls     # type a wrong password three times
sudo -k
sudo ls     # type a wrong password again, then the correct one
```

Then run the analyzer against your log. Only do this on a machine you own.

## Options

| Option | Default | Description |
|---|---|---|
| `--file PATH` | `/var/log/auth.log` | Log file to analyze |
| `--threshold N` | `5` | Failures needed to raise a brute force alert |
| `--window SECONDS` | `120` | Length of the sliding time window |
| `--min-prior-fails N` | `3` | Failures before a success that count as a possible breach |
| `--off-hours START-END` | `0-6` | Off hours range in 24 hour time. It may wrap past midnight, so `22-6` means 10pm to 6am |
| `--year YEAR` | current year | Year to use for logs whose timestamps leave it out (see below) |
| `--json` | off | Print results as JSON instead of the text report |
| `--exit-code` | off | Exit with status 1 when a brute force or breach alert is raised |

### Examples

Make detection more sensitive, alerting on 3 failures within one minute:

```bash
sudo python3 auth_analyzer.py --threshold 3 --window 60
```

Treat 10pm to 7am as off hours:

```bash
sudo python3 auth_analyzer.py --off-hours 22-7
```

Save results as JSON for another tool or a SIEM:

```bash
sudo python3 auth_analyzer.py --json > results.json
```

Analyze last year's rotated log:

```bash
sudo python3 auth_analyzer.py --file /var/log/auth.log.1 --year 2025
```

Run hourly from cron and only act when something is found:

```bash
python3 auth_analyzer.py --file /var/log/auth.log --exit-code || echo "Auth alert on $(hostname)"
```

## Reading the report

**Events parsed** is the number of login failures and successes the tool
recognized. If it is zero, the path is probably wrong or the file is not
readable.

**Brute force alerts** show either a user or a source IP, how many failures
happened, how quickly, and when the burst started and ended. Each burst
produces one alert, even if the attack continues for a long time.

**Success after failures** is the most important section. Each entry means an
account logged in successfully shortly after several failed attempts. Check
whether the owner of that account was actually the one logging in.

**Off hours logins** are not necessarily malicious, but they are uncommon on
most systems and are worth confirming.

## How it works

1. **Parsing.** Each line is checked for a timestamp, then classified as a
   failure, a success, or irrelevant. Both log timestamp formats are
   supported: ISO 8601 (`2026-11-05T14:02:12...`) and the traditional syslog
   format (`Nov  5 14:02:12`). The username and source IP are extracted from
   each event.

2. **Noise filtering.** sshd records every attempt twice, once in its own
   message and once through PAM, so the duplicate PAM line is skipped. Sessions
   started by cron and systemd are also ignored, because they are created by
   the system rather than by a person logging in.

3. **Detection.** For brute force, the tool keeps a sliding window of recent
   failures for every user and every source IP. Failures older than the window
   are dropped, and an alert is raised when the count reaches the threshold.
   The same window is used to decide whether a success followed a burst of
   failures.

## Running the tests

The test suite uses synthetic logs and needs no special permissions:

```bash
pip install -r requirements-dev.txt
pytest -q
```

GitHub Actions runs the same tests automatically on every push.

## Limitations

* Compressed rotated logs (`auth.log.2.gz`) must be decompressed first, for
  example with `zcat auth.log.2.gz > auth.log.2`.
* Time zone offsets in ISO timestamps are ignored, so all events are compared
  in the log's local time.
* The traditional syslog format does not record the year, so a log that spans
  New Year's Eve may need to be split and analyzed in two parts.
* This is an analysis tool, not a blocking tool. It reports activity but does
  not ban addresses the way fail2ban does.

## Project history

The first version detected brute force per user, success after failures, and
off hours logins on ISO formatted logs. Testing it against realistic Ubuntu
log entries showed that it double counted SSH failures, treated nightly cron
jobs as off hours logins, ignored key based logins, and could not read the
traditional syslog format at all. Most importantly, it missed password spraying
because it only grouped failures by username. See [CHANGELOG.md](CHANGELOG.md)
for the full list of what was fixed and why.

## Privacy

Real authentication logs contain usernames, hostnames, and IP addresses. The
`.gitignore` excludes every `.log` file except the bundled sample and the
synthetic test fixtures, which use reserved documentation addresses
(RFC 5737) rather than real ones.
