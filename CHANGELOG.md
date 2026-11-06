# Changelog

## v1.1 (November 2026)

### Fixed

* **SSH attempts were counted twice.** sshd logs each attempt in its own
  message and again through PAM. Both lines matched, so two real failures
  looked like four, which effectively halved the brute force threshold. The
  duplicate PAM lines are now skipped.
* **Cron jobs triggered off hours alerts.** cron opens a root session every
  time a job runs, and these were treated as logins. Any nightly job produced
  an alert for root. cron and systemd sessions are now ignored.
* **Usernames were extracted incorrectly in several cases.** Successful
  password logins showed up as `unknown`, a PAM line containing `ruser=eve`
  was blamed on eve instead of the real user, and names with dots or hyphens
  were cut short (`john.doe` became `john`).
* **Key based SSH logins were not counted.** Only password logins counted as
  successes, so a brute force burst followed by an `Accepted publickey` login
  was never correlated.
* **Traditional syslog logs could not be read.** Logs using the
  `Nov  5 14:02:12` format, including RHEL's `/var/log/secure`, parsed to zero
  events. Both formats are now supported, with `--year` for logs that omit it.

### Added

* **Brute force detection per source IP.** Password spraying, where one
  address tries a different username on every attempt, never reached the
  threshold for any single account and went completely undetected. Failures
  are now also grouped by IP, and the alert lists every username tried.
* Source IP in breach and off hours alerts.
* `--off-hours`, `--min-prior-fails`, `--json`, and `--exit-code` options.
* 29 unit tests and a realistic Ubuntu log fixture.
* GitHub Actions workflow that runs the tests on every push.
* Expanded README with installation, usage, and troubleshooting steps.

### Changed

* Events are stored as a named tuple, and the sliding windows use a deque
  instead of repeatedly removing from the front of a list.

## v1.0 (August 2026)

* First release. Parses ISO formatted auth logs and detects brute force per
  user with a sliding window, success after failures, and off hours logins.
