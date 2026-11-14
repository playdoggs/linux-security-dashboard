# Known Bugs and Regression Guards

Audit date: **2026-04-23**

## Open
None tracked. File a new `### N) …` block when one surfaces.

## Regression guards (previously fixed — don't regress)

### Quick-check parsing
- SSH checks use anchored regex: `^\s*PermitRootLogin\s+(no|prohibit-password)\b` and `^\s*PasswordAuthentication\s+no\b`.
- UFW / fail2ban use exact equality: `o.strip() == "active"`.
- **Never** reintroduce substring matching (`"active" in o.lower()`, `"no" in o.lower()`).

### Guided Wizard
- Fix commands parsed with `shlex.split()` or stored as pre-split lists. No `cmd.split()`.
- Multi-step fixes run sequentially via `_run_next_fix_cmd()` draining a queue. No `for cmd in ...: worker.start()` loops.

### Undo row removal
- Match on `time + action + cmd + undo_cmd` (four fields) — never on `time` alone.

### Other
- Background sudo uses `sudo -S` with `stdin=DEVNULL` fallback.
- `CommandWorker.finished_ok` is success-only; `failed` covers nonzero exit,
  timeout and exceptions. Wizard failures stop the queue and clear credentials;
  failed actions/undo must retain findings/history. Wizard failures refresh
  indicators without announcing completion. Failed Lynis installation/update
  checks use `on_failed`, never the sidebar healthy-completion callback.
  Update checks release both callback references on either outcome; lifecycle
  cleanup uses `QThread.finished`. Covered by `tests/test_command_outcomes.py`.
- HTML reports escape content via `html.escape()`.
- CVE HTTP uses a TLS context + bounded retries.
- `CvePanel` is shared by CVE and updates scans — both entry points clear `cve_table` on start.
- Internet-dependent features gate on `has_internet()`; they advise the user when offline instead of hanging on urllib timeouts.
- **`smartctl` is invoked with `-H` only — never `-t`.** `-t` instructs the drive firmware to run destructive/long self-tests and must never be called without explicit user opt-in.
- Drive names from `lsblk` are validated with `^[a-zA-Z0-9]+$` before being composed into `/dev/<name>` argv — defence in depth even though argv avoids shell interpolation.
- Timeshift snapshot failure ABORTS the pending action. Never swallow the failure and let the destructive command run anyway.
