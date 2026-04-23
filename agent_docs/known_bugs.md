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
- Worker completion signalling avoids stuck "please wait" states.
- HTML reports escape content via `html.escape()`.
- CVE HTTP uses a TLS context + bounded retries.
- `CvePanel` is shared by CVE and updates scans — both entry points clear `cve_table` on start.
- Internet-dependent features gate on `has_internet()`; they advise the user when offline instead of hanging on urllib timeouts.
