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

### Structured undo boundary (Increment 2, pending review)
- Never run `cmd`/`undo_cmd` from history. Only validated schema-version-2
  operations can construct sudo worker argv; unknown/legacy rows stay disabled.
- Validate exact package/backend and reviewed service targets; derive display
  warnings from the operation, not saved risk labels. Revalidate after dialogs.
- Existing JSONL is read-only legacy history, never executable or auto-imported.
  Increment 3 stores new records and outcomes in SQLite; failed/pending/completed/
  unknown records never automatically become actionable.
- Regression coverage: `tests/test_structured_undo.py` (mocks/temporary files).

### Durable undo lifecycle (Increment 3)
- Identify records by UUID, never timestamp or command text. Duplicate metadata
  must not update a different record. Retain completed records in audit history.
- Persist a pending claim before worker creation; persist outcomes before UI
  updates. Storage failure must never offer memory-only execution.
- Pending after restart means uncertain; do not auto-retry or reset it to available.
- Use separate success/failure/uncertain outcomes. Bounded pages must replace,
  not append to, the table. Old structured JSONL has no known lifecycle state.
- Regression coverage: `tests/test_undo_persistence_ui.py`.

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
