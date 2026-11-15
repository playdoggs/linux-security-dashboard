# Running Tests

## Automated command-outcome regression tests

```bash
python3 -m unittest discover -s tests -v
```

Requires existing PyQt6 and Python; uses unittest from the standard library.
Tests load selected production definitions through AST extraction, avoiding
module-level logging and distro detection. All subprocess calls are mocked;
no application window, sudo command or security-setting change is performed.
Coverage includes success/warnings, nonzero exits with/without stderr, timeout,
missing commands, unexpected exceptions, thread completion, wizard stop/advance,
failed actions/undo retaining state, and failed scan completion bookkeeping.
Real QThread tests exercise the production sidebar entry points and actual
success/failure handlers for Lynis installation failures and update outcomes
(nonzero exit, timeout, missing executable, plus update success). A partial
wizard sequence verifies that status refreshes after a later step fails and
that no full-completion dialog appears. Widget endpoints remain test doubles;
status probes are mocked rather than run against the host.
This does not validate actual privileged commands or full GUI behavior.

Manual application checks below require a suitable authorized test environment.

## Structured undo regression tests

`tests/test_structured_undo.py` covers strict operation/schema/argument validation,
new-record creation, generated confirmations and safety text, disabled legacy and
invalid rows, mixed/malformed/oversized history, append-only preservation,
rejection before sudo/worker creation, mutation during dialogs, cancellation,
and success/failure/timeout/missing-executable behavior. AST extraction avoids
application startup; Qt widgets and all subprocess calls are mocked. History
I/O uses temporary directories only. Run through the unittest command above.
The Increment 1/2 rollback fixtures now use persisted IDs and structured
operations; their failure-retention and generated-command assertions remain. No real packages/services are touched.

## Baseline
```bash
python3 -m py_compile linux-security-dashboard.py
python3 linux-security-dashboard.py
```

## Manual regression checklist

**Security checks** — UFW/fail2ban fail on `inactive`, pass only on exact `active`. SSH regex ignores commented lines.

**Guided wizard** — SSH sed steps apply correctly (shlex-parsed). Multi-step fixes run sequentially.

**Actions + undo** — action adds an undo entry; rollback removes the correct row when two entries share a timestamp.

**CVE / updates**
- Online: rows populate; terminal shows `[N/TOTAL] pkg — …` per package.
- Offline: CVE scan shows `⚠ Requires internet — CVE check skipped`; RUN EVERYTHING still completes.
- Switching CVE → updates clears stale CVE rows.
- Updates offline: cached warning, scan still runs from local apt cache.

**Progress lines** — CVE, risky services, quick checks, and updates all emit `[N/TOTAL]` lines; counter starts at 1 each run.

**Tool installs** — offline click on INSTALL shows "Requires Internet" dialog and does not prompt for sudo.

**Theme / language / profile** — theme switch updates persistent widgets; language choice persists; profile affects NORMAL tagging.

## Increment 3 Stage A storage tests

`tests/test_undo_history_store.py` extracts the production storage class and pure
validator without importing the application. All databases/files are in temporary
directories. Coverage includes protected paths and sidecars, schema rejection,
UUID identity, immutable payloads/events, lifecycle transitions, concurrent claims,
lock timeouts, failed writes/commit acknowledgement, reopen persistence, no replay,
uncertain outcomes, and bounded keyset paging. Two short-lived Python child-process
tests exit abruptly before/after a temporary database commit; they execute no host
commands and verify recovery of committed versus uncommitted state.

Run with the existing unittest discovery command (use `python3 -B` to suppress
bytecode writes). No full GUI, privileged command, package or systemd operation is
used. Storage tests alone do not establish full GUI behavior.

## Increment 3 Stage B integration tests

`tests/test_undo_persistence_ui.py` runs production panel/verification methods
against temporary real SQLite stores with mocked widgets and subprocesses. It
checks commit-before-worker ordering, outcome-before-success UI ordering, no
memory-only fallback, failed/uncertain claims and outcome writes, no automatic
replay after restart, repeated/nested clicks, uncertain dispatch, bounded view
paging, and unchanged display-only legacy files. Existing Increment 1/2 tests
continue to run; rollback fixtures now refer to persisted records. No full GUI
launch or privileged command occurs.

### SQLite POSIX-lock regression

The storage suite holds a production connection's `BEGIN IMMEDIATE` transaction
while a fresh Python subprocess attempts a conflicting write. It must report
`LOCKED` both before and after a second production connection (including existing
store initialization checks) opens/closes, then `ACQUIRED` after rollback. This test
failed against the original raw-descriptor implementation (`ACQUIRED` too early).
A separate test checks that creation closes its private descriptor before publishing
the database, never raw-opens the published name, and removes the staging name.
These tests use only temporary databases; they do not validate every filesystem.

## Increment 4 Stage 4A streaming outcome tests

`tests/test_streaming_outcomes.py` extracts production worker and callback methods
without importing/launching the GUI. Mocked `Popen` streams cover zero/nonzero exit,
missing executables, timeout (including failed kill), unexpected startup/read/
password-write exceptions and exactly one terminal outcome. Actual Lynis callback
chains parse/report success only on success and call the sidebar failure handler
otherwise. Real QThreads with mocked subprocesses exercise production WorkerMixin
cleanup through `QThread.finished` on both success and failure.

Run `python3 -B -m unittest discover -s tests -q`. These fixtures do not prove
real timeout bounds, concurrent pipe draining, descriptor cleanup or descendant
termination; see Stage 4B tests below. No sudo or host commands execute in these tests.

## Increment 4 Stage 4B streaming execution tests

`tests/test_streaming_execution.py` runs extracted production methods in fresh
interpreters with a six-second outer harness timeout. Only unprivileged Python
fixtures execute: silent/partial-line children, large stderr, inherited pipes,
closed pipes with a still-running child, ignored SIGTERM, output/update limits,
nonzero exits, blocked stdin and injected read errors. Tests assert one outcome,
closed owned pipes, bounded elapsed time, direct-child reaping and incomplete
output rejection. A short-lived inherited-pipe descendant exits independently;
no process group or recursive kill is used. The stdin fixture substitutes its
Python argv before Popen and never invokes sudo. Stage 4A tests now mock the I/O
collector specifically; real selector behavior is tested separately here.

`test_streaming_outcomes.py` additionally checks denied terminate/kill attempts
remain unconfirmed, without requesting privileges or performing real signals.
Timing tests allow scheduling slack and do not prove hard real-time deadlines or
cleanup of root-owned processes. Run with the same `python3 -B` discovery command.
