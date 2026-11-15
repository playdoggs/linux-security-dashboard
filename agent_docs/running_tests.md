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
The Increment 1 rollback fixture now uses a valid structured operation; its
failure-retention assertion is unchanged. No real packages/services are touched.

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
