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

## Increment 4 Stage 4C assessment sequencing

`tests/test_assessment_sequence.py` binds production sidebar orchestration,
CvePanel adapters and WorkerMixin methods to lightweight widget doubles. Controlled
worker signals test real signal connections and their order without commands,
network calls or elapsed-time sleeps. Coverage includes all seven steps, delayed
CVE/update thread completion, synchronous/duplicate/stale callbacks, repeated runs,
missing tools/targets, offline checks, cancellation acknowledgement, parser and
summary exceptions, unknown worker exits, control restoration, preserved findings,
exactly-once summary and absence of timer chains/privileged additions. Buffered
worker threads/outcomes remain covered by Increment 1 tests. No full GUI is run.

### Stage 4C dispatch-exception regression

Fault injection covers CVE bookkeeping before dispatch and errors after startup
for sidebar commands, CVE and updates. It verifies no next step, summary or control
restoration while the required worker is active; post-dispatch errors remain in
step outcomes. Additional cases cover pre-start refusal, fast exited threads whose
finished notification is queued, inline finish followed by setup failure, exceptions
after an adapter's dispatch call, outcome-calculation failure and duplicate/late
notifications. Four focused regressions failed against the rejected implementation
before the correction. Controlled worker signals execute no commands or network
requests; they model callback ordering rather than launching the full GUI.

## Increment 4 Stage 4D coverage and verdicts

`tests/test_assessment_coverage.py` tests production coverage helpers, banner and
summary/report methods, quick/temperature checks, package probes and parser paths.
All subprocess and widget interactions are mocked. Cases include complete runs
with/without findings, every incomplete state, partial/offline/full-page CVEs,
unknown package probes, missing sensors, quick-check exceptions, malformed output,
preserved findings and late successful completion after failure. Both HTML modes
must keep incomplete coverage visible and escape explanatory text.

Sequencing fixtures now return explicit evidence quality rather than `completed`;
all prior UUID, dispatch-exception, ordering and exactly-once protections remain
tested. RiskTracker/remediation package checks are unchanged. No GUI, host commands
or network requests are used by the new coverage tests.

### Stage 4D evidence-validation acceptance corrections

Two focused production-method regression tests reproduce the rejected SSH and
sensor cases. Against the rejected code, conflicting/malformed directives and
sensor diagnostic/nonzero-exit cases produced 13 failing subtests. Corrected tests
cover both SSH directives: secure/insecure, contradictory values in either order,
identical duplicates, comments, missing/malformed values and no passed message or
complete coverage for ambiguous evidence. They do not execute sshd or change files.

Sensor fixtures cover empty stderr, explicit failures with/without valid readings,
harmless warnings, warning-prefixed read failures, nonzero exit with usable readings,
and retention of hot findings. Tests verify incomplete sensor evidence cannot make
all-seven coverage complete and verify child-only LC_ALL=C. All subprocesses are
mocked; no sensors detection/configuration or privileged commands are executed.

The follow-up temperature-wording regression covers read failed, reading failed,
failed reading, cannot read, failed to read, unable to read and read error, including
capitalization/tabs and sensor identifiers. The previous classifier failed 18 of
these subtests. Each failure phrase is checked with normal, hot and absent readings;
coverage, findings retention, banner and HTML verdicts are exercised through
production methods. Separate cases ensure harmless warnings and unrelated uses of
"failed" remain non-fatal. No command is actually executed by these cases.

## Increment 4 Stage 4E scan isolation

`tests/test_scan_isolation.py` binds production entry points, ownership wrappers,
worker dispatch, result adapters, coverage/banner methods and Lynis parsing to
widget doubles. Controlled signals test overlapping individual/RUN EVERYTHING
requests, direct panel starts, stale findings/status/banner updates, duplicate
completion and CVE responses, fast dispatch, pre/post-start exceptions, owned
seven-step completion and the legacy three-step scope. Findings/manual mutation
requests cannot bypass active ownership. A real QThread/QCoreApplication fixture
checks queued results arrive before ownership release, without launching a GUI or
subprocess. Existing buffered/streaming/SQLite tests continue unchanged in scope.

Lynis tests use current-attempt strings and temporary missing/empty/stale log
fixtures which must never be read as evidence. Success requires both the worker's
successful thread completion and recognizable complete output; failures, truncation,
parser exceptions and partial output retain incomplete status and existing warnings.
Installation-to-audit handoff retains one lease and rejects late installation signals.
No actual sudo, tool install, network scan or host configuration operation runs.

These Stage 4E tests do not prove window-close/shutdown handling, arbitrary
third-party callbacks or all real Lynis formats; Stage 4F coverage is described below. They model one application instance; other
processes remain outside its GUI ownership coordinator.

### Stage 4E startup rollback acceptance regressions

The admission-banner regression failed against the rejected implementation with an
escaped exception and retained nesting depth. Cleanup-signal fault injection also
reproduced a phantom non-running worker and blocked retries. Tests now cover coverage
initialization errors, nested admission, pre-worker run setup/control restoration,
first/later cleanup connections, partial reference additions, cleanup errors that
must not mask original startup errors, and once-only delete scheduling. Retrying a
scan must succeed after rollback; delayed old completion must not retire its worker.
Existing fast/queued/post-dispatch cases still require real completion before release.
Signal doubles implement disconnect, allowing assertions on partial registration.

## Increment 4 Stage 4F shutdown and HTTP bounds

`tests/test_shutdown_http.py` extracts production shutdown, worker ownership and
HTTP definitions without importing the application or launching widgets. Controlled
signals cover idle/active/repeated close, cancel shutdown, finishing during the
confirmation, seven-step/legacy sequences, blocked scans/clear/fixes/profile,
queued/duplicate/late callbacks and guided-fix close/Escape. Real QThreads and a
QCoreApplication test result delivery during shutdown and ownership retained until
actual `finished`; a non-running worker awaiting queued cleanup still blocks close.

HTTP tests use mocks for socket timeout, shared-budget exhaustion and late success,
and the production CVE result handler to verify deadline errors prevent complete
coverage. A loopback-only temporary HTTP server exercises a normal response, stalled
headers/body, trickled bytes, a shorter socket timeout and response overflow against
actual isolated helper processes. Deadline tests assert the helpers are reaped;
fixtures use bounded waits and shut down their server/request threads. This requires
local socket permission (the restricted agent sandbox may require an approved test
run outside it). No external endpoint, sudo, package change or host probe is used.

These checks do not validate the full GUI, real Qt widget destruction, desktop
session exit, arbitrary external callbacks, frozen/embedded Python packaging or
uninterruptible kernel behaviour. No application-state database is created.

### Guided-fix startup rollback acceptance correction

`GuidedFixStartup` exercises the full production guided-wizard class with only its
QDialog base, status probes and commands replaced by inert doubles. Base dismissal
is observable, so recovery tests actually reach the superclass close/done paths.
Production WorkerMixin and ownership run unchanged. Initial and subsequent command
startup failures must leave no phantom worker, clear chain/password references,
restore Run/dismissal, preserve existing findings/history and report failure.
Post-dispatch failures keep the dialog protected and credentials available until
actual completion, including fast completion followed by a start exception.

Ten regressions cover these paths, partial cleanup connection failure, refresh
failure, duplicate/stale signals, normal multi-command progress and a real QThread
that starts then raises. The initial seven fault-injection tests all failed against
the rejected code, including both original command-position reproductions; they
passed after correction. The real-thread fixture uses QCoreApplication, a bounded
Event wait and guaranteed thread cleanup, without launching widgets or commands.
Clearing Python credential references is not a secure memory-erasure guarantee.

### Guided-fix sequencing correction

Three additional `GuidedFixStartup` tests cover success before native completion,
failure before native completion, and both outcomes through real gated QThreads.
The two controlled-signal regressions failed against the previous code: success
started a second worker early, while failure reset `_fix_running` early. They now
assert controls/credentials/ownership remain protected until `finished`, exactly-once
progression, duplicate callback isolation and successful normal chain completion.
The real thread emits its terminal signal and remains running behind a bounded
Event gate; no command is executed. First/subsequent startup-failure regressions
remain in the same suite. Two earlier synchronous CommandOutcomes fixtures now
explicitly model native completion after calling `run()`; calling `run()` alone
never emits Qt's automatic `finished` notification. The existing real-thread
partial-failure test continues to use actual Qt completion.

## Qt / GNOME schema startup compatibility

`tests/test_qt_platform_theme.py` extracts the production startup policy without
importing the GUI module. Nine mocked tests cover the affected schema, explicit
GTK3 versus other theme choices, other platforms/desktops, legacy-compatible
schemas, missing/failed/stalled probes and ordering before QApplication creation.
Only the read-only `gsettings list-keys` command is permitted by the policy.

Actual desktop probes on Ubuntu GNOME with Qt 6.10.2 reproduced the exact fatal
missing `antialiasing` key under automatic GTK3 theme selection. A debugger trace
showed `libqgtk3` -> GTK initialization -> GDK3 -> `g_settings_get_enum`. The same
isolated Qt dialog succeeded with process-local `QT_QPA_PLATFORMTHEME=generic`,
including expansion of error details. These were actual Qt GUI runs, not mocks.

An actual production main/dashboard smoke run with the new policy also succeeded:
all five colour themes, all five pages and expanded QMessageBox error details.
That smoke fixture used a temporary HOME/config/cache/state, memory-only GSettings,
a stub first-run wizard and host probes, disabled worker starts, and automatic
closure. It validates real Qt widgets/startup while protecting existing user data;
it is not a scan, privileged-operation or unmodified end-to-end application test.
No system packages, schemas, GNOME values or existing preferences were changed.
Other desktop/Qt versions and explicit third-party platform themes are unverified.
