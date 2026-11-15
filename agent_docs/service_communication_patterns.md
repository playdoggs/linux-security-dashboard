# Communication Patterns

## Command execution
1. UI creates `CommandWorker`.
2. Worker runs off the GUI thread.
3. `output_ready` / `error_ready` → terminal.
4. For `CommandWorker`, `finished_ok` means exit status zero; only then run
   success-dependent verification, score updates or the next wizard step.
5. `failed` means nonzero exit, timeout or exception. Stop dependent steps;
   keep findings and undo entries, restore controls and report incomplete work.
   Wizard failure also refreshes fix indicators and the selected detail view.
   Lynis installation and update checks use separate `on_failed` callbacks:
   sidebar failure clears pending state and hides the healthy banner. Update
   checks clear both stored callbacks on either outcome before notification.
6. `QThread.finished` handles unconditional lifecycle cleanup and callbacks that
   must run on either outcome. Streaming/HTTP workers retain their own signal
   contracts; do not infer their success from the buffered worker contract.

## CVE scan
1. `CvePanel.scan_cve()` checks `has_internet()` — offline → skip with clear message, still fires `on_complete`.
2. Build installed-package target list.
3. `HttpWorker` per-package to Ubuntu CVE API.
4. `result_ready` → CVE table + findings + `[N/TOTAL]` terminal line.
5. `finished_ok` → summary counters.

## Action + undo
Remediation: confirm → `CommandWorker` → verify → SQLite create+audit commit →
add record UUID to session report → refresh the current history page. If saving
fails, report that remediation succeeded but history could not be confirmed saved;
do not expose a memory-only undo entry.

Undo: selected UUID → fresh store get/validate → generated confirmation → fresh
get/validate → sudo authorization → atomic claim+audit commit → fresh claimed
operation validation → `CommandWorker`. Local in-flight IDs prevent nested clicks;
conditional claims prevent cross-instance duplicate execution.

Success/failure callbacks persist outcome+audit before refreshing by UUID. Nonzero
exit/missing executable are failed; timeout/unexpected execution are uncertain.
Failed outcome persistence leaves pending/uncertain state and a visible error.
Completed outcomes remain in audit history. No automatic retry/reactivation.
Legacy JSONL is paged separately and cannot trigger dialogs or worker creation.

## RUN EVERYTHING
`SideBar.run_everything()` creates a UUID run → `_re_advance()` starts one
step → run-local `on_terminal(outcome)` acknowledges it → next step. Workers
acknowledge on `QThread.finished`, including CVE and update workers owned by
CvePanel; logical success alone cannot advance. Synchronous helpers acknowledge
return. Missing/offline checks acknowledge skipped execution. Cancellation of CVE
waits for its worker to finish before acknowledging cancellation.

`_re_step_done(run_id,index,outcome)` accepts each waiting step once. Stale,
duplicate and finalized callbacks are ignored. `_re_finalize()` consumes the
summary callback once after all seven outcomes. No timer chain is used. Repeated
requests are refused; sidebar/CVE controls are disabled temporarily and CvePanel
uses the run token to reject conflicting starts. Existing findings are preserved.
Coverage semantics and general overlapping scans remain separate stages.

## Progress reporting
Multi-item scans emit `[N/TOTAL] item — status` on every iteration (CVE, risky services, quick checks, updates). Counter resets at scan start.

## Offline gates
`has_internet()` is the single source of truth.
- Hard gate (refuse + advise): CVE scan, tool install.
- Soft gate (warn + continue): `apt list --upgradable` (local cache still works).
- Always fire `on_complete` even when skipping — chained flows must not stall.

## Shared-panel reset
`CvePanel` serves both CVE and updates buttons. Every entry point **must** `self.cve_table.setRowCount(0)` before populating — or stale rows leak across scans.

## Thread-safety
Widget mutation only in main-thread signal handlers. Never from worker threads.

### Assessment dispatch exceptions

Finish fallible CVE session bookkeeping before dispatch. The assessment-specific
start guard registers completion first and retains a run-local dispatch token.
Failure before start can acknowledge immediately; failure after start records an
error and waits for actual `QThread.finished`. A stopped thread with queued slots
is still dispatched work, not a pre-start failure. Exceptions after the adapter's
start call also retain that boundary. Terminal outcome calculation failures become
failed outcomes; UUID/index guards still consume acknowledgement once. Ordinary
worker starts and command success/failure signals are unchanged.
