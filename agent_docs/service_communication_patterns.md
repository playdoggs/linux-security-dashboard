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
`SideBar.run_everything()` queues steps → `_re_tick()` polls worker completion → on empty queue fires callback → `RunEverythingSummaryDialog`.

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
