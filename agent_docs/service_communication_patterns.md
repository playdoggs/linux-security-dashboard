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
Remediation: confirm → `CommandWorker` → verify → append structured undo record
plus display metadata to `UNDO_LOG` and JSONL → refresh `UndoPanel`.
Undo: validate structured operation → generated confirmation → revalidate → sudo
prompt → revalidate unchanged argv → `CommandWorker`. Only `finished_ok` removes
the table/memory entry; failure/timeout retains it. Legacy/invalid records cannot
prompt or create a worker. Existing history is never automatically migrated;
successful rollback does not yet update persistent history.

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
