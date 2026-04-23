# Communication Patterns

## Command execution
1. UI creates `CommandWorker`.
2. Worker runs off the GUI thread.
3. `output_ready` / `error_ready` → terminal.
4. `finished_ok` → post-processing + score update.

## CVE scan
1. `CvePanel.scan_cve()` checks `has_internet()` — offline → skip with clear message, still fires `on_complete`.
2. Build installed-package target list.
3. `HttpWorker` per-package to Ubuntu CVE API.
4. `result_ready` → CVE table + findings + `[N/TOTAL]` terminal line.
5. `finished_ok` → summary counters.

## Action + undo
Sudo prompt → confirm → `CommandWorker` → verify → append to `UNDO_LOG` (in-memory + JSONL) → refresh `UndoPanel`.

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
