# Code Conventions

## General
- Keep the single-file architecture.
- Slow/blocking work → `CommandWorker` / `HttpWorker`. Never touch Qt widgets from worker threads.

## Command safety
- Argv lists only. No `shell=True`.
- Validate package names with `valid_pkg()` before any package-manager action.
- Parse user-facing fix commands with `shlex.split()` (or store pre-split lists). Never `cmd.split()`.

## Check parsing
- systemd state: exact equality — `output.strip() == 'active'`, not substring.
- Config files: anchored regex that ignores commented lines.

## Connectivity-aware features
- Call `has_internet()` before any network-dependent action.
- Offline → surface `⚠ Requires internet` in panel status + terminal, and still fire `on_complete` so chained flows don't stall.
- Hard gate pure-network features (CVE scan, tool install); soft-warn for features that degrade gracefully (cached upgradable list).

## Progress reporting
- Multi-item scans emit `[N/TOTAL] item — status` on every iteration.
- Counter resets at scan entry, not in the worker callback.

## Theme / styling
- Persistent widgets use object names + `make_style()`. Avoid inline styles that freeze across theme changes.

## Worker lifecycle
- Start via `_start_worker()` where available. Always connect completion + cleanup signals.

## Shared panels
- A panel used by more than one entry point (e.g. `CvePanel`) clears its widgets at the start of **every** scan method.
