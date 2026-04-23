# Service Architecture

## Main components
- `AuditDashboard` — main window + orchestration
- `SideBar` — actions and scan entry points
- `FindingsTable` — shared findings list
- `TerminalPanel` — shared command/log output
- `RiskScorePanel` — score, progress, face, profile
- `CvePanel` — CVE *and* updates scans (shared table; must clear on every entry)
- `LynisPanel` — Lynis execution and parsing
- `ToolsPanel` / `ToolCard` — recommended tools install/run/help
- `UndoPanel` — rollback history and execution
- `GuidedWizard` — step-by-step hardening flows
- `StartupWizard` — first-run onboarding
- `RunEverythingSummaryDialog` — post-RUN-EVERYTHING good/needs-fixing view
- `SessionSummaryDialog` — "what have I done?" session recap

## Workers
- `CommandWorker(QThread)` — local commands (argv lists only)
- `HttpWorker(QThread)` — CVE API calls, retries + timeouts
- `WorkerMixin` — lifecycle + cleanup

## Module-level helpers
- `has_internet(timeout=2.0)` — TCP probe to `1.1.1.1:443`; gates CVE scan + tool install, warns on cached upgradable list
- `get_system_info()` — hostname/distro/kernel for reports + startup banner
- `check_update_age()` — last `apt update` timestamp → health face
- `check_sudo_cached()` — non-blocking sudo state probe

## Data flow
- Scans → `FindingsTable` → `score_changed` → `RiskScorePanel`
- Actions → `UNDO_LOG` (in-memory + JSONL) → `UndoPanel`
- Reports read `RISK`, `UNDO_LOG`, profile, `get_system_info()`
- RUN EVERYTHING: `SideBar.run_everything()` → `_re_tick()` → `on_complete` → summary dialog

## Panel stack
`0` Findings · `1` CVE (shared by CVE + updates) · `2` Lynis · `3` Tools · `4` Undo
