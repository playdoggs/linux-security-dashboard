# Data Persistence Model

No SQL database. All state is files + in-memory globals.

## Persistent files

**`~/.audit-dashboard.conf` (INI)** — atomic writes via temp-file replace in `save_config()`.
Fields: language, profile, theme-lock state + locked theme, sidebar collapse keys.

**`~/.audit-dashboard-undo.log` (JSONL)** — one action per line.
Fields: `time`, `action`, `cmd`, `undo_cmd`, `risk_level`, `rollback_risk`, `rollback_exploit`, `name`.
Rollback removes the row by matching `time + action + cmd + undo_cmd` (not `time` alone).

**Error log** — `~/.audit-dashboard-errors.log` (fallback `/tmp/.audit-dashboard-errors.log`).

## In-memory globals
- `RISK` — findings list + score
- `SESSION` — session activity tracker
- `UNDO_LOG` — mirror of the JSONL for the current session
- `IGNORE_LIST` — ignored findings (session-only)
- `T`, `LANG`, `PKG_MGR`, `BASE_FS` — active theme / language / package manager / base font size
