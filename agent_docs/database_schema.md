# Data Persistence
<!-- AGENT: No SQL. Three files on disk + two in-memory singletons. -->

## Files on disk

### `~/.audit-dashboard.conf` — INI format
```ini
[prefs]
theme_locked = false
locked_theme = Light
language     = EN

[sidebar]
scan_collapsed   = false
checks_collapsed = false
cve_collapsed    = false
tools_collapsed  = false
undo_collapsed   = false
```
Read at startup via `load_config()`. Written atomically via `save_config(section, key, value)`.

### `~/.audit-dashboard-undo.log` — JSON Lines
One JSON object per line. Each action appended by `save_undo_entry(entry)`.
```json
{
  "time":             "2026-04-17 14:32:01",
  "action":           "remove 'ftp'",
  "cmd":              "sudo apt purge -y ftp",
  "undo_cmd":         "sudo apt install ftp",
  "risk_level":       "HIGH",
  "rollback_does":    "Reinstalls the FTP package on your machine",
  "rollback_risk":    "FTP transmits credentials in plain text",
  "rollback_exploit": "Anyone on the network can capture credentials with Wireshark.",
  "name":             "ftp"
}
```
Loaded at startup into `UNDO_LOG` list. `UndoPanel` reads this list.

### `~/.audit-dashboard-errors.log` — plain text
Written by Python `logging` module. `init_logging()` tries home dir first, falls back to `/tmp`. Never crashes the app.

## In-memory singletons

### `RISK` — RiskTracker
```python
RISK.findings  # list[str]  e.g. ["HIGH","HIGH","MEDIUM","LOW"]
RISK.score()   # int 0-100  weights: HIGH=20, MEDIUM=8, LOW=3, INFO=0
RISK.add(risk)
RISK.remove_entry(risk)
RISK.clear()
RISK.label()   # (str, colour) — "ALL CLEAR" / "LOW RISK" / "MODERATE" / "HIGH RISK" / "CRITICAL"
```

### `SESSION` — SessionTracker
```python
SESSION.scans_run       # list of (name, datetime, findings_count)
SESSION.actions_taken   # list of (action, name, datetime, succeeded)
SESSION.score_at_start  # int|None — captured on first scan
SESSION.log_scan(name, count)
SESSION.log_action(action, name, succeeded)
SESSION.build_summary() # → str for SessionSummaryDialog
```

## Other globals
| Name | Type | Notes |
|------|------|-------|
| `UNDO_LOG` | `list[dict]` | In-memory copy of undo log entries this session |
| `IGNORE_LIST` | `set[str]` | Package names to skip — session only, not persisted |
| `T` | `dict` | Active theme colours — updated by `apply_theme()` |
| `LANG` | `str` | Active language code e.g. `"EN"` |
| `PKG_MGR` | `str` | `"apt"` / `"dnf"` / `"pacman"` — detected from PATH at startup |
| `BASE_FS` | `int` | Font size in px, default 13. `fs(delta)` = `max(9, BASE_FS + delta)` |
