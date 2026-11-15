# Data Persistence Model

No SQL database. All state is files + in-memory globals.

## Persistent files

**`~/.audit-dashboard.conf` (INI)** — atomic writes via temp-file replace in `save_config()`.
Fields: language, profile, theme-lock state + locked theme, sidebar collapse keys.

**`~/.audit-dashboard-undo.log` (JSONL)** — one action per line.
New records add `schema_version: 2` and `undo` to historical display metadata
(`time`, `action`, `cmd`, `undo_cmd`, risk descriptions and `name`). `undo` is a
strict package-install/service-enable/service-unmask object, or null when no
supported reverse operation exists. `build_undo_argv` is the execution authority;
command strings and saved risk labels are not trusted. See SECURITY.md S-002.
Legacy history remains visible and non-executable, with no automatic migration.
Loader limits: 16 KiB per line and 8 MiB per read; malformed non-object records
are skipped and display strings are bounded. The original file is not rewritten.
Rollback still removes only memory/table rows using `time + action + cmd +
undo_cmd`; persistent removal after successful rollback remains an open defect.

**Error log** — `~/.audit-dashboard-errors.log` (fallback `/tmp/.audit-dashboard-errors.log`).

## In-memory globals
- `RISK` — findings list + score
- `SESSION` — session activity tracker
- `UNDO_LOG` — mirror of the JSONL for the current session
- `IGNORE_LIST` — ignored findings (session-only)
- `T`, `LANG`, `PKG_MGR`, `BASE_FS` — active theme / language / package manager / base font size
