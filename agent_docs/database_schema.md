# Data Persistence Model

Increment 3 uses a protected SQLite store for new undo history and lifecycle
outcomes. Preferences remain INI; the original JSONL is read-only legacy history.
`UNDO_LOG` is session reporting data, not the authority for execution.

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
The application no longer appends to this file. Old structured records also
remain historical/non-actionable: their past outcomes cannot be established.
Legacy display uses at most 200 rows per page within the existing byte limit;
no automatic import, deletion or migration is performed.

**Error log** — `~/.audit-dashboard-errors.log` (fallback `/tmp/.audit-dashboard-errors.log`).

## In-memory globals
- `RISK` — findings list + score
- `SESSION` — session activity tracker
- `UNDO_LOG` — current-session persisted remediation records, updated by record UUID
  after a persisted undo outcome; completed records remain for reporting
- `IGNORE_LIST` — ignored findings (session-only)
- `T`, `LANG`, `PKG_MGR`, `BASE_FS` — active theme / language / package manager / base font size

## Increment 3: transactional store and application integration

`UndoPanel` explicitly constructs `UndoHistoryStore` at application startup,
using `~/.audit-dashboard-history/history.sqlite3`. Nothing is created at module
import; tests use temporary stores only. The store API never imports JSONL.

Storage schema version 1 is separate from operation schema version 2:
- `undo_records`: monotonic sequence cursor, UUID record ID, immutable structured
  operation and display metadata, current state, active attempt UUID, timestamps.
- `undo_events`: sequence cursor, event UUID, record/attempt IDs, state, bounded
  reason code and timestamp. Application APIs and schema triggers forbid editing
  or deleting audit events and original record payloads.

Transitions: `available -> pending -> completed | failed | outcome-unknown`.
There is no retry/reactivation API. Creating a record and its event, claiming a
record and its event, or recording an outcome and its event are single transactions.
A claim returns its generated argv/attempt UUID only after commit succeeds.
Repeated or competing claims and stale outcomes fail closed.

Opening does not relabel pending attempts: another instance may still be running.
Pending entries remain non-actionable. An explicitly determined interruption can
be recorded as outcome-unknown using the exact record/attempt IDs. A successful
external command whose outcome cannot be persisted must never be retried silently.

A call owns its connection and closes it in the same thread. DELETE journaling,
synchronous EXTRA, foreign keys and a bounded lock wait (default one second,
maximum two) are enforced. An initialization integrity check and exact version,
application-ID and schema checks reject corrupt/unsupported stores without
replacement. Failed initial creation may leave an empty unsupported store which
requires explicit recovery, not automatic deletion.

Directory mode 0700 and database/sidecar mode 0600, current-user ownership,
regular files, single file links, and non-symlink path components are required.
Only the final application directory is created. Directory descriptors anchor
opens on Linux. These checks are not protection against same-user/root tampering.
Use local filesystems with working SQLite locking and durable flush semantics.

`page()` and `events()` use keyset cursors with at most 200 rows per call;
actionable/history filtering uses current stored state before the page limit.
The UI has Actionable, Audit history and read-only Legacy history views. Pages
replace the table rather than accumulate widgets. Selection/execution uses a
stable UUID and reloads the record from SQLite, not cached row command text.

After confirmation/password authorization, claim commits before worker creation.
The freshly claimed operation must still match the confirmed generated argv.
Outcome/audit commit precedes success/failure state refresh. Missing executables
and nonzero exits are failed; timeouts, unexpected exceptions and uncertain
dispatch are outcome-unknown. Pending after restart is shown as uncertain and
never automatically retried. Failed/completed/unknown records have no undo button.
Persistence failure is shown in the panel/terminal; no memory-only undo is offered.
Original remediation may already have succeeded before saving its reversal fails;
the UI reports that limitation rather than implying the system change was undone.
