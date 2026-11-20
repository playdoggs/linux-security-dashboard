# ARCHITECTURE

**Function:** Living map of the codebase — what each component is, how data flows between them, where state lives on disk, and what surfaces the app exposes.

Last reviewed: 2026-05-03

---

## UI foundation (Stage 2)

Presentation remains PyQt6 Widgets with the existing pages and actions. `THEMES`
provides seven palettes; `apply_theme()` derives semantic content, navigation,
status and control colours. `UI_METRICS` and `UI_TYPOGRAPHY` centralize shared
sizes and type choices, while `fs()` preserves existing font scaling.
`build_palette()` and `make_style()` supply the common Fusion component skin.

`set_theme_style()` retains a recipe for component-specific styles rather than
freezing construction-time colours. `refresh_theme_widgets()` reapplies recipes,
updates table/console presentation and adjusts geometry without clearing evidence.
Console spans retain colour roles in Qt text-format metadata. `FoundationEvents`
handles display sizing and responsive toolbar reflow; it does not consume events
or own workers. Risk calculations, coverage, reports and operation ownership remain
separate from these presentation helpers. Locked themes remain persistent; unlocked
startup defaults to Enterprise Workspace. Legacy palettes share the new component
skin, with muted Hacker/Solarized text adjusted for readability.

This section describes the Stage 2 implementation only; the historical component
line references below have not been comprehensively refreshed.

## Workspace shell (Stage 3)

`AuditDashboard._build_workspace()` creates seven pages once and retains one
instance of each existing controller/result widget. `SideBar` remains the existing
scan controller, rendered as assessment actions rather than primary navigation.
`WorkspaceRouter` translates its old indices: 0 → Findings, 1/2 → Assessments
CVE/Lynis tabs, 3/4 → Remediation tools/undo tabs. No scan controller is reconstructed
when a page is selected. Existing non-constructor scan/worker/remediation/report
methods are unchanged. Reparented inventory/wizard controls mirror their original
controller's enabled state through a UI-only change event.

A 500 ms display timer reads operation/coverage state for the header and Overview;
it does not sequence, execute, cancel or complete work. Activity uses the existing
terminal and splitter, with a visibility toggle. Form pages scroll when necessary.
See [feature mapping and validation](agent_docs/ui_navigation_shell.md). Historical
line references/diagrams below predate the shell; the existing execution and storage
sections remain authoritative for those mechanisms.

## Responsive findings presentation (Increment 4G)

`ResponsiveFindingsTable` uses the existing six logical columns unchanged, while
ordering them visually as Name, Risk, Actions, Type, Tag, Detail. It recomputes widths
on view resize/data changes and theme sizing; priority columns receive minimums
before surplus goes to Name/Detail. Users can still drag interactive headers;
automatic allocation resumes on a view resize or evidence refresh. Below the
combined minima, horizontal scrolling remains available. Text is elided rather
than wrapped into tall rows; full current cell text is HTML-escaped in tooltips.
Sorting, search, report readers and action callbacks continue to use logical indices.

`ExplainDialog` retains the same explanation/glossary selection and text, with its
header and body inside one top-aligned scroll area. Its initial dimensions follow
content, bounded by 760×640 logical pixels and the available screen (with margins).
The Close control remains outside the scroll area. No execution, authorization or
persistence code participates in either sizing mechanism.

## Prerequisite management (Increment 4H)

`PREREQUISITES`/`prerequisite_rows()` define execution dependencies and supported
backends. `PrerequisitesPanel` owns bounded background discovery/preview jobs, the
Settings table and an explicitly approved installation/verification chain. Targeted
`prerequisite_gate()` checks precede affected scan entry points and step adapters.
It does not turn tool presence into successful coverage or install assessment subjects.

`build_prerequisite_plan()` strictly parses new-package simulations and pins their
resolved versions; `execute_prerequisite_plan()` revalidates before sudo and uses
no automatic termination/deadline for active APT. Existing WorkerMixin/ScanOwnership
and an explicit continuation lease protect native completion and nested confirmation
loops. The dashboard also counts read-only prerequisite workers when closing.
See [canonical workflow, limits and legacy-path caveats](agent_docs/prerequisites.md).

## Component table (file → role)

The application is a single-file PyQt6 GUI. All components live in [linux-security-dashboard.py](linux-security-dashboard.py); line numbers below pin each component.

### Module-level globals & helpers

| Component | Lines | Role |
|---|---|---|
| `LOG_FILE` / `CONFIG_FILE` / `UNDO_LOG_FILE` | [53-55](linux-security-dashboard.py#L53-L55) | Per-user persistent file paths under `$HOME` |
| `init_logging()` | [57-72](linux-security-dashboard.py#L57-L72) | Best-effort error-log file with `/tmp` and stderr fallbacks |
| `load_config()` / `save_config()` / `config_bool()` / `get_startup_theme()` | [78-115](linux-security-dashboard.py#L78-L115) | INI preference storage with atomic temp-file replace |
| `valid_pkg()` / `PKG_RE` | [119-122](linux-security-dashboard.py#L119-L122) | Package-name validator — gate before every package-manager argv |
| `strip_ansi()` | [126-128](linux-security-dashboard.py#L126-L128) | Drop terminal colour escapes before display in QTextEdit |
| `THEMES` / `apply_theme()` / `build_palette()` / `make_style()` | [141-440](linux-security-dashboard.py#L141-L440) | 7 colour themes; QPalette + global Qt stylesheet rebuilt on theme/font change |
| `LANGS` / `L()` | [445-574](linux-security-dashboard.py#L445-L574) | 12-language UI string lookup with EN fallback |
| `detect_distro()` / `pkg_install()` / `pkg_remove()` / `pkg_installed()` | [577-632](linux-security-dashboard.py#L577-L632) | Distro detection + apt/dnf/pacman command generation |
| `check_update_age()` | [634-657](linux-security-dashboard.py#L634-L657) | Reads apt mtimes to drive the "days since update" health face copy |
| `check_sudo_cached()` | [659-669](linux-security-dashboard.py#L659-L669) | Non-blocking `sudo -n true` probe |
| `timeshift_is_configured()` / `create_timeshift_snapshot()` | [671-725](linux-security-dashboard.py#L671-L725) | Pre-action safety-net snapshot; failure aborts the pending action |
| `has_internet()` | [727-737](linux-security-dashboard.py#L727-L737) | TCP probe to `1.1.1.1:443`, gates CVE + tool install |
| `get_system_info()` | [739-811](linux-security-dashboard.py#L739-L811) | hostname/distro/kernel/CPU/RAM/uptime for header + reports |
| `prompt_for_sudo_password()` | [813-833](linux-security-dashboard.py#L813-L833) | Tri-state result: bytes / `b""` (cached) / `None` (cancel) |
| `ROLLBACK_RISK` / `get_rollback_info()` | [835-903](linux-security-dashboard.py#L835-L903) | Per-action plain-English rollback explanation database |
| `TOOLS_DATA` | [905-1029](linux-security-dashboard.py#L905-L1029) | Recommended-tools cards (15 entries: install/run/help) |
| Embedded face PNGs / `get_face_pixmap()` | [1031-1060](linux-security-dashboard.py#L1031-L1060) | Base64-embedded Duke-style health face images keyed off score |
| `RiskTracker` / `RISK` | [1155-1195](linux-security-dashboard.py#L1155-L1195) | Findings list → score (HIGH 20, MEDIUM 8, LOW 3, INFO 0) |
| `SessionTracker` / `SESSION` | [1063-1152](linux-security-dashboard.py#L1063-L1152) | Per-session scan/action log for the "What's Been Done?" recap |
| `IGNORE_LIST` / `UNDO_LOG` / `UNDO_MAP` | [1198-1212](linux-security-dashboard.py#L1198-L1212) | Session-level mute set, mirror of JSONL undo log, action→reverse map |
| `make_undo_cmd()` / `save_undo_entry()` / `load_undo_log()` | [1214-1248](linux-security-dashboard.py#L1214-L1248) | Append-only JSONL log + reverse-command derivation |
| `detect_profile()` / `PROFILES` | [2697-2730 / 2649-2695](linux-security-dashboard.py#L2697-L2730) | Process- and package-signal profile classifier (gaming, docker, hypervisor, …) |
| `run_quick_checks()` | [2734-2832](linux-security-dashboard.py#L2734-L2832) | 8 sysctl/systemctl/ssh checks with pass/fail + remediation hint |
| `run_temperature_check()` | [2850-2947](linux-security-dashboard.py#L2850-L2947) | lm-sensors parser → per-sensor findings (no sudo) |
| `_list_physical_drives()` / `run_drive_health_check()` | [2958-3153](linux-security-dashboard.py#L2958-L3153) | `sudo smartctl -H` per disk; **never `-t`** |
| HTML report (`_collect_findings_by_section`, `_render_finding_rows`, `_build_exec_statement`, `generate_report`) | [6387-6687](linux-security-dashboard.py#L6387-L6687) | Executive / Technical HTML report; sections mirror sidebar |
| `main()` | [7151-7182](linux-security-dashboard.py#L7151-L7182) | Qt app, Fusion style, palette + stylesheet, first-run wizard, then `AuditDashboard` |

### Workers

| Component | Lines | Role |
|---|---|---|
| `CommandWorker(QThread)` | [1255-1343](linux-security-dashboard.py#L1255-L1343) | Buffered argv command execution; sudo via `-S` + stdin password or `DEVNULL` |
| `StreamingCommandWorker(QThread)` | [1346-1441](linux-security-dashboard.py#L1346-L1441) | Deadline-aware concurrent `Popen` pipes for Lynis; bounded `full_output` for success-only parsing |
| `HttpWorker(QThread)` | [1444-1522](linux-security-dashboard.py#L1444-L1522) | Sequential CVE lookups against `ubuntu.com/security/cves.json`; bounded retries; cancelable |
| `WorkerMixin` | [1526-1557](linux-security-dashboard.py#L1526-L1557) | Tracks live workers in a set; `_start_worker()`, `_stop_all_workers()`, `_any_running` |

### Buffered command outcomes

`CommandWorker.finished_ok` is emitted only for exit status zero. `failed`
is emitted for a nonzero exit, timeout or exception. The wizard stops dependent
steps on failure, clears its password, restores controls and refreshes status
indicators without announcing full remediation success. Failed actions and
rollbacks do not run success callbacks. Lynis installation and update scans
route failures to a separate `on_failed` callback; the sidebar clears pending
state and hides the healthy banner instead of marking the scan successful.
Update scans release both stored callbacks before notifying the outcome-specific
caller. Tool status refreshes and worker lifecycle cleanup remain attached to
`QThread.finished`.

The buffered implementation is specific to `CommandWorker`. Streaming execution
is described below; HTTP worker behavior is unchanged. Exit status zero is not
proof that the intended security state was achieved. Focused buffered tests:
`tests/test_command_outcomes.py`.

Review scope: buffered command outcomes and affected callers, 2026-11-15.

Increment 4 Stage 4B: `StreamingCommandWorker` now uses Linux selectors and
nonblocking binary pipes to drain stdout/stderr and send password input under one
monotonic deadline. Success requires EOF on both streams, exit zero, and complete
bounded output. Retention is at most 2 MiB combined bytes; live preview is bounded
to 4096 updates of at most 16384 characters. Exceeding limits is a failed/incomplete
assessment, never an input to successful Lynis parsing. A failure attempts direct
child terminate/wait then kill/wait (0.5 seconds each); descriptors are closed and
reaping status reported separately from descendants, whose state is unverified.
There is no process-group kill or privileged termination fallback. Process creation
and kernel-level stalls cannot be guaranteed interruptible. This does not change
buffered command workers, undo validation, SQLite lifecycle or scan orchestration.

Other component line ranges below reflect the earlier review baseline.

### Widgets / panels

| Component | Lines | Role |
|---|---|---|
| `ArrowSplitterHandle` / `CueSplitter` | [1560-1580](linux-security-dashboard.py#L1560-L1580) | Splitter with painted ⇕/⇔ glyph for discoverability |
| `TerminalPanel(QWidget, WorkerMixin)` | [1583-1668](linux-security-dashboard.py#L1583-L1668) | Shared scrolling output; A+/A−/CLEAR controls; rebuilds global stylesheet on font change |
| `RiskScorePanel(QWidget)` | [1671-1810](linux-security-dashboard.py#L1671-L1810) | Health face + bar + per-section breakdown; reads `RISK` and findings table |
| `PreActionDialog(QDialog)` | [1813-1912](linux-security-dashboard.py#L1813-L1912) | Confirmation dialog with command box, undo hint, optional Timeshift checkbox |
| `EXPLANATIONS` / `GLOSSARY` / `ExplainDialog(QDialog)` | [1918-2091](linux-security-dashboard.py#L1918-L2091) | Per-finding everyday-language explanation with glossary hits |
| `FindingsTable(QWidget, WorkerMixin)` | [2095-2644](linux-security-dashboard.py#L2095-L2644) | Main findings table; dedupe, risk sort, action cell builder, search filter, ignore, action+verify pipeline |
| `GuidedWizard(QDialog, WorkerMixin)` | [3157-3735](linux-security-dashboard.py#L3157-L3735) | 12 step-by-step hardening fixes with idempotent re-checks |
| `LynisPanel(QWidget, WorkerMixin)` | [3738-4012](linux-security-dashboard.py#L3738-L4012) | Streams current-attempt Lynis stdout; shared logs are never assessment evidence |
| `CvePanel(QWidget, WorkerMixin)` | [4016-4340](linux-security-dashboard.py#L4016-L4340) | CVE table + offline gating + apt-list-upgradable; shared by both buttons |
| `ToolCard(QFrame)` | [4344-4545](linux-security-dashboard.py#L4344-L4545) | Single recommended-tool card with INSTALL / HELP / RUN |
| `ScheduleScanDialog(QDialog)` | [4548-4716](linux-security-dashboard.py#L4548-L4716) | User-crontab installer for periodic upgradable-package check |
| `ToolsPanel(QWidget)` | [4719-4891](linux-security-dashboard.py#L4719-L4891) | Category-tabbed grid of tool cards + the schedule card |
| `UndoPanel(QWidget, WorkerMixin)` | [4894-5153](linux-security-dashboard.py#L4894-L5153) | Persistent rollback log table with HIGH-risk warning UI |
| `SideBar(QWidget, WorkerMixin)` | [5156-5842](linux-security-dashboard.py#L5156-L5842) | Collapsible nav + every scan handler + RUN-EVERYTHING completion-driven sequence |
| `ProfileDialog(QDialog)` | [5846-5897](linux-security-dashboard.py#L5846-L5897) | Confirm/override auto-detected profile |
| `StartupWizard(QDialog)` | [5900-6119](linux-security-dashboard.py#L5900-L6119) | First-run 4-page onboarding (mode / connectivity / profile / summary) |
| `SessionSummaryDialog(QDialog)` | [6123-6157](linux-security-dashboard.py#L6123-L6157) | Toolbar "What's Been Done?" recap |
| `RunEverythingSummaryDialog(QDialog)` | [6160-6383](linux-security-dashboard.py#L6160-L6383) | Post-RUN-EVERYTHING good/needs-fixing dialog with one-click report open |
| `AuditDashboard(QMainWindow)` | [6691-7147](linux-security-dashboard.py#L6691-L7147) | Top-level window: toolbar, risk panel, sidebar, stack, terminal splitter |

### Build / packaging

| File | Role |
|---|---|
| [build-deb.sh](build-deb.sh) | Wraps `dpkg-buildpackage -us -uc -b`; writes `.deb` to parent dir |
| [debian/control](debian/control) | Package metadata, deps (`python3-pyqt6`, `libxcb-cursor0`), recommends (deborphan, lynis, smartmontools, lm-sensors) |
| [debian/install](debian/install) | Lays the script under `/usr/lib/linux-security-dashboard/`; launcher in `/usr/bin/` |
| [debian/rules](debian/rules) | `dh $@` — plain debhelper, no Python module packaging |
| [packaging/linux-security-dashboard](packaging/linux-security-dashboard) | sh launcher: `exec python3 /usr/lib/linux-security-dashboard/linux-security-dashboard.py "$@"` |
| [packaging/linux-security-dashboard.desktop](packaging/linux-security-dashboard.desktop) | Desktop entry (categories: System;Security;Utility) |

---

## Data flow (ASCII)

```
                          ┌──────────────────────────────┐
                          │       AuditDashboard         │
                          │ (QMainWindow — toolbar,      │
                          │  RiskScorePanel, SideBar,    │
                          │  QStackedWidget, splitter)   │
                          └──────────────┬───────────────┘
                                         │ wires
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
  ┌───────────┐                ┌───────────────────┐                ┌──────────┐
  │  SideBar  │  click ───►    │   FindingsTable   │ ◄── findings ──│  scans   │
  │           │ pre_scan()     │   (dedupe/sort)   │                │ (quick,  │
  │ run_*() ──┼──── argv ──►  ┌┴───────────────────┴┐               │  temps,  │
  │           │ ◄── result ── │  CommandWorker /    │ ── stdout ──► │  drives, │
  │ run steps │               │  StreamingWorker /  │               │  unused, │
  │ queue     │               │  HttpWorker         │               │  network,│
  └─────┬─────┘               └──────────┬──────────┘               │  service)│
        │                                │                          └──────────┘
        │                                ▼
        │                         ┌───────────────┐
        │                         │ TerminalPanel │ ◄── append_*()
        │                         └───────────────┘
        │
        ▼
  ┌──────────────┐    score_changed    ┌─────────────────┐
  │ FindingsTbl  ├────────────────────►│ RiskScorePanel  │
  │ score=RISK   │                     │ (face, bar,     │
  └──────────────┘                     │  section split) │
        │                              └─────────────────┘
        │ confirmed action
        ▼
  ┌─────────────────────────────────────────────────────────┐
  │  PreActionDialog → optional Timeshift snapshot →        │
  │  CommandWorker (sudo -S) → verify (pkg_installed) →     │
  │  UNDO_LOG.append + save_undo_entry → UndoPanel.live     │
  └─────────────────────────────────────────────────────────┘
        │
        ▼
  ~/.audit-dashboard-undo.log (JSONL, append-only)

  Persistent panels (CvePanel) are SHARED by 2 buttons; each entry-point
  must clear cve_table before populating — see service_communication_patterns.md.
```

RUN EVERYTHING (`SideBar.run_everything()` → `_re_advance`) uses an in-memory
UUID run identity and a single waiting-step index. The seven steps remain unused
software, ports, services, quick checks, temperatures, CVEs and updates. Sidebar
command workers and CvePanel HTTP/update workers deliver a run-local terminal
callback only on `QThread.finished`, after their logical outcome and parsing.
Synchronous functions acknowledge return; missing dependencies/offline CVE checks
acknowledge a skip. A step is consumed once; duplicate/stale callbacks cannot
advance another step/run. There is no polling timer. Finalization consumes the
summary callback once after all seven outcomes, with no waiting step.

The run preserves main findings and terminal evidence. It refuses to begin while
existing sidebar/CVE/Lynis workers are active, rejects repeated requests, and
temporarily disables sidebar/CVE controls. A CvePanel ownership token also rejects
conflicting programmatic scan starts. Controls are restored before the summary callback; shared scan ownership remains
held through actual thread completion and callback cleanup. Existing CVE/update detail-table replacement is unchanged.
CVE session bookkeeping runs before dispatch. `_start_assessment_worker` connects
its terminal acknowledgement before startup and distinguishes pre-dispatch errors
from exceptions after a worker starts (including a fast exit with queued signals).
A run-local acknowledgement token retains post-dispatch errors even if the step
adapter raises after startup returns. Running workers still acknowledge only on
`finished`; errors are retained in the final step record. Inline completion is
held until the startup call returns, so setup errors cannot become false success.
The dispatch guard introduces no polling or termination changes.

Stage 4D retains six coverage states per named step: succeeded, partial, failed,
skipped, cancelled and unknown. `completed` is not accepted as successful evidence.
Synchronous helpers return evidence quality; worker adapters combine execution
outcome with parser/discovery quality. Findings severity is independent of coverage.
All seven ordered steps must succeed, with no active run, before assessment coverage
is complete. A findings-table snapshot gates the banner and drives both the final
dialog and executive/technical exports. Replacing findings invalidates that snapshot.
Any incomplete step prevents an unqualified clean verdict, including after later
success. Discovered findings and diagnostic errors are retained.

Package probes used by scans distinguish absent from unknown, without changing
remediation's bool helper. Quick checks recognize usable output before recording
coverage; sensors require readings; CVE discovery/API shape/full-page limits and
cached-only updates reduce coverage conservatively. Update success covers the
local package-list query, not proof that the host has every current repository patch. The CVE query remains limited
to selected apt packages and is not a distribution/version applicability proof.
Acceptance corrections: explicit SSH directive values must agree and use a
recognized supported value. Identical duplicates and comments are allowed;
contradictory/malformed evidence is unverified, never a passed SSH check. This
reads the selected output only, not effective sshd Include/Match semantics.
Temperature coverage combines return code, stdout readings and diagnostic errors
on stderr. Usable readings/findings survive errors as partial evidence; no usable
readings with errors is failed. Harmless diagnostic warnings do not alone fail a
check. Only the sensors child uses LC_ALL=C to stabilize diagnostic recognition;
no host locale or security settings are changed.

RiskTracker calculations and existing severity thresholds are unchanged. CVE
records below those thresholds are counted separately in coverage reporting, so
zero risk score is never treated as proof of no findings. Coverage is a scan-time
snapshot, not ongoing monitoring or certification. General panel overlap is protected by the Stage 4E ownership model below. Lynis and drive checks remain outside RUN EVERYTHING.


## Scan isolation (Increment 4 Stage 4E)

`FindingsTable` creates one GUI-thread `ScanOwnership` shared through its terminal.
Public scan entries acquire a UUID lease before clearing evidence or asking for
sudo. Conflicting requests return with a terminal explanation; they never cancel
or replace active work. Internal continuations explicitly join the current lease.
Expired continuation tokens cannot start a new operation. RUN EVERYTHING retains
its separate run UUID/index guards and exactly seven default steps. The legacy
full-scan entry retains three steps, using completion callbacks instead of timers.

A worker record captures the lease and worker UUID before signal connection.
`scan_slot` filters output, result, status and completion callbacks by that live
record; logical completion slots are consumed once. Duplicate CVE package responses
are ignored. `_start_worker` holds strong references before dispatch and retires
the record only on actual `QThread.finished`, after result/outcome handlers. A
pre-start failure releases a non-running worker; a post-start error retains the
lease until its real completion. Parser/setup errors become incomplete outcomes.
No new polling, process termination or privileged capability is added.

Individual sidebar and direct CVE/update/Lynis entries, quick/temperature/drive
checks, inventories and legacy full scan share the lease. Clearing findings or the
terminal, changing profile, tool runs/installs and manual remediation/undo are also
admitted through it because they can change shared evidence or its interpretation.
Existing confirmations, operation validators and SQLite lifecycle remain in place;
undo outcome persistence is not discarded by a stale-result filter. A blocked
startup profile prompt can be retried via CHANGE PROFILE; it is not auto-requeued.

Lynis no longer reads `/var/log/lynis.log` or falls back to `sudo -n cat`. Only
successful, non-truncated output from the authorized worker is parsed for
completion after its thread finishes. A separate partial-observation handler can
retain explicit warnings from failed/truncated attempts without success parsing. Recognized warning/suggestion counts, a valid hardening index and
positive performed-test count are required for a complete attempt. Empty, missing,
failed or unsupported-format output remains unknown. Partial warnings/findings are
retained; a stale or readable empty shared log cannot create a clean result.

Acceptance rollback corrections protect every admission preparation action after
lease acquisition. A preparation failure restores the prior coverage/banner where
possible and always unwinds that entry's depth/token. A pre-worker run setup failure
restores its saved controls and aborts the unstarted run; a dispatched worker keeps
ownership. Restoration errors are reported without replacing the original exception.

Worker cleanup connections and both reference registrations form one protected
startup transaction. Failure before start disconnects registered cleanup slots and
rolls back partial additions; cleanup actions are idempotent. Once start is called,
actual finished/running state distinguishes pre-start failure from dispatched or
queued completion. In uncertain Qt state, references remain for actual completion.
The assessment adapter recognizes completed starter rollback to avoid duplicate
`deleteLater`; an overridden starter still receives conservative fallback cleanup.
No worker is terminated to solve rollback errors.

This is GUI-state isolation, not an OS-wide lock or atomic view of the host.
Other processes can still change the system. See the Stage 4F lifecycle below for
shutdown and HTTP bounds. Full GUI flows and supported real Lynis versions remain
unverified by mocked widgets.

---

## Increment 3 transactional undo history

`UndoHistoryStore` remains in the single Python module. Stable UUIDs identify
records; conditional committed claims precede privileged worker construction.
Immutable operation payloads and append-only events retain audit context.
`UndoPanel` initializes the protected store and pages Actionable/Audit history
with at most 200 rows; a separate Legacy view never executes/imports old JSONL.

`FindingsTable._verify` records verified successful remediation through the panel's
store before adding session reporting data. UI state refresh follows persisted
undo outcomes. `CommandWorker.failure_reason` distinguishes nonzero/missing-command
failure from timeout/uncertain execution while preserving success/failure signals.
No retry/reactivation or database replacement is automatic. See
`agent_docs/database_schema.md` for schema, lifecycle and protected paths.

## Storage paths

All under `$HOME` — **no root required for normal app state**.

| Path | Format | Writer | Notes |
|---|---|---|---|
| `~/.audit-dashboard.conf` | INI | `save_config()` [84-94](linux-security-dashboard.py#L84-L94) | Atomic via `tmp.replace()`; sections: `prefs` |
| `~/.audit-dashboard-undo.log` | JSONL | `save_undo_entry()` [1223-1230](linux-security-dashboard.py#L1223-L1230) | Append-only; one entry per line; loaded on UndoPanel init |
| `~/.audit-dashboard-errors.log` | text | Python `logging.basicConfig` [57-72](linux-security-dashboard.py#L57-L72) | Falls back to `/tmp/.audit-dashboard-errors.log`, then stderr-only |
| `~/.audit-dashboard-schedule.log` | text | crontab-installed entry [4651-4655](linux-security-dashboard.py#L4651-L4655) | Output of `apt list --upgradable` appended by user cron |
| `~/audit-report-<host>-<YYYYMMDD-HHMM>.html` | HTML | `RunEverythingSummaryDialog._open_report` [6360-6383](linux-security-dashboard.py#L6360-L6383) | `_generate_report` (toolbar) prompts via `QFileDialog` instead |

System-side reads (read-only): `/etc/os-release`, `/etc/ssh/sshd_config`, `/etc/sysctl.conf`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime`, `/var/lib/apt/periodic/update-success-stamp`.

---

## Schema

### `~/.audit-dashboard.conf` (INI)

```ini
[prefs]
language      = EN          # ISO key into LANGS dict
profile       = laptop      # PROFILES key (read but never re-applied — see B-002)
mode          = simple      # "simple" | "expert"
theme_locked  = false       # bool
locked_theme  = Light       # THEMES key, used only when theme_locked=true
```

### `~/.audit-dashboard-undo.log` (JSONL — one object per line)

Increment 2 format (local implementation pending review, 2026-11-15):

```json
{"schema_version": 2, "undo": {"operation": "package_install", "manager": "apt", "package": "example-package"}}
```

New entries also carry historical display metadata. `make_undo_operation` derives
only supported forward-action reversals; `build_undo_argv` validates the operation
and constructs executable arguments. `undo_presentation` derives previews and
warnings from that operation. Legacy, unknown-format and invalid-operation rows
are non-executable. Execution validates before dialogs and again afterward.
The file is now legacy display-only, including its structured records. New records
and durable outcomes are stored in SQLite; no JSONL import or rewrite occurs.
See SECURITY.md S-002 for target restrictions, limits and residual trust.

The example below describes legacy display metadata, not executable authority:


```json
{
  "time":             "2026-04-23 18:42:11",
  "action":           "remove 'telnet'",
  "cmd":              "sudo apt purge -y telnet",
  "undo_cmd":         "sudo apt install telnet",
  "risk_level":       "HIGH",
  "rollback_does":    "Reinstalls Telnet — an unencrypted remote shell",
  "rollback_risk":    "Every command you type ...",
  "rollback_exploit": "An attacker on your network ...",
  "name":             "telnet"
}
```

Rollback row removal matches on **`time + action + cmd + undo_cmd`** (four-field key) — see [_remove_undo_entry_after_rollback](linux-security-dashboard.py#L5124-L5153). Never on `time` alone.

---

## Public surface

This is a desktop GUI; the only external API is the Ubuntu CVE endpoint.

| Surface | Where | Notes |
|---|---|---|
| **CLI** | `python3 linux-security-dashboard.py` or `linux-security-dashboard` (deb launcher [packaging/linux-security-dashboard](packaging/linux-security-dashboard)) | No flags; all config via the GUI |
| **HTTP (outbound)** | `https://ubuntu.com/security/cves.json?package=<pkg>&limit=5` [1494-1499](linux-security-dashboard.py#L1494-L1499) | UA: `linux-audit/4.2`; system trust store; ~28 packages per scan; 8s socket timeout, up to 2 attempts/package within a 60s batch deadline; 2 MiB/response |
| **TCP probe (outbound)** | `1.1.1.1:443` [727-737](linux-security-dashboard.py#L727-L737) | Connectivity gate; no payload sent |
| **Crontab entry** | User crontab; marker `# audit-dashboard-schedule` [4557](linux-security-dashboard.py#L4557) | Read-only `apt list --upgradable` redirected to `~/.audit-dashboard-schedule.log` |
| **Subprocess execs** | argv lists only — `subprocess.run`/`Popen`, no `shell=True` (verified) | Sudo via `sudo -S` + stdin password OR `sudo` with `stdin=DEVNULL` for cached |
| **Disk writes** | `/etc/sysctl.conf`, `/etc/sysctl.d/99-*.conf`, `/etc/modprobe.d/*.conf`, `/etc/ssh/sshd_config` (via `sed`), Timeshift snapshot store | All gated through `PreActionDialog` or `GuidedWizard` confirmation |
| **systemd state changes** | `systemctl disable --now`, `systemctl mask`, `systemctl restart sshd`, `systemctl enable apparmor` | Each one preceded by a confirmation dialog showing the exact argv |
| **Package mgmt** | `apt purge`, `apt install`, `dpkg -l`, `apt-mark showmanual`, `apt list --upgradable`, `dpkg-query -W` | All package names validated through `valid_pkg()` before reaching argv |

---

## Module dependency graph

```
                    main() ─────────────────────┐
                       │                        │
                       ▼                        ▼
                StartupWizard            AuditDashboard
                                                │
   ┌──────────────┬────────────┬────────────────┼─────────────────┬───────────────┐
   ▼              ▼            ▼                ▼                 ▼               ▼
TerminalPanel FindingsTable LynisPanel      CvePanel         ToolsPanel       UndoPanel
   ▲              │            │                │                 │                │
   │              │            │                │                 │                │
   │              ▼            ▼                ▼                 ▼                │
   │          PreActionDialog  StreamingCmd  HttpWorker        ToolCard            │
   │          ExplainDialog    Worker        +CommandWorker    +CommandWorker      │
   │              │                                            +ScheduleScan       │
   │              │                                                                │
   └──────── all panels write through ───►  WorkerMixin / CommandWorker ──►  TerminalPanel
                                            │
                            argv only ──────┴──── subprocess (no shell=True)

                                          ┌── RISK (RiskTracker)         module-level singletons,
   FindingsTable / RiskScorePanel ───────► ├── SESSION (SessionTracker)  imported by every panel
                                          ├── UNDO_LOG (list mirror)
                                          ├── IGNORE_LIST (set)
                                          └── T / LANG / BASE_FS / PKG_MGR
```

`SideBar` orchestrates: it owns references to **all** panels and the `QStackedWidget`, drives `_pre_scan` (clears findings + terminal + cancels in-flight CVE), and runs the completion-driven assessment. RUN EVERYTHING bypasses the clearing
`_pre_scan` path to preserve existing findings and evidence.

`AuditDashboard` monkey-patches `QApplication.instance().undo_panel_ref = undo_panel` ([6850](linux-security-dashboard.py#L6850)) so `FindingsTable._verify` can post live entries from the table without holding a panel reference. See [R-003](CODE_REVIEW.md#r-003).

---

## Open architectural questions

1. **Single-file boundary.** `code_conventions.md` mandates "Keep the single-file architecture." At 7186 lines this is now well beyond comfortable navigation. The constraint is documented but not justified — does it remain a goal, or is a controlled split (workers/, panels/, scans/) on the table?
2. **Profile persistence is half-wired.** `saved_profile` is read at [6715](linux-security-dashboard.py#L6715) but never used; the app always re-prompts via `_detect_profile`. See [B-002](BUGS.md#b-002). Is the intended UX always-prompt or remember-on-tick?
3. **Two cmd-string parse paths.** The wizard uses `shlex.split()` ([3395](linux-security-dashboard.py#L3395)), `_act` uses `cmd.split()` ([2554](linux-security-dashboard.py#L2554)), `_run_undo` uses `.replace("sudo ", "").split()` ([5115](linux-security-dashboard.py#L5115)). The agent_docs convention is `shlex.split()` everywhere. Should the latter two be normalised? See [S-001](SECURITY.md#s-001) / [R-010](CODE_REVIEW.md#r-010).
4. **Globals vs DI.** `RISK`, `SESSION`, `UNDO_LOG`, `IGNORE_LIST`, `T`, `LANG`, `BASE_FS`, `PKG_MGR` are module-level singletons accessed from every panel. Testability and reasoning suffer; would dependency injection through `AuditDashboard` be worth the churn? See [R-002](CODE_REVIEW.md#r-002).
5. **Synchronous main-thread scans.** `run_quick_checks` ([2734](linux-security-dashboard.py#L2734)) and the wizard's per-fix re-checks ([3346-3355](linux-security-dashboard.py#L3346-L3355)) run subprocesses on the main thread. Brief freezes are noticeable when the wizard opens. Should those move to workers? See [P-004](PERFORMANCE.md#p-004).
6. **Cross-distro parity.** `pkg_install`/`pkg_remove`/`pkg_installed` cover apt/dnf/pacman, but inventory scans (`_scan_os_installed`, `_scan_user_installed`) and CVE lookups (Ubuntu API only) are apt-only. Roadmap acknowledges this — needs an architectural decision before adding more apt-specific paths.

## Increment 4 Stage 4F shutdown and HTTP execution

The shared `ScanOwnership` also holds the shutdown lifecycle: `running`,
`shutdown_requested`, `waiting`, `safe_to_close`. Dashboard close requests accept
immediately only when no ownership token or worker references remain. Otherwise a
confirmation offers waiting for completion or cancelling shutdown. The still-live
window keeps processing queued results and actual Qt `finished` cleanup. A single
parent-owned 100 ms timer checks for drain; it does not sequence assessment steps
or block the GUI with `wait()`. Repeated requests reuse this timer. Cancelling
shutdown restores admission; it never claims to cancel the active operation.

New top-level scans, fixes, undo, clears and profile changes are rejected while
shutdown is requested/waiting. Existing identity-bearing continuations may finish
the current seven-step or legacy three-step sequence. Completion updates coverage
and outcomes normally; the toolbar summary popup is suppressed during shutdown.
Once safe to close, guarded scan callbacks are inert. The guided fix dialog also
refuses close/Escape while its workers or fix chain remain active. The old unused
`_stop_all_workers` method is now a non-mutating idle check: no thread termination,
reference clearing or GUI-thread waits occur there.

`HttpWorker` uses an isolated Python helper process for each urllib request, retaining
its QThread owner until actual completion. Fixed source is passed with `-I -c`,
without a shell, application import, sudo or stdin. TLS uses urllib's default system
certificate verification. The socket timeout is at most 8 seconds; this bounds
individual blocking socket operations, not total elapsed time. One monotonic
60-second budget covers the whole package batch, retries, DNS/headers/body and
helper execution. A helper exceeding the remaining budget is killed and reaped by
`subprocess.run`; only that unprivileged direct child is affected. Responses read at
most 2 MiB plus one overflow-detection byte; overflow is discarded as an error,
never parsed as successful evidence. At most two attempts per package share the
budget, with no retry sleep. Unchecked packages receive timeout records after the
budget expires. Batch `finished_ok` means response processing ended, not that
coverage succeeded; CVE coverage still counts actual usable responses.

Process creation, kernel stalls and scheduler delays can exceed wall-clock bounds.
In particular, direct-child reaping may wait in the HTTP QThread under OS failure;
the GUI remains responsive and closure stays deferred rather than abandoning it.
No forced QThread cancellation or command-worker termination changes were added.
External forced exit, crashes, desktop-session termination, real GUI/platform
teardown and frozen/embedded Python packaging have not been validated. The helper
requires a normal Python interpreter at `sys.executable` with standard-library
networking support. Forced exit during undo retains the existing SQLite pending /
outcome-unknown recovery semantics; shutdown does not manufacture success.

### Guided-fix startup rollback correction

Each guided command now has a small startup/terminal guard in `_run_next_fix_cmd`.
Logical outcomes received during `start()` are deferred until it returns. Confirmed
pre-dispatch failure stops the pending chain, clears its password references,
restores Run and refreshes status without declaring success. This applies to both
the first command and later commands. A refresh error cannot restore a stuck
running flag or replace the recorded startup error.

A startup exception after dispatch is not completion: the dialog retains its
running flag, worker/ownership references and password until actual Qt `finished`.
Then the chain fails once, clears the dialog and affected worker password references
and restores dismissal after worker cleanup. Fast completion followed by an
exception also fails rather than dispatching the next command. Duplicate logical
outcomes cannot stop or advance a later step. Normal successful command chaining
is preserved; this does not change command-worker execution, dashboard shutdown,
HTTP helpers, ownership coordination, undo history or risk/coverage calculations.

### Guided-fix outcome / thread completion boundary

Guided commands record logical success/failure independently of Qt `finished`.
The per-command guard now waits for actual thread completion on every dispatched
path, including ordinary success and failure. Success can advance exactly once
only after both notifications; failure restores controls and stops the chain only
once the thread has completed. Until then the fix-running flag, Run-disabled state,
password and worker references remain protected. Completion without an observed
command outcome remains an unknown/failure, never an automatic successful step.
Confirmed pre-dispatch startup failure still performs immediate recovery because
there is no running worker to await. Ownership cleanup remains WorkerMixin's job;
advancing one command cannot retire the next command's worker.
