# ARCHITECTURE

**Function:** Living map of the codebase — what each component is, how data flows between them, where state lives on disk, and what surfaces the app exposes.

Last reviewed: 2026-05-03

---

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
| `THEMES` / `apply_theme()` / `build_palette()` / `make_style()` | [141-440](linux-security-dashboard.py#L141-L440) | 5 colour themes; QPalette + global Qt stylesheet rebuilt on theme/font change |
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
| `LynisPanel(QWidget, WorkerMixin)` | [3738-4012](linux-security-dashboard.py#L3738-L4012) | Streams Lynis output; parses `/var/log/lynis.log` (preferred) or live text fallback |
| `CvePanel(QWidget, WorkerMixin)` | [4016-4340](linux-security-dashboard.py#L4016-L4340) | CVE table + offline gating + apt-list-upgradable; shared by both buttons |
| `ToolCard(QFrame)` | [4344-4545](linux-security-dashboard.py#L4344-L4545) | Single recommended-tool card with INSTALL / HELP / RUN |
| `ScheduleScanDialog(QDialog)` | [4548-4716](linux-security-dashboard.py#L4548-L4716) | User-crontab installer for periodic upgradable-package check |
| `ToolsPanel(QWidget)` | [4719-4891](linux-security-dashboard.py#L4719-L4891) | Category-tabbed grid of tool cards + the schedule card |
| `UndoPanel(QWidget, WorkerMixin)` | [4894-5153](linux-security-dashboard.py#L4894-L5153) | Persistent rollback log table with HIGH-risk warning UI |
| `SideBar(QWidget, WorkerMixin)` | [5156-5842](linux-security-dashboard.py#L5156-L5842) | Collapsible nav + every scan handler + RUN-EVERYTHING queue (`_re_tick`) |
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
  │ _re_tick  │               │  StreamingWorker /  │               │  unused, │
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

RUN EVERYTHING (`SideBar.run_everything()` → `_re_tick()`, [5730-5789](linux-security-dashboard.py#L5730-L5789)) is a polled queue: each tick waits for `_any_running` to clear, runs the next step's `fn()`, then re-arms via `QTimer.singleShot(500, _re_tick)`. The final tick fires `on_complete` → `RunEverythingSummaryDialog`.

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

System-side reads (read-only): `/etc/os-release`, `/etc/ssh/sshd_config`, `/etc/sysctl.conf`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime`, `/var/lib/apt/periodic/update-success-stamp`, `/var/log/lynis.log`.

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
| **HTTP (outbound)** | `https://ubuntu.com/security/cves.json?package=<pkg>&limit=5` [1494-1499](linux-security-dashboard.py#L1494-L1499) | UA: `linux-audit/4.2`; system trust store; ~28 packages per scan; 8s timeout, 2 attempts |
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

`SideBar` orchestrates: it owns references to **all** panels and the `QStackedWidget`, drives `_pre_scan` (clears findings + terminal + cancels in-flight CVE), and runs the `_re_tick` queue.

`AuditDashboard` monkey-patches `QApplication.instance().undo_panel_ref = undo_panel` ([6850](linux-security-dashboard.py#L6850)) so `FindingsTable._verify` can post live entries from the table without holding a panel reference. See [R-003](CODE_REVIEW.md#r-003).

---

## Open architectural questions

1. **Single-file boundary.** `code_conventions.md` mandates "Keep the single-file architecture." At 7186 lines this is now well beyond comfortable navigation. The constraint is documented but not justified — does it remain a goal, or is a controlled split (workers/, panels/, scans/) on the table?
2. **Profile persistence is half-wired.** `saved_profile` is read at [6715](linux-security-dashboard.py#L6715) but never used; the app always re-prompts via `_detect_profile`. See [B-002](BUGS.md#b-002). Is the intended UX always-prompt or remember-on-tick?
3. **Two cmd-string parse paths.** The wizard uses `shlex.split()` ([3395](linux-security-dashboard.py#L3395)), `_act` uses `cmd.split()` ([2554](linux-security-dashboard.py#L2554)), `_run_undo` uses `.replace("sudo ", "").split()` ([5115](linux-security-dashboard.py#L5115)). The agent_docs convention is `shlex.split()` everywhere. Should the latter two be normalised? See [S-001](SECURITY.md#s-001) / [R-010](CODE_REVIEW.md#r-010).
4. **Globals vs DI.** `RISK`, `SESSION`, `UNDO_LOG`, `IGNORE_LIST`, `T`, `LANG`, `BASE_FS`, `PKG_MGR` are module-level singletons accessed from every panel. Testability and reasoning suffer; would dependency injection through `AuditDashboard` be worth the churn? See [R-002](CODE_REVIEW.md#r-002).
5. **Synchronous main-thread scans.** `run_quick_checks` ([2734](linux-security-dashboard.py#L2734)) and the wizard's per-fix re-checks ([3346-3355](linux-security-dashboard.py#L3346-L3355)) run subprocesses on the main thread. Brief freezes are noticeable when the wizard opens. Should those move to workers? See [P-004](PERFORMANCE.md#p-004).
6. **Cross-distro parity.** `pkg_install`/`pkg_remove`/`pkg_installed` cover apt/dnf/pacman, but inventory scans (`_scan_os_installed`, `_scan_user_installed`) and CVE lookups (Ubuntu API only) are apt-only. Roadmap acknowledges this — needs an architectural decision before adding more apt-specific paths.
