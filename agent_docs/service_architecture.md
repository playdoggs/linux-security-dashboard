# Service Architecture
<!-- AGENT: Read to understand class relationships before modifying any class. -->

## Key Classes
| Class | Purpose |
|-------|---------|
| `AuditDashboard` | Main window — assembles all panels, wires signals, owns toolbar |
| `RiskTracker` | Global `RISK` singleton — findings list + score calculation |
| `SessionTracker` | Global `SESSION` singleton — tracks scans run and actions taken |
| `FindingsTable` | Shared findings table fed from all scans. Owns risk sort, ignore, action cells |
| `TerminalPanel` | Shared terminal at bottom — `append()`, `append_ok()`, `append_err()`, `append_warn()`, `append_cmd()`, `append_info()`. A+/A- font buttons |
| `RiskScorePanel` | Risk progress bar + Duke face PNG (6 states) + profile label + update-age warning |
| `SideBar` | Left nav 252px — collapsible `section()` groups, collapse state saved to config |
| `CvePanel` | CVE lookup + upgradable packages — page 1 of QStackedWidget |
| `LynisPanel` | Lynis audit output — page 2 of QStackedWidget |
| `ToolsPanel` | 15 ToolCard widgets — page 3 of QStackedWidget |
| `UndoPanel` | Rollback log loaded from disk, live-updated — page 4 of QStackedWidget |
| `WorkerMixin` | Mixin for worker lifecycle: `_start_worker()`, `_stop_all_workers()`, `_any_running` |
| `CommandWorker` | `QThread` — runs shell commands, emits `output_ready`, `error_ready`, `finished_ok` |
| `HttpWorker` | `QThread` — fetches Ubuntu CVE API, emits `result_ready`, `finished_ok`. Cancellable |
| `ArrowSplitterHandle` | Custom `QSplitterHandle` — paints ⇕/⇔ glyph via `QPainter` |
| `CueSplitter` | `QSplitter` subclass that creates `ArrowSplitterHandle` |
| `ToolCard` | `QFrame` — one security tool card with install status + INSTALL + HOW TO USE |
| `GuidedWizard` | Step-by-step fix dialog — iterates through fix steps with sudo support |
| `ProfileDialog` | Startup profile detection + confirmation — runs `detect_profile()` |
| `ExplainDialog` | Plain English finding explanation popup |
| `PreActionDialog` | "Are you sure?" confirmation before any remove/disable |
| `SessionSummaryDialog` | "What's Been Done?" popup — built from `SESSION.build_summary()` |
| `ShowCodeDialog` | Full command reference popup |
| `StartupWizard` | First-run wizard — mode, connectivity, profile selection |

## Layout Structure
```
AuditDashboard (QMainWindow)
├── Toolbar (mode / lang / theme / "What's Been Done?" / "Change Profile" / report / show code / dev log)
├── RiskScorePanel (face 70px + progress bar + profile label + update-age label)
└── Body (QHBoxLayout)
    ├── SideBar (252px fixed — collapsible sections, persist collapse to config)
    │   ├── [▼/▶] SCAN YOUR SYSTEM
    │   │   ├── Scan for Unused Software     (Ctrl+1)
    │   │   ├── Check Open Ports             (Ctrl+2)
    │   │   ├── Check Risky Services         (Ctrl+3)
    │   │   ├── OS Pre-installed Software
    │   │   ├── User Installed Software
    │   │   └── RUN FULL SCAN                (Ctrl+R)
    │   ├── [▼/▶] SECURITY CHECKS
    │   │   ├── Quick Security Checks        (Ctrl+4)
    │   │   ├── Run Lynis Full Audit
    │   │   └── Step-by-Step Fix Wizard
    │   ├── [▼/▶] CVE VULNERABILITY CHECK
    │   │   ├── Check for Known Vulnerabilities (Ctrl+5)
    │   │   └── Check for Available Updates
    │   ├── [▼/▶] RECOMMENDED TOOLS
    │   │   └── View Recommended Tools
    │   └── [▼/▶] UNDO / ROLLBACK
    │       └── View Undo / Rollback Log
    └── CueSplitter (Vertical — draggable with ⇕ glyph)
        ├── QStackedWidget  (NO tab bar — sidebar controls page index)
        │   ├── Page 0: FindingsTable  ← default, shown after every scan
        │   ├── Page 1: CvePanel
        │   ├── Page 2: LynisPanel
        │   ├── Page 3: ToolsPanel
        │   └── Page 4: UndoPanel
        └── TerminalPanel (always visible at bottom)
```

## Global Objects
| Name | Type | Purpose |
|------|------|---------|
| `RISK` | `RiskTracker` | Score/findings singleton |
| `SESSION` | `SessionTracker` | Scan/action history singleton |
| `UNDO_LOG` | `list[dict]` | In-memory undo entries this session |
| `IGNORE_LIST` | `set[str]` | Names to skip in `add_finding()` |
| `T` | `dict` | Active theme colour values |
| `LANG` | `str` | Active language code e.g. `"EN"` |
| `PKG_MGR` | `str` | `"apt"` / `"dnf"` / `"pacman"` |
| `BASE_FS` | `int` | Base font size px (default 13) |
| `TOOLS_DATA` | `list[dict]` | 15 tool definitions for ToolsPanel |
| `PROFILES` | `dict` | 9 system profile configs with `normal_procs` / `normal_ports` |
| `THEMES` | `dict` | 5 themes: Dark, Hacker, Solarized, Light, Pink |
| `LANGS` | `dict` | 12 language dicts keyed by code |
| `ROLLBACK_RISK` | `dict` | Per-action undo risk explanation used by `get_rollback_info()` |

## FindingsTable column layout
| Col | Content | Notes |
|-----|---------|-------|
| 0 | Package/service name | UserRole = `{name,ftype,risk,detail,cmd_remove,cmd_disable}` dict |
| 1 | Finding type | LEFTOVER / NETWORK / SERVICE / CVE / HARDENING / OUTDATED |
| 2 | Risk badge | `🔴 ✖ HIGH` / `🟡 ▲ MEDIUM` / `🟢 ● LOW` / `ℹ INFO` |
| 3 | Tag | LEFTOVER / NETWORK / SERVICE / HARDEN / UPDATE / NORMAL ✓ |
| 4 | Detail text | Plain English explanation |
| 5 | Action cell | `QWidget` with `_build_action_cell()` buttons — rebuilt by `_sort_by_risk()` |

## Scan methods — _scan_* vs _do_scan_*
- `_scan_foo()` = user-facing button: calls `_pre_scan()` + `_do_scan_foo()`
- `_do_scan_foo()` = work only: no clear, safe to call from `_run_full_scan()`
- `_run_full_scan()` calls `_pre_scan()` once, then `_do_scan_*` variants via timers

## Key design rules
- Never run anything without explicit user confirmation (`PreActionDialog`)
- `L()` for all user-visible strings — falls back to EN silently
- Profile-aware: `FindingsTable._get_tag()` checks `normal_ports` / `normal_procs` before flagging
- `QStackedWidget` not `QTabWidget` — no visible tab bar; sidebar drives page switches
- `init_logging()` tries home dir, falls back to `/tmp`, falls back to stderr-only — never crashes startup
