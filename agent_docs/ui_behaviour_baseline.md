# UI redesign — Stage 1 behaviour baseline

Original Stage 1 recorded: 2026-11-17. UI-BL-001 follow-up recorded separately below. Scope: current local v4.2 implementation before the visual
foundation. No application source changes, real-user preference/history changes,
privileged commands, package installation or live scans were used.

## Reproduce and inspect

From the repository root, using the existing Python/PyQt6 environment:

```bash
python3 -B -m unittest discover -s tests -q
python3 -B tests/capture_ui_baseline.py --check tests/fixtures/ui_baseline_ui_bl_001
```

The first command uses existing mocks, temporary SQLite stores, isolated QThreads
and loopback-only HTTP fixtures; the execution environment must permit local sockets.
It launches no application GUI and performs no real sudo/package/systemd operations.
The capture utility AST-loads production definitions, uses inert table/item/dialog
endpoints, synthetic host/tool data and a fixed fixture timestamp. It blocks real
subprocess execution. The sequence capture reuses the existing controlled-signal
AssessmentSequence fixtures. These are semantic captures, not visual screenshots.

Original pre-fix reference files (preserved): [behaviour.json](../tests/fixtures/ui_baseline/behaviour.json),
[manifest.json](../tests/fixtures/ui_baseline/manifest.json) and four labelled
`*-coverage-fragment.html` files in the same directory. The manifest records the
application SHA-256. Production sorting, deduplication, filtering and mode-toggle
methods are exercised; action-widget construction is inert. This is provenance, not the behavioural comparison key: an
approved visual edit may change source bytes without changing result semantics.

To capture into a disposable directory for inspection:

```bash
python3 -B tests/capture_ui_baseline.py --output /tmp/dashboard-ui-baseline-review
```

Do not overwrite reference captures to conceal behavioural drift. Exit codes:
0 = capture/check succeeded without a report failure; 1 = production report smoke
failed; 2 = behavioural capture mismatch. Original Stage 1 returned exit 1 because
full HTML generation was broken. The corrected baseline command above now returns
exit 0. Checking against the preserved pre-fix directory returns exit 2 because the
report outcomes intentionally changed. No fake renderer is supplied.

## Original Stage 1 validation results

| Check | Observed result |
|---|---|
| Existing regression suite | 207 tests in 8.800 seconds; OK, zero failures/errors |
| Capture generation | Six files written; exit 1 because both full-report modes fail |
| Independent capture comparison | MATCH; exit 1 for the same product failure |
| GUI or privileged execution | Not performed in Stage 1 |

The new utility is support infrastructure, not an additional discovered test case.
A passing existing suite does not establish successful full-report generation.

## Current UI and required reachable functionality

These are current destinations/actions, not the proposed seven-section interface.

| Current surface | Functions that must remain reachable after navigation changes |
|---|---|
| Findings page | Results, search, severity sorting, tags, full explanations, session ignore, clear findings, remove/disable where offered |
| CVE/update page | Known-vulnerability lookup, installed versions and response errors; cached available-update listing; the same detail table is reused |
| Lynis page | Privileged audit, captured output and partial findings; installation offer when unavailable |
| Tools page | Category/name filtering, installed-state indicators, per-tool help, approved install/run actions; local scan scheduler |
| Undo page | Actionable reversals, audit history, legacy read-only history, Previous/Next/Refresh, selected-record safety detail and confirmed undo |
| Scan sidebar group | Unused software, network ports, risky package/service checks, OS pre-installed inventory, user-installed inventory and legacy full scan |
| Checks sidebar group | Quick checks, Lynis, guided fixes, temperatures and SMART health |
| Other sidebar groups | CVEs/updates when online controls are constructed; tools and undo |
| Global toolbar | RUN EVERYTHING, session summary, profile selection, HTML report chooser, command reference and development log |
| Shared controls | Simple/Expert mode, language, five themes, theme lock, global text size, terminal clear and resizable splitter |

`SideBar._scan_installed` exists internally; its presence does not establish a
separate exposed sidebar entry beyond the current inventory controls.

Dedicated dialogs: StartupWizard, ProfileDialog, ExplainDialog, PreActionDialog,
GuidedWizard, ScheduleScanDialog, SessionSummaryDialog and RunEverythingSummaryDialog.
Additional dialog flows: tool help, Executive/Technical report selection, native
save chooser, sudo/password prompts, install confirmations, warnings/errors and
shutdown wait/keep-open confirmation. All retain their existing safety semantics.

Guided fixes cover firewall, fail2ban, SSH, automatic updates, core dumps, kernel,
network, legacy protocols, filesystems, DMA, AppArmor and Ctrl+Alt+Del handling.
Scheduling is existing user-crontab functionality, not central scheduling.
Themes: Dark, Hacker, Solarized, Light, Pink. Language choices: EN, DE, ES, FR, PT,
IT, NL, PL, RU, SV, TR, ZH; presence of a choice is not proof of complete translation.

## Execution and coverage contract

| Order | Seven-step RUN EVERYTHING | Completion boundary |
|---|---|---|
| 1 | Unused software (`deborphan`) | Command worker completion, or explicit skipped result |
| 2 | Open network ports (`ss -tunlp`) | Command worker completion and parsed evidence |
| 3 | Risky services | Synchronous completion of seven package probes; this is not a general active-service census |
| 4 | Quick security checks | Synchronous evidence/coverage result for eight checks |
| 5 | Hardware temperatures | Synchronous sensors evidence/coverage result, or skipped |
| 6 | CVE vulnerabilities | CvePanel HTTP worker completion and usable-response accounting, or skipped |
| 7 | Available updates (`apt list --upgradable`) | CvePanel command worker completion and parsed evidence |

Legacy full scan invokes exactly steps 1–3. Neither aggregate silently adds Lynis,
SMART, remediation or package installation. The sequence fixtures capture seven
outcomes/one final-summary callback, versus three outcomes/no summary callback for
the legacy sidebar entry. Both finish inactive/finalized.

Per-step coverage states are succeeded, partial, failed, skipped, cancelled and
unknown. Complete seven-check coverage requires all seven correctly ordered named
outcomes to succeed and the run to be inactive. Three successful legacy steps do
not establish complete seven-check coverage. Missing dependencies and offline
checks must not be counted as successful evidence.

Run UUID + expected step index enforce once-only progression and finalization.
Asynchronous result processing and actual Qt completion are required; a command
outcome alone cannot release the completion boundary. Earlier findings remain
available when a later check is incomplete. General overlap/stale-result protection
uses one operation owner and worker identities.

## Findings, Simple/Expert, scores and report captures

Six synthetic inputs exercise SERVICE/HIGH, NETWORK/MEDIUM, HARDENING/LOW,
LEFTOVER/INFO, OUTDATED/MEDIUM and CVE/HIGH. A repeated identity is also submitted.

| Fixture | Retained rows | Score | Coverage/banner |
|---|---:|---:|---|
| Expert, all seven succeed | 6 | 51 | Complete; banner hidden because findings exist |
| Simple, same inputs | 4 | 48 | Complete; LOW/INFO discarded before score/report storage |
| Expert → Simple after collection | 6 | 51 | Existing LOW/INFO rows remain |
| Simple → Expert after collection | 4 | 48 | Discarded LOW/INFO rows do not return |
| Expert, search matches one row | 6 retained / 1 visible | 51 | Underlying sections and coverage unchanged |
| Expert, no findings, seven succeed | 0 | 0 | Complete; banner visible |
| One partial/failed/skipped/cancelled/unknown check | 6 | 51 | Incomplete; banner hidden in every case |
| Missing coverage or all checks failed, no findings | 0 | 0 | Unknown/failed; banner hidden |
| Three successful legacy steps | 6 | 51 | Incomplete seven-check coverage; banner hidden |

Weights: HIGH 20, MEDIUM 8, LOW 3, INFO 0; capped at 100. OUTDATED rows do not add
risk, despite their displayed severity. A complete check can discover a security
finding: coverage and finding severity are separate dimensions.

Simple mode suppression occurs in `FindingsTable.add_finding`, not merely in a
filter. Changing mode affects subsequent additions; it neither hides existing Expert rows
nor reconstructs previously discarded Simple rows. Reports and
summaries currently read retained table data. Search hides rows without deleting
them; it must not be treated as a request to export only visible matches. Dedup
uses `(name, type)` and session ignore uses name. Normal tags do not rewrite the
underlying severity. Preserve these current semantics in the visual foundation.

The four HTML files are **coverage statement fragments**, not complete reports.
They cover complete-with-findings and skipped/incomplete states in both report
modes. Fixed synthetic host data/time prevents personal data and timestamp drift.
`behaviour.json` captures all case outcomes, sections, score inputs, banner state,
verdicts and full-report failures for Executive and Technical modes.

## Execution and persistence safeguards

- Buffered and streaming command outcomes are distinct from unconditional native
  Qt completion. Streaming deadlines, concurrent pipe handling, output bounds and
  direct-child cleanup remain unchanged.
- Guided fixes require command outcome AND Qt finished before advancement or
  control restoration. Confirmed pre-dispatch startup failure recovers immediately;
  post-dispatch errors retain worker ownership, credentials and close protection.
- Remediation retains existing authorization/confirmation, optional Timeshift
  gating and verification behaviour. Do not reorder prompts as a cosmetic change.
  Package-removal verification probes installation; some non-removal actions trust
  successful command exit. This baseline does not claim complete restoration.
- Structured undo validates the operation allowlist, manager, arguments and schema;
  stored free-form strings are not execution authority. Record/attempt UUIDs and
  an atomic durable pending claim precede worker creation; outcome/audit persistence
  precedes display updates. No memory-only fallback or automatic uncertain retry.
- SQLite file/path/permission/locking checks fail closed; history pages are bounded
  to 200 rows. Original JSONL stays unchanged, historical and non-executable.
- Operation ownership blocks conflicting scans, clear/profile/fix/undo actions;
  stale callbacks cannot update a new operation. Page changes must not abandon it.
- Shutdown blocks new work, waits without an unbounded GUI-thread wait, and retains
  references through real completion. Cancelling shutdown does not cancel work.
- HTTP socket timeout, batch deadline, response cap and owned-helper cleanup remain
  intact. Lynis evidence is current-attempt captured output, not shared stale logs.
- Prerequisite setup is approved future work, not current behaviour: scan-triggered
  Lynis/SMART installation offers still exist and must not be silently refactored
  during the visual foundation. Remote installation is not authorized or implemented.

## Existing failures and Stage 2 gate

| ID | Existing issue | Evidence/status |
|---|---|---|
| UI-BL-001 | Previously: full Executive/Technical HTML generation raised `NameError` for missing `_render_finding_rows` | Fixed in the separately approved follow-up below; original failure captures preserved |
| UI-BL-002 | Non-empty Ubuntu CVE responses rejected by the current provider contract | Prior live audit/source evidence; separate corrective backlog; not rerun or corrected here |
| UI-BL-003 | Installed client packages labelled as risky network services | Prior live audit/source evidence; separate corrective backlog; no service-classification change here |

No redesign implementation has occurred. The original 207-test suite missed
UI-BL-001; the approved follow-up restores reports and adds four real-generator
tests. Stage 2 remains unimplemented and awaits review of the corrected baseline.

Legacy maintenance documentation contains outdated JSONL/four-field undo matching
claims. The implementation and current SQLite/UUID regression tests govern this
baseline; do not run old user-state reset instructions to reproduce it.

## UI-BL-001 corrective follow-up

The approved fix adds only the missing finding-row renderer to application code.
It renders the existing name/type/risk/tag/detail columns, preserves order and text,
HTML-escapes every value, and uses the existing report palette for severity. Empty
sections remain empty; collection, report template, scores and verdicts are unchanged.

Current references: [corrected behaviour.json](../tests/fixtures/ui_baseline_ui_bl_001/behaviour.json)
and [corrected manifest](../tests/fixtures/ui_baseline_ui_bl_001/manifest.json).
The corrected directory contains six full reports (Expert complete, Simple complete
and Expert skipped coverage, each Executive/Technical), six coverage fragments and
two JSON files. Original Stage 1 references remain untouched.

Comparison: all 14 pre-existing cases retain identical fields except `reports`;
both orchestration snapshots and all four original fragments are byte-identical.
The 28 full-report results changed from failed/NameError to generated/SHA-256.
Additional Simple-mode HTML files are new evidence, not changed selection semantics.
The manifest source fingerprint changes because the helper was added.

Validation: four new test methods passed, including a 24-report Simple/Expert ×
coverage-state × Executive/Technical matrix, plus escaping, empty/unknown results,
filtering and mode-switch cases. The existing coverage test no longer substitutes
row rendering. Full regression suite: **211 tests in 8.819 seconds, OK**. Corrected
capture comparison: **MATCH, exit 0**. No GUI/browser rendering, host probes or
privileged execution was performed for this correction. No remaining failure was
observed in the executed suite/report captures; UI-BL-002 and UI-BL-003 remain open.


## Stage 2 visual foundation comparison

Enterprise Workspace and Hybrid Professional share the same component skin as
all five retained palettes. The corrected fixture comparison remains **MATCH**:
findings selection, Simple/Expert suppression, scores, coverage, seven/three-step
sequences and both HTML modes are unchanged. Stage 1 and UI-BL-001 captures remain
historical reference evidence; no expected result was regenerated for Stage 2.

Live Qt validation used synthetic findings and temporary preferences, with host
probes disabled. It exercised seven appearances, existing pages, representative
dialogs, Tab traversal, font sizes 13–22, a 1100×700 window and normal shutdown.
At maximum font size, wider tables require horizontal scrolling; severity and
in-cell action geometry remain intact. This is not a privileged workflow test or
full accessibility certification. Existing CVE/service-classification backlog
items remain outside Stage 2.
