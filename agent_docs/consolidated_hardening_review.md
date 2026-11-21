# Consolidated hardening review — scope, findings and implementation plan

Review covers structural indexing of every Python source/test file and application
function/class, privilege/process/storage/result boundaries, UI construction/style
sites, regression fixtures and existing architecture/known-bug records. The attached
JSON indexes locations. This is not a line-by-line proof of every branch or a live
security assessment. No real scans, installs, privileged commands or host changes
are authorized/executed here. Locations in the initial inventory refer to the
pre-correction source; current function names remain authoritative.

## Findings ranked before implementation

No Critical finding established within this review. High impact is not proof of
exploitation: privileged operations below require user authorization; authentication,
trusted package sources and existing command validation reduce exposure.

| ID | Severity | Confirmed mechanism/location | Decision |
|---|---|---|---|
| H01 | High | parse_prerequisite_simulation:661–682 ignores unknown action lines if some Inst rows are valid | Correct now: explicit grammar; unknown output aborts plan |
| H02 | High | execute_prerequisite_plan:2956–2970 recovery sleeps only when read raises; EOF can spin while process lives | Correct now: paced recovery, retaining ownership and no kill |
| H03 | High | ToolCard._install:6377–6412, GuidedWizard._run_next_fix_cmd:5240–5324 and undo package restores use generic CommandWorker timeouts | Defer migration: changes privileged workflow/recovery guarantees |
| H04 | Medium | detect_prerequisites:549–589 discovers PATH executables; build_prerequisite_plan:685–713 checks leaf stat only | Correct now: separate trust diagnostic and parent/path validation for installer tools; do not silently change all scan PATH policy |
| H05 | Medium | FindingsTable._act:4289–4348 builds elevated argv from internally generated strings using cmd.split; other legacy elevated paths use PATH | Defer shared privileged operation schema/absolute-path policy; no demonstrated untrusted-history execution path (undo is validated) |
| H06 | Medium | Quick checks, temperatures, SMART, profile probes, package verification and scheduler issue synchronous subprocess calls on GUI thread | Defer moving workflows into workers; risks sequencing/approval changes. Timeouts exist but cumulative UI stalls remain |
| H07 | Medium | CVE provider expects cvss_severity at CvePanel._handle_cve_result:6037–6121; installed packages treated as risky services at SideBar._do_scan_services:7577–7619 | Existing confirmed compatibility/classification backlog; defer scan semantics changes |
| H08 | Medium | prerequisite_read:506–517 and generic CommandWorker buffer before checking/without output bounds | Defer shared bounded subprocess collector; new prerequisite APT executor already bounds retained/live output |
| H09 | Medium | make_style:244–298 defines several selected states through colour only; per-category inline style can override shared border | Correct now: native ticks/dots, stronger borders/bold selection, stable focus cues |
| H13 | Medium | APT preview-to-execution is not atomically locked with external package managers; scripts execute as root | Accepted architectural limitation; version pins/fingerprints/revalidation mitigate, not eliminate. Defer libapt/transaction redesign |
| H15 | Medium | Prerequisite confirmation requested No, but Qt autoDefault could promote Yes on startup/focus | Initially deferred; corrected in the authorized final confirmation hardening on 2026-11-18. See ui/CONFIRMATION_REVIEW.md |
| H10 | Low | generate_report:8492–8667 queries each tool twice; counts can disagree if package state changes between calls | Correct now: one query per unique tool per report, no cross-report stale cache |
| H11 | Low | save_config:91–101 uses predictable .tmp under HOME, default creation permissions and no multi-instance merge | Defer protected persistence policy; no secret storage identified here, requires config/recovery decisions |
| H12 | Low | SideBar retains retired section bookkeeping/helpers; many fixed-size dialog/control constants and English-only shell labels | Defer deletion/localisation/dialog-wide layout redesign until approved; retain compatibility |
| H14 | Low | Explanation QLabel auto-rich-text predates this work; screen-reader/high-DPI/full desktop teardown lack exhaustive tests | Defer plain-text policy change (could alter intended glossary formatting); test selected states and representative fixtures now |

## Privilege boundary review

- Prerequisite install: fixed approved plan, explicit confirmation, stdin authentication,
  absolute tools, sanitized environment, live version/state revalidation, no timeout kill.
- Undo: schema/allowlists, post-dialog revalidation, durable claim before worker creation;
  no stored free-form command execution. SQLite protections/transactions left intact.
- Findings actions: confirmation/snapshot optional, password and generic command worker;
  internal strings are not shell=True, but stronger shared argument policy is deferred.
- Guided fixes: user-approved command chains and native thread completion protections;
  include deliberate shell/config-edit commands from the built-in catalogue. No new
  interpretation of files as commands added. Generic timeout remains a package risk.
- Tool install/run: catalogue-derived argv and approval; generic deadline/PATH caveats.
- SMART/Lynis/snapshot: separately authorized; root processes may have limits/side effects.
  Read-only assessment scope does not mean Timeshift/remediation are read-only.
- Scheduler: unprivileged crontab writes after explicit user action; not package elevation.

## Coordinated plan

1. Implement only H01/H02/H04/H09/H10 with regression tests. Separate security helpers
   from shared stylesheet changes in the source. Preserve scanners, scores, allowlists,
   undo and privilege/approval policy. Do not remove dead code speculatively.
2. Run focused tests then full suite, corrected baseline and real-widget Enterprise/
   Hybrid fixtures at normal/smaller sizes. Save unique evidence in project screenshots.
3. Report actual outcomes and unresolved risks. H03/H05/H06/H07/H08/H11–H14 behavioural,
   policy and architecture proposals need user approval, not automatic implementation.

## Coverage limits

Every definition/test file is inventoried; detailed manual review prioritised the
listed boundaries. No claim that every widget, branch, OS distribution, screen reader
or real package-maintainer script has been exercised. Full fleet/OT assessment,
external penetration testing and performance certification are outside this review.

## Implemented corrections and current locations

| Source | Current function/line | Result |
|---|---|---|
| linux-security-dashboard.py | parse_prerequisite_simulation:684 | Recognized C-locale boilerplate/package lists and Inst/Conf actions only; unknown output aborts planning, including whitespace-prefixed removals |
| linux-security-dashboard.py | execute_prerequisite_plan:2942 | Every recovery iteration sleeps 50 ms, including EOF; empty exception messages retain the exception class as failure evidence. No termination/cancellation added |
| linux-security-dashboard.py | executable_trust:552; detect_prerequisites:571; build_prerequisite_plan:722 | Discovery remains availability only; UI explains path trust separately. Installer executable paths, resolved targets and parents must be protected |
| linux-security-dashboard.py | make_style:244; ToolsPanel._style_cat_buttons:6800 | Native ticks/dots plus structural borders for checked controls/categories, selected rows and active navigation; existing focus styling retained |
| linux-security-dashboard.py | generate_report:8531 | One presence query per unique tool per report, preserving rendered output and no persistent cache |

Updated deferred locations: ToolCard._install:6416, GuidedWizard._run_next_fix_cmd:5279,
FindingsTable._act:4328, run_quick_checks:4580, run_temperature_check:4741,
CvePanel._handle_cve_result:6076, SideBar._do_scan_services:7616,
prerequisite_read:509 and save_config:91. Deferred findings are not fixed by these
line-number updates. Legacy timed package execution is a confirmed design concern;
its exact process/transaction consequence has not been tested with real packages.

`codebase_review_inventory.json` contains a 22-Python-file census and current
locations for all 421 application class/function definitions, including nested
callbacks. The pre-correction direct-definition index is retained separately.
An AST comparison against the pre-correction 4H snapshot identifies only seven
modified functions and the one new trust helper listed above. Command/streaming/
HTTP workers, scan ownership, scan result logic, structured undo, SQLite and risk
calculations are structurally unchanged by this consolidated batch.

## Executed evidence — 2026-11-17

- Focused prerequisite/report/theme tests: initially 40 passed; an additional
  empty-exception regression also passed. Final full suite: **256 tests passed in
  24.786 seconds**, zero failures/errors. This is eight additional methods over the
  initial 248-test 4H snapshot. Local HTTP fixtures require a sandbox with loopback
  access; no external API, package installation or sudo was used.
- Before/after probe: execute the new regression methods with production AST nodes
  from the pre-correction snapshot, in memory only. Five selected methods produced
  nine failing assertions/subtests and no fixture errors. Unknown-action rejection,
  EOF pacing, discovery/trust wording, report query count and selected-state cues
  all detected the previous implementation. The corrected full suite passes.
- Report query fixture: three catalogue entries with two unique names now cause
  **four total queries for two reports**, versus twelve previously. Normal unique
  catalogues halve their queries. This is deterministic call-count evidence, not a
  wall-clock GUI performance benchmark. EOF recovery tests require one sleep per
  iteration; there is no claim of complete process/OS scheduling bounds.
- Corrected Stage 1 captures: **MATCH**. Findings selection, Simple/Expert behaviour,
  scores, assessment coverage text and both HTML modes are unchanged.
- Real Qt desktop fixture: all seven destinations and all seven themes exercised
  with synthetic host data and one gated, unprivileged fixture QThread. No host scan
  executes. Enterprise/Hybrid captures include 1100×700 logical-pixel findings,
  selected rows, profile radios, checked checkbox, explanation and larger text.
  Native tick/dot, row underline and navigation marker are visible in inspected
  images. Unique evidence is under `screenshots/increment4h-hardening/`.
- One repeat desktop run lost row selection after requesting focus and failed the
  new fixture assertion. The fixture now settles focus/resize before setting its
  current cell and selecting the row. The rerun passed; no production behaviour
  was changed to hide the assertion. Desktop Space activation and main-window Tab
  traversal passed; profile-dialog focus was unavailable (0/2 Tab checks), so full
  desktop keyboard/accessibility coverage remains unproven. Offscreen Qt also tests
  the fixture. Screenshots are synthetic real-widget evidence, not a live host audit.
- `git diff --check HEAD` passed. The existing user-staged content is preserved;
  the batch is additional unstaged/untracked work, with no index mutation. The older
  `increment4h-independent-review.tar.gz` remains a historical, pre-hardening archive.

Reproduction commands:

```bash
python3 -B -m unittest discover -s tests -p test_prerequisites.py -q
python3 -B -m unittest discover -s tests -p test_html_reports.py -q
python3 -B -m unittest discover -s tests -p test_ui_foundation.py -q
python3 -B -m unittest discover -s tests -q
python3 -B tests/capture_ui_baseline.py --check tests/fixtures/ui_baseline_ui_bl_001
QT_QPA_PLATFORMTHEME=generic python3 -B tests/ui_navigation_probe.py
git --no-optional-locks diff --check HEAD
```

No new privileged capability, package allowlist, automatic remediation, scan
semantics or approval workflow was introduced. Root path checks remain observations
subject to filesystem/TOCTOU limitations, not an atomic trusted-execution mechanism.
Unusual APT output fails closed; supported-release strings alone do not prove every
APT version's output compatibility. Keep H03/H05/H06/H07/H08/H11–H14 visible for the
next approval decision instead of presenting this batch as an exhaustive security
certification or complete UI/accessibility audit.

Final focused rerun after the fixture-ordering correction: both workspace navigation
tests passed in 4.172 seconds. The staged application bytes still match the initial
pre-hardening snapshot. Unrelated zero-byte `agent_docs/ui/` placeholders appeared
while the task was in progress; they were left untouched and are not review evidence.

## Supplied visual reference alignment — 2026-11-18

The five reference images are now populated and were all inspected. Earlier
zero-byte-placeholder observations above are historical. Their interpretation,
colours, typography, spacing, components and state rules are canonical in
[DESIGN_SYSTEM.md](ui/DESIGN_SYSTEM.md). Teal emphasis is adapted to the approved
light/Hybrid appearances; the dark example screens do not redefine package
allowlists, statuses, findings or navigation.

This follow-up changes only THEMES/UI_METRICS, apply_theme, make_style,
ToolsPanel._style_cat_buttons and one presentation property in
PrerequisitesPanel.__init__. A production AST comparison confirms prerequisite
detection/planning/approval/execution methods, package allowlists, scan methods,
coverage, workers, shutdown, undo, SQLite and scoring are unchanged from the
pre-styling snapshot. The initial 4H hardening remains separately reviewable.

Validation: **258 tests passed in 26.219 seconds**, corrected Stage 1 captures MATCH.
Both real-widget desktop fixtures completed before and after. The
local paired evidence index (`screenshots/ui-reference-alignment/comparison.md`) covers
all five reference themes using synthetic data, including selected rows/profiles,
native check marks, active navigation, focus/pressed buttons, prerequisite selection
and approval dialogs. The image subjects remain actual current features. No real
installation, scan or privileged command ran. Profile-dialog Tab traversal still
lacked desktop focus (0/2); safe Cancel-button focus and main-window Tab traversal
were verified. This is representative validation, not an exhaustive desktop audit.

**H15, independently probed:** the preview calls No.setDefault(True), but five
isolated offscreen dialog observations in each source (before and after visual
alignment) reported Yes.isDefault() == True and No.isDefault() == False. The
new default-button outline makes that Qt state visible; it does not cause it.
Enter-key approval consequences are inferred, not tested here. Authentication is
still separately required and the fixture never invokes real sudo. Do not claim
that the safe No default is established. Correct explicit initial focus/auto-default
behaviour and add Enter/Escape tests in a separately approved change; do not alter
approval behaviour silently within this styling pass.

## H15 correction — authorized follow-up, 2026-11-18

The preceding deferral is historical. The user authorized confirmation hardening.
Shared button policy now disables autoDefault on both choices, assigns the sole
default/initial focus to No or Cancel and preserves explicit Space/click approval.
The same issue was corrected in pre-action, guided-fix, tool-install and rollback
decisions. Password entry and shutdown semantics were not changed.

The new real prerequisite-dialog regression fails against the prior source with
`initial dialog focus is not No` and passes after correction. Runtime tests verify
isDefault, autoDefault and actual Qt focus before/after navigation, then send Enter,
keypad Enter, Escape, Space and Tab. Profile traversal/focus is now exercised with
an activated dialog rather than skipped. Final suite: **262 tests passed**;
Enterprise/Hybrid desktop probes passed and corrected captures MATCH. Full audit,
remaining risks and evidence: [CONFIRMATION_REVIEW.md](ui/CONFIRMATION_REVIEW.md).


## Superseding final security batch — 2026-11-21

The earlier deferred H03/H05/H16 entries and unchanged-worker statements describe
older snapshots. They are superseded for the current source by
[final_security_hardening.md](final_security_hardening.md): legacy privileged package
and shell transactions now share no-kill ownership; privileged argv uses protected
system executable paths and a clean environment; package diagnostics and unexpected
errors are sanitized before storage, signals, logging and display. H13 transaction
TOCTOU, non-privileged PATH policy, general buffered output, synchronous UI probes,
CVE parsing/service classification and the other explicitly deferred work remain.
H15 confirmation/default/focus protection is preserved and revalidated.
