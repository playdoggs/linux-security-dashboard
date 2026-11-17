# Stage 3 — seven-section workspace

This stage changes navigation and presentation. Existing scanners, ownership,
coverage, scoring, Simple/Expert suppression, report generators, authorization,
remediation, undo storage and shutdown execution paths are preserved.

## Feature mapping

| Destination | Existing functionality and actions |
|---|---|
| Overview | Local endpoint identity, current profile, original severity/section scores, coverage verdict/details; links to Assessments and Findings |
| Assets | Existing system details; OS/user package inventory; existing all-package listing. Results still open Findings/use Activity; these actions retain their original result replacement behaviour |
| Assessments | RUN EVERYTHING (seven steps), legacy full scan (three), unused packages, listening ports, risky services, quick checks, temperatures, SMART drive health, CVEs, update checks, Lynis; scheduler dialog shortcut |
| Findings | Original table, search, explanations, ignore/clear and per-row remediation actions; original Simple/Expert behaviour |
| Remediation | Original guided fix dialog, recommended tools/categories/install/run/help controls, undo/history/paging/details. The original scheduler shortcut in Tools is retained as an alias |
| Reports | Original Executive/Technical export chooser, existing assessment summary and session summary; original report data/selection/wording |
| Settings | All seven appearances, theme lock, language, presentation mode, detect/change profile, command reference and diagnostic log |

Endpoint identity and operation state remain in the global header/rail. Activity
is the original shared terminal, with clear/text-size controls and a collapse toggle.
Collapsing it or changing pages never cancels, replaces or releases active work.
Alt+1–7 selects pages; Ctrl+R and Ctrl+1–5 retain scan actions. In Offline mode,
CVE/update launch buttons remain disabled and the CVE shortcut is not registered.

The old collapsible action groups are replaced by workspace destinations. Their
execution bookkeeping remains internal; Overview retains the established coverage
reporting. Scheduler, SMART and remediation retain their existing permissions and
confirmation behaviour. Merely selecting a navigation destination starts none of them.

## Implementation boundary

Pages and controllers are created once. The legacy `SideBar` controller now renders
the Checks actions; a small `WorkspaceRouter` translates its existing page-index
requests. Inventory/guided-fix buttons retain their existing connected slots and
mirror the original controller's enabled state. Tabs select existing CVE/Lynis and
tools/undo instances. A display-only timer reads existing state; scan progression
still uses the accepted completion-driven orchestration.

There is no prerequisite installation workflow, central collection, fleet model or
new security analysis. Existing CVE parsing and service-classification limitations
remain in their separate backlog. Navigation labels are English; the existing
language selector still requires restart for full application-label changes. New
workspace strings have not been translated as part of this stage.

## Validation and limits

See [running tests](running_tests.md#workspace-navigation-regression-checks) for
reproduction. Automated real-widget validation uses an isolated process, synthetic
evidence and a real bounded QThread. It does not run actual host scans or privileged
operations. The existing regression suite and corrected Stage 1 fixture comparison
remain the behaviour acceptance boundary.

Visual evidence is under [screenshots/stage3](../screenshots/stage3/), including all
seven pages in Enterprise and Hybrid, smaller-window/larger-text checks and an
explanation dialog. Each run preserves earlier evidence and writes a visual-check
JSON record. Temporary runtime data and logs remain outside the repository.

Full desktop accessibility, screen readers, translated workspace layouts and real
privileged workflows have not been validated. At larger font sizes or smaller
windows, wide existing tables require horizontal scrolling. Source-level comparison
confirms unchanged worker/storage/validator/report methods; it is supporting evidence,
not proof of every desktop integration path.


Executed Stage 3 result (2026-11-17): **219 tests passed** in 14.096 seconds
(217 existing plus two navigation tests); corrected capture comparison **MATCH**;
`git diff --check` clean. The final desktop fixture exited successfully with empty
stderr, including all seven themes, Qt keyboard activation and Tab traversal,
owned-thread navigation, sizing, explanation dialog and normal shutdown.
Two existing SQLite test ResourceWarnings remain outside this navigation change.
No privileged workflow, real schedule installation or host security scan was run.
