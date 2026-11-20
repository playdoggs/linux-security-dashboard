# Changelog

All notable changes to Linux Security Dashboard are documented here.

## [Unreleased] — v4.2.1

### Changed
- Increment 4H: add Settings → Prerequisites with read-only startup discovery,
  targeted pre-scan gates, five explicit availability states, unchecked selection,
  individual/batch installation and candidate/release allowlists. Preview pinned
  package/dependency plans before elevation, reject unrelated changes, revalidate
  before dispatch and verify packages/executables afterward. The dedicated APT
  executor never force-terminates an active transaction. Remove Lynis/SMART inline
  installers and automatic audit handoffs; preserve independent scan authorization.
- Increment 4G: prioritize Name, Risk and Actions in the findings table's visual
  order, with viewport-based widths and escaped full-text tooltips. Logical column
  indices, sorting, filtering, explanation content and action handlers are retained.
  Make explanation dialogs content-sized within screen-aware limits, with all text
  scrollable and a separate, always-visible Close control.
- UI redesign Stage 3: introduce Overview, Assets, Assessments, Findings,
  Remediation, Reports and Settings. Reuse persistent scan/result controllers;
  move existing controls to their workspace destinations and retain scan keyboard
  shortcuts. Add global operation/endpoint status and collapsible Activity.
  Preserve legacy scan routing through a presentation adapter, existing results,
  report semantics, privilege approval, undo persistence and shutdown behaviour.
- UI redesign Stage 2: add Enterprise Workspace (default) and Hybrid Professional,
  retaining all five legacy palettes and locked appearance preferences. Share
  semantic colours, typography, sizing and focus styles across existing widgets;
  refresh existing component/console colours on theme changes. Widen severity and
  action columns, increase row/control heights and wrap the existing toolbar at
  smaller widths or larger fonts. Professional themes hide the decorative face;
  legacy themes retain it. Navigation, result semantics and reports are unchanged.
- UI-BL-001: restore full HTML report generation with the missing five-column
  finding-row renderer. Escape every cell and use fixed severity colours without
  changing findings selection, scores, coverage wording or report structure.
  Add real-generator regression coverage and separate corrected baseline captures.
- Ubuntu/GNOME startup: bypass the GTK3/GDK legacy `antialiasing` schema crash
  with a process-local generic Qt platform theme before QApplication construction.
  Scope the fallback to the affected schema/session and preserve explicit non-GTK
  choices, other desktops and the dashboard's existing Fusion colour themes.
- Stage 4F guided-fix sequencing correction: success/failure signals now record
  command outcomes without advancing/restoring controls until Qt `finished`.
  Preserve immediate recovery for confirmed pre-dispatch startup failures.
- Stage 4F acceptance correction: recover guided-fix state after first/later
  pre-dispatch startup failure; stop the chain, clear temporary credentials and
  restore dismissal. Post-dispatch exceptions retain close protection until Qt
  completion. Startup and duplicate terminal callbacks cannot falsely advance.
- Increment 4 Stage 4F: defer window closure until actual worker/operation completion;
  reject new work during shutdown, support cancelling shutdown, retain guided-fix
  dialogs while active, and suppress shutdown-time assessment popups. Remove the
  unused helper's unsafe reference clearing and ineffective thread quit/wait.
- Bound CVE HTTP requests through unprivileged isolated Python helpers: 60-second
  total batch budget, 8-second socket timeout, 2 MiB response limit. Deadline and
  response errors remain incomplete evidence. Command workers are unchanged.
- Increment 4 Stage 4E: add shared operation/worker identities to isolate findings,
  coverage, status and report inputs. Reject conflicting requests before clearing
  or authorization; ignore retired/duplicate scan callbacks and retain workers
  until actual Qt completion. Preserve seven-step RUN EVERYTHING; remove delayed
  timers from the legacy three-check full scan. Individual CVE/update completion
  uses actual thread termination, with conservative parser/setup failures.
  Lynis now uses only successful current-attempt output with a recognized summary;
  shared log reading and sudo-cat fallback were removed. Added overlap/stale-result,
  startup, handoff, provenance and real-QThread ordering regression tests.
  Acceptance rollback corrections now protect admission preparation and make signal/
  reference registration exception-safe. Failed pre-dispatch setup restores state
  and releases phantom references; dispatched work retains completion ownership.
  Cleanup is idempotent and preserves original errors.
- Increment 4 Stage 4D: separate six-state evidence coverage from findings severity.
  Require all seven checks to succeed before a complete verdict; missing, partial,
  failed or unknown checks suppress all-clear reporting. Show per-step coverage in
  the summary and both HTML report modes. Scan-only package probes, quick checks,
  temperatures and parsers now distinguish verified evidence from missing or
  unrecognized results. Preserve findings, sequencing and remediation; risk-score
  calculations and severity thresholds remain unchanged. Neutral findings labels
  replace score-only health claims. General panel overlap remains Stage 4E.
  Acceptance corrections reject contradictory SSH values instead of selecting a
  secure match. Temperature evidence now includes stderr and return status while
  retaining usable readings/findings; mixed failures are partial, not successful.
  Harmless diagnostics remain non-fatal; sensors uses child-only LC_ALL=C.
- Increment 4 Stage 4C: replace RUN EVERYTHING timer polling with seven explicit
  completion-driven steps. UUID run/step guards reject duplicate and stale
  callbacks; CVE/update worker thread completion gates progression. Record terminal
  outcomes, preserve existing findings, reject repeated starts and temporarily
  lock conflicting controls. Final summary fires once after all seven outcomes.
  Coverage verdicts and general panel overlap remain Stages 4D/4E.
  Acceptance correction: move CVE logging before dispatch and retain asynchronous
  completion ownership across post-start/setup exceptions. Record the error while
  waiting for the actual worker end; cover pre-start, post-start, queued/inline
  completion and duplicate acknowledgement regressions.
- Increment 4 Stage 4B: concurrently drain nonblocking stdout/stderr and password
  input under one monotonic execution deadline, including inherited open pipes.
  Cap captured output at 2 MiB and live updates at 4096; incomplete evidence fails
  rather than reaching Lynis success parsing. Bounded direct-child cleanup and
  owned-pipe closure report reaping separately from unverified descendant state.
  No new termination privileges or process-group killing. Added isolated Python
  subprocess regressions alongside existing mocked outcome/callback tests.
- Increment 4 Stage 4A: streaming commands emit exactly one terminal outcome
  when execution returns: success only for exit zero, failure for nonzero exit,
  timeout, missing executable or exceptions. Failed Lynis audits skip successful
  parsing/completion and notify the sidebar failure handler. Thread cleanup still
  uses `QThread.finished`. Blocking pipe reads and full process cleanup remain
  deferred to Stage 4B.
- Increment 3 (pending review): added and integrated a protected SQLite history
  store with stable IDs, atomic claims, durable outcomes and append-only events.
  Claims commit before worker creation; outcomes commit before UI state updates.
  Actionable, audit and legacy views replace pages of at most 200 rows. Completed,
  failed and uncertain records never automatically reactivate. Original JSONL is
  preserved as display-only history, including old structured records.
  Added temporary-store concurrency/crash tests and mocked UI execution tests.
  Storage errors are visible and never fall back to memory-only undo.
- Documentation refreshed across all markdown files to match current v4.2 code behavior.
- Architecture, communication flow, persistence model, and test checklist updated to current implementation.

### Security
- Increment 3 locking correction: only SQLite opens the published history DB;
  private-file publication preserves restrictive creation permissions without
  raw descriptor closes releasing another connection's POSIX locks. Added an
  independent-process lock regression and documented path-race limitations.
- Increment 2 (local, pending review): replaced free-form privileged undo with
  versioned, validated package/service operations and generated previews/warnings.
  Legacy history remains visible but cannot execute. Unknown/malformed operations
  cannot request sudo or start workers. Loading is bounded and never migrates files.
  Automatic undo is limited to reviewed apt/dnf and service operations; persistent
  removal after successful rollback remains unresolved.
- Added an explicit security review record (2026-04-23) to docs.
- Documented open high-impact logic/command-execution bugs in Guided Wizard and quick checks.

### Fixed
- Buffered command failures no longer trigger success callbacks. Guided fixes
  stop after failure and restore controls; failed actions and rollbacks retain
  their findings/history. Failed Lynis installation and update checks clear
  pending scan state without invoking healthy-completion callbacks. Partial
  wizard failures refresh status indicators without claiming full completion.
  Update callback references are released on either outcome.
- Added mocked command-outcome regression tests; no privileged commands are
  executed by the suite. Streaming worker behavior is unchanged.

## [v4.2]
- Current production baseline reflected by this repository state.
