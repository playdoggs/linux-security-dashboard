# Scan prerequisite management — Increment 4H

Settings → Prerequisites detects local executable availability and cached package
candidates without sudo, scans, package-index refreshes or installation. The
Assessments link opens this table; unavailable scan controls stay visible and
explain where to resolve prerequisites. All selections start unchecked and are
cleared on Refresh. Install Selected deduplicates packages across sections.

## Scope and interpretation

The table distinguishes Installed, Missing, Unsupported, Not Required and Could
Not Verify. Installed means an executable is present, not that a scan passed or a
service works. Sources of uncertainty remain explicit. Before each relevant scan,
stat-based executable/platform checks run again. Missing prerequisites yield
Skipped outcomes; Quick checks can still run its unaffected probes. Coverage stays
separate from findings. Seven-step RUN EVERYTHING and the legacy three-step scope
are unchanged.

Discovery now shows the PATH discovery location and a separate trust
diagnostic. A found executable can be marked Installed while its path is not
root-controlled. This does not bless arbitrary PATH programs. Privileged execution
now ignores caller PATH and resolves the program, sudo and env through protected
system directories immediately before dispatch. Non-privileged scan PATH policy
is unchanged. Prerequisite installer tools also require regular executable files with root-owned, non-group/world-
writable original/resolved paths and parents. Symlinks to protected system tools
can pass; inaccessible or unsafe paths fail closed. These stat checks do not verify
signatures, package provenance, ACLs, mount semantics or an immutable execution target.

`PREREQUISITES` is the canonical executable-to-package registry. Generic probes and
existing RPM/pacman package-query paths remain available on their supported
platforms. Ubuntu-specific CVEs remain unsupported elsewhere. The installation
allowlist is deliberately narrower: Ubuntu 22.04, 24.04 and 26.04 only, with
`deborphan`, `iproute2`, `lm-sensors`, `smartmontools`, `lynis` and `cron`.
A verified local candidate and working installer/sudo backend are mandatory.
Core OS repair, SSH/UFW/Fail2ban/unattended-upgrades and optional tool-catalogue
packages are not offered as scan-prerequisite installations. A missing deborphan
candidate does not trigger a replacement, repository addition or external download.

## Approval and execution

1. An individual Install or Install Selected builds a bounded read-only APT plan.
   It checks dpkg audit output, candidates, source/config ownership and permissions,
   public APT state fingerprints, simulation results and candidate policies.
2. Only new packages are accepted. Removals, upgrades, duplicate/unrecognized
   changes and unrelated pending package configuration are rejected. Requested
   packages and all resolved dependencies are pinned to the previewed versions.
   The parser accepts explicitly recognized C-locale boilerplate/package lists and
   Inst/Conf records only; unknown transaction actions or output abort the preview.
   A new APT output format can therefore disable installation until reviewed.
3. A scrolling plain-text dialog displays the exact packages, full command,
   sources, absence of removals/upgrades, side effects and irreversibility warning.
   No is the default. Authentication is requested only after explicit approval.
   Qt automatic default promotion is disabled on both buttons. No also receives
   initial focus. Tab/focus changes cannot make Yes the default; Enter never
   approves, including when details consume it. Use Space on Yes or click it to
   approve. Escape declines. See [the keyboard audit](ui/CONFIRMATION_REVIEW.md).
4. The existing password prompt and shared worker ownership are reused. The new
   prerequisite executor uses absolute root-owned binaries, argv without a shell,
   a sanitized environment and fixed APT options. User APT_CONFIG/proxy environment
   overrides are not inherited; system APT configuration remains applicable.
5. The approved plan is rebuilt and compared immediately before invoking sudo.
   Changed metadata or a changed transaction rejects execution and requires another
   preview/approval. No automatic retry, upgrade, repair or apt update is performed.
6. After native thread completion, dpkg state and exact versions are checked for
   every resolved package, and executable detection is refreshed. Uncertain
   dependency verification keeps requested capabilities unavailable. Success does
   not start a scan or create an undo entry.

A package-manager success message alone does not enable a feature. Partial/failed
outcomes are shown in the table and Activity. Refresh is the retry path after
reviewing failures; no repeated installation prompt is generated automatically.

## Transaction lifecycle and safety

CommandWorker now delegates privileged package operations (install, removal and
restoration) to the same `run_package_transaction` collector as prerequisites.
Privileged shell recipes also use that policy because they can invoke package
managers. Other command deadlines remain unchanged. The collector drains owned
output, caps retained output at 2 MiB and live progress notifications at 1,024,
and waits for its direct package-manager/wrapper process.
It never calls kill/terminate and has no automatic cancellation or execution deadline
once dispatched. Output-collection failures still wait/drain instead of abandoning
an active package transaction. Live progress uses fixed messages; detailed output
is redacted after completion to avoid leaking credentials split across chunks.
Every collector-recovery iteration sleeps 50 ms, including successful empty reads,
so EOF cannot cause an unbounded tight poll loop while the process is still alive.

Native Qt completion retains worker references. A continuation lease spans preview
confirmation/authentication and subsequent dispatch, including nested dialog event
loops. Closing waits for active work; cancelling shutdown restores normal operation.
Read-only startup detection is also tracked for close safety. Generation and
once-only guards reject stale/duplicate results and stale progress.

Independent Lynis/SMART actions retain their own scan authorization. Their old
inline dependency installers were removed; installation approval no longer chains
into a privileged audit or SMART operation. Scheduler installation does not create
a crontab entry, and sensor installation does not run sensors-detect or change fans.

## Residual risks and limitations

- No real installation or sudo operation was used for validation. APT plan parsing
  is strict LC_ALL=C text parsing; unsupported formats fail closed. Actual resolver
  behaviour and package scripts still require deployment validation in a disposable
  authorized environment before relying on the installer operationally.
- Preview/revalidation is not atomic with an external package manager's later lock
  acquisition. Fingerprints, repeated simulation, version pins and restrictive flags
  reduce races; they do not provide an in-process libapt transaction guarantee.
- A hung package transaction can defer closing indefinitely. The app does not delete
  lock files, forcibly cancel dpkg, retry automatically or claim cancellation worked.
- Package maintainer scripts execute with root privileges and may configure/start
  services, including smartd/cron. Installation is not automatically reversible, and
  package presence does not establish service or hardware readiness.
- Detection has a 12-second local-query budget; individual metadata commands have
  at most 3 seconds. Preview queries have a 15-second budget. APT fingerprints have
  5-second/512-MiB/10,000-file limits and stream file contents; oversized, inaccessible
  or changing state fails closed. OS-level filesystem/process-creation stalls are
  not interruptible guarantees. Read-only subprocess output is checked after capture;
  it is not a hard streaming memory bound like the transaction collector.
- Credential references are released with the completed job's closure, not securely
  erased from Python memory. No password is written to preferences/history/log files.
- Optional ToolCard/guided-fix installers and validated package undo now share the
  no-forced-termination collector. Their existing approvals, package choices and
  undo rules remain separate from the narrower prerequisite installation allowlist.
  Privileged shell recipes have no automatic execution deadline either; they can
  defer closing indefinitely. There is no automatic retry or claim of cancellation.
- UI labels are English, and non-Ubuntu package display mappings remain limited;
  automatic installation is deliberately disabled outside reviewed Ubuntu releases.

## Validation

See [running tests](running_tests.md). `test_prerequisites.py` covers pure discovery,
allowlists, simulation/argument safety, metadata changes, package verification,
redaction and no-kill execution with mocked processes. `ui_prerequisites_probe.py`
uses real Qt threads/dialogs with synthetic metadata and mocked transactions for
selection, approval/cancellation, failure, stale results, shutdown and retry readiness.
No real package changes occur. Visual evidence is saved uniquely under
`screenshots/increment4h/`; temporary preferences and runtime logs stay outside the repo.


Executed validation (2026-11-17): **248 tests passed** in 23.781 seconds
(224 prior tests plus 24 prerequisite tests); corrected Stage 1 captures **MATCH**;
`git diff --check` clean. The final real-desktop fixture exited successfully with
empty stderr and synthetic transactions only. Enterprise/Hybrid screenshots and
validation records are in `screenshots/increment4h/`. Source AST comparison confirms
unchanged command/streaming/HTTP workers, ScanOwnership, WorkerMixin, undo store and
validation, scores/reports, the 4G table/dialog and existing guided/tool installers.
The scheduler's original Tools shortcut now uses the same prerequisite gate as
Assessments, preventing it from bypassing the missing-crontab check.

The preceding 248-test result describes the initial 4H implementation. Consolidated
hardening results and broader deferred risks are recorded in
[the review inventory](consolidated_hardening_review.md); its screenshots are under
`screenshots/increment4h-hardening/`. The older review archive is unchanged and does
not contain the subsequent hardening corrections.


## Final security hardening — 2026-11-21

H03, H05 and H16 corrections are documented in
[the final hardening handover](final_security_hardening.md). Prerequisite previews
use the same trusted invocation builder as execution, including the sudo `--`
separator, clean environment and protected executable paths. Legacy internal
command text is normalized with `shlex.split` into argv once; saved undo strings
remain non-executable and the structured undo validator is unchanged.

Sanitization runs before worker signals, error storage, UI presentation and application
logging. It covers stdin password matches, URL userinfo/query/fragment and named
authentication path segments, common token/secret fields, authentication headers,
private-key blocks and recognized credential prefixes. Unexpected parser/runtime
exceptions report the exception class without interpolating opaque input. Known
parser rejection messages omit the rejected raw line. Useful non-sensitive package
errors remain visible. Privileged streaming uses fixed live messages until the
bounded capture can be sanitized as a whole; Lynis result parsing still uses the
completed capture. General non-privileged streaming deadlines/bounds are unchanged.

Redaction is conservative and not a proof that arbitrary unlabeled secrets can be
identified. Do not paste raw package output into new display/log paths. Exact password
matching is reference cleanup, not memory erasure. Path stat checks are not atomic
execution pinning; protected system paths, root/package trust and local filesystem
semantics remain assumptions. No real package installation or sudo was validated.


## Shared privileged-output confidentiality boundary

The pure `privileged_capture(stdout, stderr, password, complete=...)` policy is now
shared by streaming commands, buffered privileged commands, package transactions,
Timeshift and SMART. It is not a process runner: each caller retains its existing
collection, deadlines, cleanup and ownership implementation.

Only complete, cleaned-up evidence may be released. The policy normalizes controls
and legacy bare colour markers before matching known credentials, sanitizes both
channels together and suppresses reconstructable cross-stream credentials. Both
prepared streams must pass before either reaches signals, Activity or a parser.
Lynis consumes already-normalized evidence and does not strip more markers later.
At stream joins, credential whitespace must be present in the boundary whitespace
run, in order; extra separators may be ignored. This does not strip whitespace
throughout diagnostics or invent a credential's missing spaces/tabs. It can
conservatively suppress unrelated adjacent records matching that boundary shape.
Partial Lynis findings also check the final name and prefixed description against
the attempt's known credential before storing or displaying them. Unsafe derived
findings use a fixed diagnostic and clear retained attempt output; safe partial
findings remain available. Parser exceptions do not interpolate evidence.
Unknown secrets and arbitrary interleavings cannot be guaranteed safe without
broader suppression. The deferred URL-context formatting issue is unchanged.

Package results distinguish `code` (actual process outcome), `capture_complete`
(EOF, no overflow, no collection/cleanup failure) and `diagnostics_allowed`
(confidentiality decision). `output` contains approved text only. A capture failure
clears retained text and uses fixed diagnostics, but still waits/drains and reaps
naturally. No transaction timeout, kill, cancellation or automatic retry is added.
Verification still runs after package completion; discarded diagnostics do not
prove that a package operation failed or that nothing changed.

The bounded regression evidence is in `tests/test_privileged_boundary.py` and
`tests/test_review_hardening.py`. Tests use synthetic credentials, mocks, temporary
state and inert local fixtures; no real installation or privileged execution is
claimed. This update documents this boundary, not a whole-system revalidation.
