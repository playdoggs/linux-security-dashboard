# Final 4H security hardening — review handover (2026-11-21)

## 1. Outcome

**COMPLETE:** targeted H03/H05/H16 implementation and isolated validation.
Independent approval is requested, not claimed. No real installation, sudo,
remediation or host configuration change was performed. Baseline at task admission:
main `f440e85e1b9dde0fbda2cb961db5456ca5998d42` plus existing mixed staged/unstaged
4H work. This batch preserves that work and does not imply approval of every earlier
change. Archive checksum is delivered separately to avoid a self-reference.

## 2. Change inventory

All source references below are to `linux-security-dashboard.py`.

| File | Functions/classes | Change/reason | Impact |
|---|---|---|---|
| linux-security-dashboard.py | sanitize_diagnostic:64, diagnostic_exception:110, DiagnosticFilter:117, init_logging:133 | New redaction/error/log boundaries | H16; unexpected messages/tracebacks are reduced |
| linux-security-dashboard.py | command_argv:667, resolve_privileged_executable:678, privileged_invocation:702, package_transaction:718 | New shared argv/path/environment policy | H05; ignore caller PATH, fail closed on unsafe paths |
| linux-security-dashboard.py | CommandWorker.run:2415, execute_prerequisite_plan:3112, run_package_transaction:3122 | Share retained no-kill collection | H03 for install/remove/restore/configure/shell recipes |
| linux-security-dashboard.py | StreamingCommandWorker:2486, PrerequisiteJob:3095, PrerequisitesPanel:3207 | Sanitize outcomes/setup/display; shared exact preview builder | No raw live privileged output; package/shell streaming refused |
| linux-security-dashboard.py | FindingsTable._act:4516, _verify:4579; ToolCard._run_tool:6673 | Carry parsed argv rather than whitespace splitting | Existing confirmation, verification and undo authority retained |
| linux-security-dashboard.py | check_sudo_cached:1273, create_timeshift_snapshot:1294, run_drive_health_check:5090, GuidedWizard._run_next_fix_cmd:5470, TerminalPanel.append:3552, LynisPanel._lappend:5912 | Related trusted/sanitized boundaries | Deadlines unchanged except package/shell transactions |
| tests/test_privileged_hardening.py | DiagnosticHardening, PrivilegedArguments, TransactionOwnership | New: 26 production-boundary regressions | No real elevation; mocked process/stat data, gated real QThread |
| tests/privileged_test_support.py | install_helpers | New: explicit legacy fixture isolation | Refuses transaction emulation unless subprocess.run is mocked |
| tests/test_command_outcomes.py, tests/test_prerequisites.py, tests/test_structured_undo.py | AST fixtures/assertions | Modified for shared API, protected paths and safe error text | Existing security/lifecycle tests retained |
| tests/test_shutdown_http.py, tests/test_streaming_execution.py, tests/ui_prerequisites_probe.py | Startup assertions, stdin backpressure harness, preview resolver stub | Modified fixture adapters | Real Qt/no-sudo boundaries remain explicit |
| ARCHITECTURE.md, CHANGELOG.md, SECURITY.md, BUGS.md, agent_docs/prerequisites.md, agent_docs/consolidated_hardening_review.md, agent_docs/running_tests.md | Relevant records | Modified; supersede affected historical claims, retain IDs/evidence | No blanket document revalidation claimed |
| agent_docs/final_security_hardening.md | This handover | New | Current scoped evidence and limitations |
| screenshots/final-security-hardening-20261121-081637-0e26acd0/ | Synthetic captures | New: unique desktop evidence | No user preferences/history or sensitive logs |

No file was deleted. Other working-tree changes predate this batch; the archive
contains both the complete implementation patch against HEAD and a source-only
hardening diff against the saved admission snapshot.

## 3. Implementation details

**H03:** CommandWorker previously used subprocess.run(timeout=...) for legacy
privileged package work. Python can kill that direct child on timeout/communication
failure. It now delegates apt/apt-get/dpkg/dpkg-reconfigure/dnf/yum/pacman/rpm and
privileged sh/bash/dash/zsh/ksh recipes to run_package_transaction. Shell recipes
receive the same conservative policy because inspecting shell text cannot reliably
prove that no package manager will run. No shell=True is introduced.

The collector bounds retained output to 2 MiB, emits at most 1,024 fixed progress
messages, and waits for natural direct-child exit. Display/log diagnostics default
to 65,536 characters after redaction (explicit truncation marker); assessment-data
paths retain their existing evidence bounds. On I/O/progress failure it closes
stdin, paces draining/discarding at 50 ms and keeps ownership until exit/reaping.
Collection errors cause failure even if the child later exits zero. No kill,
terminate, forced thread termination, timeout or cancellation occurs in this path.
Other workers retain their deadlines. Streaming refuses package/shell commands
before creating a child, preventing its termination path from touching them.

The prerequisite executor still rebuilds/compares the approved plan first. Legacy
ToolCard installs, guided package steps and structured undo restores automatically
share the collector through CommandWorker. Their separate approvals/package choices
are not converted into prerequisite allowlist authorization.

**H05:** Built-in legacy command text is normalized once with shell-aware parsing;
the worker accepts structured privileged argv only. Undo strings are never parsed
for execution. Protected executable lookup checks original/resolved paths and their
parents using executable_trust; caller PATH is ignored. sudo/env use validated
absolute paths, a sudo -- separator, env -i, fixed system PATH/root HOME/C locale
and noninteractive debconf variables. Cached authentication uses sudo -n/DEVNULL;
explicit passwords use stdin only, with type/length/newline/NUL validation.

**H16:** Complete diagnostics are sanitized before truncation, signals, error
storage, UI insertion and logging. URL userinfo/query/fragment/auth paths, common
secret fields and CLI options, authentication headers/schemes, private-key blocks,
recognized token prefixes and exact stdin password matches are removed. Unknown
APT lines are not copied into exceptions. Unexpected runtime/parser exceptions
retain class/context without opaque payloads. Logging discards raw traceback
payloads; no-active-exception records cannot break the filter. Privileged streaming
shows fixed live progress until its bounded whole capture can be sanitized, avoiding
credential leakage split across chunks. Non-sensitive errors remain available.

Stage 4F guided outcomes still wait for BOTH logical outcome and native Qt finish.
Only startup-error text changed there. AST comparison against the admission snapshot
confirms unchanged undo validator/derivation/store, WorkerMixin, ScanOwnership,
shutdown methods, seven-step orchestration, risk calculations, report generator,
confirmation policy, and theme/style definitions.

## 4. Security assessment

- **Privilege/authorization:** same explicit user approvals and password boundaries;
  no automatic install, scan, retry, hardening or new elevated capability. Legacy
  package actions retain their old scope, not the narrow prerequisite package list.
- **Subprocesses:** structured argv, protected absolute executable lookup and clean
  privileged child environment. Built-in shell recipes remain explicit authorized
  configuration operations. No group/recursive termination or shell=True added.
- **Input/trust:** prerequisite allowlists/version pins/revalidation and Increment 2
  undo schema/allowlists/post-dialog checks are unchanged. Unsafe/missing privileged
  paths fail before process creation. User-controlled PATH is not privileged input.
- **Credentials/output:** passwords remain stdin-only; displayed/stored/logged
  diagnostics are filtered. Python reference cleanup cannot guarantee memory erasure.
  Redaction is conservative and cannot identify every arbitrary unlabeled secret.
- **Filesystem/packages:** stat checks are not atomic executable pinning, package
  signatures, ACL/mount validation or protection from a compromised root. APT plan
  revalidation is not atomic with external package-manager lock acquisition (H13).
  Root maintainer scripts may configure/start services. No real APT/sudo validated.
- **Concurrency/shutdown:** existing token/generation/once guards and native Qt
  ownership remain; no memory-only undo fallback. Hung transactions/shell recipes
  can defer closure indefinitely. External kills/crashes and detached descendants
  are outside this direct-child ownership guarantee; no automatic retry is added.
- **Attack surface:** no new endpoint, server, repository, database or privileged
  command capability. Changed trust policy may refuse nonstandard/user-managed tools.

## 5. UI/UX assessment

No stylesheet/layout/navigation redesign. Approved DESIGN_SYSTEM.md/five references,
Enterprise light content, Hybrid dark navigation, five legacy themes, selected rows,
checked controls and visible focus styling remain unchanged. Preview adds the exact
shared sudo/env invocation; raw privileged streaming progress becomes fixed text.
Unexpected errors expose less detail intentionally. No/Cancel stays default/focused;
Enter never approves (details may consume it); Escape declines. Space on an explicitly focused affirmative button approves,
and Tab never promotes it to default. Profile keyboard traversal remains usable.

Actual desktop fixtures used synthetic data/temp preferences and mocked transactions.
All seven pages/themes, 1100x700/smaller layouts, selected/checked states, larger text,
explanations, safe navigation during a real QThread and normal fixture shutdown passed.
Representative Enterprise/Hybrid prerequisites and confirmation images were inspected.
There is no newly introduced design deviation; existing English/emoji/density and
incomplete accessibility/localization limitations remain. This is not pixel identity
with the dark-content reference images or accessibility certification.

Evidence: screenshots/final-security-hardening-20261121-081637-0e26acd0/.
The final package-classification/logging guard additions followed desktop captures;
presentation definitions are unchanged, and final offscreen real-widget tests cover
final source. Full live installation and arbitrary desktop teardown are unverified.

## 6. Verification evidence

Executed in this batch, not copied from previous results:

```bash
python3 -B -m unittest discover -s tests -p test_privileged_hardening.py -q
python3 -B -m unittest discover -s tests -p 'test_*.py' -q
python3 -B tests/capture_ui_baseline.py --check tests/fixtures/ui_baseline_ui_bl_001
git diff --check
```

Focused: 26 passed. Final full suite: 288 passed in 28.785 s, zero failed/skipped/
errored. Corrected Stage 1 baseline MATCH. Diff check clean. Four selected tests
were run against saved pre-batch production AST nodes: four assertion failures,
zero fixture errors; all four pass on the correction. No source was reverted.
Interim failures (old relative-path/raw-error expectations, an undo-derivation
compatibility mistake, and focused fixture/URL-context checks) were corrected;
final results do not conceal them.

Desktop commands, with QT_QPA_PLATFORMTHEME=generic and --screenshots pointing into
the evidence directory:

```bash
python3 -B tests/ui_navigation_probe.py --screenshots <evidence-directory>
python3 -B tests/ui_prerequisites_probe.py --screenshots <evidence-directory>
python3 -B tests/confirmation_keyboard_probe.py --case <preaction|message|profile> --theme '<Enterprise Workspace|Hybrid Professional>' --screenshots <evidence-directory>
```

Eight desktop processes passed (two workspace/prerequisite fixtures and six
keyboard probes). Two non-fatal Wayland text-input warnings occurred in the
prerequisite fixture. An interim suite run produced two SQLite ResourceWarnings;
they did not recur in the final run, and the store implementation is unchanged.
No claim of a proven leak fix. Final suite output contained no warnings.

Real host read-only stat validation passed for sudo/env/apt/apt-get/systemctl and
/usr/sbin/dpkg-reconfigure. The UID-mapped sandbox correctly rejected non-root-
looking files. Tests use mocked package processes/stat data and a real gated QThread;
streaming/HTTP regressions use isolated unprivileged children/local HTTP. There were
no real installations, privileged commands, external probes or host setting changes.

## 7. Findings and limitations

No remaining blocking defect demonstrated in the targeted batch. Independent
acceptance is still required. The following are not claims of fixes outside scope.

| ID | Severity | Status/trigger and consequence | Correction/decision | Blocking |
|---|---|---|---|---|
| H03 | High | Legacy package timeout path removed, including dpkg-reconfigure | Implemented/tested; review no-kill ownership | No known open blocker |
| H05 / S-001 / B-008 | Medium | Legacy splitting/PATH elevated dispatch replaced | Implemented/tested; argv/path review requested | No known open blocker |
| H16 | Medium | Raw package diagnostics/unknown exception leakage boundaries corrected | Implemented/adversarially tested; residual unlabeled-secret risk | No known open blocker |
| H13 | Medium | External APT changes after revalidation; root maintainer scripts | Accepted TOCTOU/root trust limitation; isolated deployment testing needed | Deferred |
| H04 remainder | Medium | Nonprivileged discovery/execution can still use caller PATH | Privileged paths fixed; broader scan PATH policy separate | Deferred |
| H06 / P-004 | Medium | Synchronous quick/hardware/wizard probes block UI | Existing; move workflows only in separately approved work | Deferred |
| H07 | Medium | CVE schema/service installation-vs-exposure classification | Existing backlog; no correction or new compliance claim | Deferred |
| H08 | Medium | Metadata and ordinary nontransaction CommandWorker buffer output | Package collector bounded; general bounded I/O still separate | Deferred |
| P-002 / P-005 | Medium/Low | Insertion/sorting/score table work scales poorly | Existing concern; no new benchmark or speculative optimization | Deferred |
| H11 | Low | Predictable preferences temp file/multi-instance persistence | Existing; protected config policy separate | Deferred |
| H12 / H14 | Low | Localization/layout/other rich-text and accessibility gaps | Representative fixtures only; broad UI policy separate | Deferred |
| H17 | Low | Historical review docs have obsolete line numbers/status labels | Scoped superseding notes added; no complete doc revalidation | Deferred |
| S-003 / S-004 | Low | Credential lifetime and connectivity-probe privacy | Known limits; no secure-erasure/privacy-policy claim | Deferred |
| B-002 / B-003 / B-006 | Low | Saved profile, repeated coredump edits, report filename collisions | Carried-forward backlog, not revalidated/fixed here | Deferred |
| S-006 / S-007 / S-008 | Low | Loose permission/package probes and cron expansion portability | Carried-forward backlog, not revalidated/fixed here | Deferred |

H01/H02/H09/H10/H15 previous corrections are preserved/retested, not newly
independently approved. Single-file/global/UI-derived result architecture remains
maintenance debt. Indefinite safe waits, root/path races, unexpected secret formats,
external crashes and untested real package recovery are explicit residual risks.

## 8. Git and artifact state

Branch main; existing staged/unstaged/untracked work preserved. Index SHA-256 remains
6fab69274e64009f1cfd91cb184216dcbd0efbc5a18977c3006108a5e821692a.
No stage, commit, push, pull, reset or Git configuration write. Existing staged
source does not include this hardening; committing that older selection alone
would omit fixes. Full relative inventory is in archive evidence/git-state.txt.

Updated archive: increment4h-final-security-hardening-review-20261121.tar.gz (or a
unique suffix if that name already exists). Contains current source/tests/relevant
docs, complete tracked HEAD diff plus untracked implementation/reference files,
source-only batch patch, findings, sanitized test/GUI evidence and SHA-256 manifest.
Generated prior archives, caches, personal data, credentials, runtime logs and Git
internals are excluded. Only selected synthetic screenshots are copied; the rest
remain in the project's evidence directory. Final archive SHA is reported separately.

## 9. Independent review checklist

Verify collector has no signal/timeout paths; all reviewed package/configure/shell
entry points delegate to it; errors never become success; logical outcomes cannot
release native Qt ownership; command resolution ignores caller PATH; undo validates
before claims/worker creation; redaction precedes every relevant signal/display/log;
legacy test adapters are not mistaken for real transaction proof; H15 keyboard policy
remains. Reproduce supplied tests/AST before-after probes and validate manifest/patch.

The archive supplies relevant source for those checks. It cannot establish real
sudoers/PAM, repository resolver races, package scripts/recovery, all distributions,
filesystem/mount guarantees, unlabeled-secret absence, full desktop teardown or
security of a compromised root. Ready for independent review; no independent approval
claimed. Local commit should follow reviewer acceptance and deliberate selection of
current files by the user.

## 10. Final summary

**Done:** Targeted H03/H05/H16 hardening and isolated validation complete. 288 tests passed.
**Next:** Independently review code/evidence, then select current changes in Source Control.
**Goal:** Safer authorized package work without forced termination or credential disclosure.


## Independent-review follow-up — H05-R1 and H16-R1

This section supersedes the affected guarantees/locations in the pre-R1 handover
above. It records only these two corrections, not a new whole-codebase review.

- **H05-R1:** `executable_trust` (`linux-security-dashboard.py:645`) now walks each
  directory and symlink with lstat/readlink instead of validating only original and
  fully resolved paths. Every link owner must be root; directories and executable
  files must be root-owned and not group/other writable. Normal Linux symlink mode
  0777 is not an access-control check: protected containing directories and link
  ownership provide that boundary. Relative/absolute targets, directory links and
  `..` are traversed in order. Broken/unreadable paths, loops and excessive traversal
  fail closed (40 link hops, 4096 component visits). Resolver search directories and
  privilege restrictions are unchanged. Read-only host checks accepted `/bin/sh`,
  Python, the editor alternatives chain, sudo and env; none was executed.
- **H16-R1:** `StreamingCommandWorker.run` (`linux-security-dashboard.py:2641`)
  records whether collection completed. Privileged captures are discarded after
  output/progress caps, timeout, read/setup errors or descriptor-cleanup failure.
  `full_output` remains empty; retained buffers are cleared. Fixed diagnostics
  replace exception payloads, including termination/reaping/descriptor errors that
  could themselves contain cut-off credentials. Complete captures remain sanitized,
  including evidence from a fully collected nonzero exit; that outcome still fails.
  Nonprivileged partial-output handling and terminal-signal contracts are unchanged.
- Regression coverage: `tests/test_review_hardening.py` uses real temporary link
  trees with simulated root ownership and real local pipes with mocked process
  creation. It covers unsafe intermediate ownership/write modes, trusted/relative/
  directory chains, resolution failures, credentials cut inside passwords/URLs,
  timeout/read/start/cleanup/reaping errors and preserved complete evidence.
- Before/after: the same 21 tests against saved pre-R1 production definitions
  produce 16 failing assertions/subtests, zero errors; corrected definitions pass
  all 21. Final full suite: **309 passed in 35.311 seconds**, zero failures/errors/
  skips and no warnings in final output. Commands: `python3 -B -m unittest discover
  -s tests -p test_review_hardening.py -q` and `python3 -B -m unittest discover -s
  tests -p 'test_*.py' -q`. Related prerequisite/privileged/streaming outcome tests
  also passed. `git diff --check` and syntax checks passed.
- H03 package collection, CommandWorker, undo validation/store, worker ownership,
  shutdown and H15 confirmation policy are unchanged (AST comparison plus regression
  suite). No real sudo/APT/installation or host changes. No live desktop GUI audit.
- Limits: pathname checks do not atomically pin executables against concurrent
  privileged filesystem changes. Sanitization of complete output remains heuristic;
  failed/incomplete privileged captures no longer rely on that heuristic. New partial
  observations from discarded captures cannot be recovered; existing findings remain.
  No archive was generated or updated; earlier archives describe pre-R1 snapshots.
