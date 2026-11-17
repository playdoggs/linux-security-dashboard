# Known Bugs and Regression Guards

Audit date: **2026-04-23**

## Open
### Separate UI redesign corrective backlog
- UI-BL-002 (CVE provider contract) and UI-BL-003 (client/service classification)
  remain separate prior-live-audit backlog items. Neither was changed by UI-BL-001.
- UI-BL-001 is resolved below; see the [behaviour baseline](ui_behaviour_baseline.md)
  for preserved pre-fix captures and the corrected report baseline.

### Streaming environmental and cleanup limits (Increment 4 Stage 4B)
- Execution uses one monotonic deadline across concurrent stdout/stderr/input
  handling and process wait. Deadline starts before `Popen`; OS process creation
  itself cannot safely be interrupted here. Kernel stalls and scheduler delays
  can exceed wall-clock expectations.
- Cleanup attempts terminate/wait (0.5 s), then kill/wait (0.5 s) for the direct
  child only, with no sudo, process groups or recursive termination. Permission
  failures or uninterruptible processes can leave termination/reaping unconfirmed.
  Closing inherited pipes does not establish descendant termination. Never retry
  automatically after uncertain execution.
- Output limits are 2 MiB combined raw stdout/stderr, 4096 live updates and 16384
  characters per update. Exceeding a byte/update limit fails the assessment with
  `output_limit` and `output_truncated=True`; no success parser runs. Partial
  `full_output` after any failure is diagnostic material, not complete evidence.


### Assessment scope and remaining integration
- Stage 4D reports evidence coverage independently of findings. Coverage describes
  the selected checks at scan time, not ongoing system state or certification.
- CVE requests cover selected apt packages with at most five returned records per
  package; full pages are partial. Version/release applicability and broader
  provider/distribution support are not established by this increment.
- RUN EVERYTHING preserves earlier main findings. They remain observations, not
  proof of current state. CVE/updates still share a detail table, but current scan
  ownership now rejects conflicting starts and retires stale callback generations.
- Quick SSH checks inspect explicit directives in the selected file, not the full
  effective sshd configuration including all defaults/includes. Missing explicit
  directives are unverified, rather than successful coverage.
- Unknown package probes, unsupported/unrecognized command output, missing sensors
  and offline CVE checks never establish successful assessment coverage.

## Regression guards (previously fixed — don't regress)

### Full HTML report renderer (UI-BL-001)
- The missing `_render_finding_rows` helper previously raised NameError in both
  report modes. A five-column renderer now escapes all cell values and selects
  severity colours from a closed palette. It does not select/filter findings.
- Real-generator tests cover Simple/Expert, incomplete coverage, special characters,
  filtering and mode switching. The older coverage test no longer mocks rendering.
- Keep original Stage 1 evidence under `tests/fixtures/ui_baseline`; corrected
  captures under `tests/fixtures/ui_baseline_ui_bl_001` retain identical semantics
  and coverage fragments. No scoring, worker, privilege or undo behaviour changed.


### Quick-check parsing
- SSH explicit values must be unambiguous; a matching secure line cannot override
  a conflicting insecure one. Identical duplicates are allowed; malformed/unknown
  values do not establish coverage or generate a pass. This is not effective sshd
  configuration analysis and does not evaluate all Include/Match semantics.
- SSH checks use anchored regex: `^\s*PermitRootLogin\s+(no|prohibit-password)\b` and `^\s*PasswordAuthentication\s+no\b`.
- UFW / fail2ban use exact equality: `o.strip() == "active"`.
- **Never** reintroduce substring matching (`"active" in o.lower()`, `"no" in o.lower()`).

### Guided Wizard
- Fix commands parsed with `shlex.split()` or stored as pre-split lists. No `cmd.split()`.
- Multi-step fixes run sequentially via `_run_next_fix_cmd()` draining a queue. No `for cmd in ...: worker.start()` loops.

### Structured undo boundary (Increment 2, pending review)
- Never run `cmd`/`undo_cmd` from history. Only validated schema-version-2
  operations can construct sudo worker argv; unknown/legacy rows stay disabled.
- Validate exact package/backend and reviewed service targets; derive display
  warnings from the operation, not saved risk labels. Revalidate after dialogs.
- Existing JSONL is read-only legacy history, never executable or auto-imported.
  Increment 3 stores new records and outcomes in SQLite; failed/pending/completed/
  unknown records never automatically become actionable.
- Regression coverage: `tests/test_structured_undo.py` (mocks/temporary files).

### Durable undo lifecycle (Increment 3)
- Identify records by UUID, never timestamp or command text. Duplicate metadata
  must not update a different record. Retain completed records in audit history.
- Persist a pending claim before worker creation; persist outcomes before UI
  updates. Storage failure must never offer memory-only execution.
- Pending after restart means uncertain; do not auto-retry or reset it to available.
- Use separate success/failure/uncertain outcomes. Bounded pages must replace,
  not append to, the table. Old structured JSONL has no known lifecycle state.
- Regression coverage: `tests/test_undo_persistence_ui.py`.

### Streaming command outcomes (Increment 4 Stage 4A)
- `finished_ok` means exit zero; `failed` means nonzero exit, timeout, missing
  executable or exception. A returning run emits exactly one logical outcome.
- Lynis audit failures skip success parsing, successful audit messages and the
  healthy-completion callback. They show incomplete/unknown status and notify
  `on_failed`. `QThread.finished` remains unconditional lifecycle cleanup.
- Regression coverage: `tests/test_streaming_outcomes.py`; mocked subprocesses
  do not establish real pipe draining, cancellation or timeout bounds; isolated
  pipe/deadline tests are in `tests/test_streaming_execution.py`.

### Other
- Background sudo uses `sudo -S` with `stdin=DEVNULL` fallback.
- `CommandWorker.finished_ok` is success-only; `failed` covers nonzero exit,
  timeout and exceptions. Wizard failures stop the queue and clear credentials;
  failed actions/undo must retain findings/history. Wizard failures refresh
  indicators without announcing completion. Failed Lynis installation/update
  checks use `on_failed`, never the sidebar healthy-completion callback.
  Update checks release both callback references on either outcome; lifecycle
  cleanup uses `QThread.finished`. Covered by `tests/test_command_outcomes.py`.
- HTML reports escape content via `html.escape()`.
- CVE HTTP uses a TLS context + bounded retries.
- `CvePanel` is shared by CVE and updates scans — both entry points clear `cve_table` on start.
- Internet-dependent features gate on `has_internet()`; they advise the user when offline instead of hanging on urllib timeouts.
- **`smartctl` is invoked with `-H` only — never `-t`.** `-t` instructs the drive firmware to run destructive/long self-tests and must never be called without explicit user opt-in.
- Drive names from `lsblk` are validated with `^[a-zA-Z0-9]+$` before being composed into `/dev/<name>` argv — defence in depth even though argv avoids shell interpolation.
- Timeshift snapshot failure ABORTS the pending action. Never swallow the failure and let the destructive command run anyway.

### RUN EVERYTHING sequencing (Increment 4 Stage 4C)
- Preserve the seven non-sudo steps; never silently add Lynis or drive checks.
- Use per-run UUID and expected step index; set waiting before starting a step.
- Advance workers on actual thread completion, not logical success or timers.
- Reject duplicate starts/callbacks and old run IDs. Consume final summary once.
- Missing dependencies, exceptions, cancellation and unknown exits must acknowledge
  terminal outcomes. Restore controls and release panel ownership at finalization.
- CVE bookkeeping must precede worker dispatch. Never convert a start/setup
  exception to immediate completion if a worker has started. Assessment dispatch
  acknowledgements retain errors and wait for actual thread completion, including
  fast exits with queued slots and inline completion during startup.
- Pre-dispatch errors can advance safely; post-dispatch errors remain in the final
  step record. Duplicate/late callbacks cannot consume that step again.
- Regression coverage: `tests/test_assessment_sequence.py` uses production scan
  adapters and controlled signals without launching GUI/commands/network calls.

### Coverage and honest verdicts (Increment 4 Stage 4D)
- Require all seven named steps to succeed; partial/failed/skipped/cancelled/unknown
  must suppress the healthy banner and complete verdicts. Function/thread return
  alone is insufficient. Later successes cannot erase earlier coverage failures.
- Preserve findings when another check fails. Insecure settings can be successfully
  checked; unknown settings cannot pass. Do not encode coverage failures as risk.
- Keep risk mathematics and remediation helpers independent. No compliance claim.
- Keep summary and both report modes aligned; INFO rows are observations, not proof
  of health. Clearing/replacing findings invalidates the coverage snapshot.
- Regression coverage: `tests/test_assessment_coverage.py` plus sequencing tests.

### Temperature diagnostic evidence
- Zero exit does not override explicit sensor errors. Combine stdout, stderr and
  return status: usable readings plus errors are Partial; errors without readings
  are Failed. Preserve genuine hot readings/findings on nonzero or partial output.
- Explicit read-failure wording includes read/reading failed, failed reading,
  cannot read, failed to read, unable to read and read error, regardless of case
  and ordinary whitespace. Do not match "failed" or "warning" alone.
- Harmless warnings are not automatically failures. LC_ALL=C applies to the sensors
  child only. Recognition covers explicit error/fatal markers and sensor access/read
  failures; it is not exhaustive sensor enumeration or proof of healthy hardware.

### Scan ownership and Lynis provenance (Increment 4 Stage 4E)
- Acquire ownership before destructive UI clearing/auth prompts; a rejected request
  must preserve active findings, coverage and worker references. Hold the lease
  until actual Qt completion, not merely finished_ok/failed.
- Check worker+lease identity on every scan result/status callback. Duplicate or
  expired callbacks cannot clear newer evidence, restore banners or release another
  operation's ownership. Preserve Stage 4C run UUID/index/once-only finalization.
- Lynis evidence comes only from current successful captured stdout. Shared logs,
  missing/empty output and unrecognized completion summaries are not success.
- Stage 4F adds tested shutdown guards and HTTP batch deadlines; full GUI/platform
  teardown, real permissions and real-version Lynis compatibility remain unverified.
  No cross-process/system-wide scan lock is claimed.

### Stage 4E startup rollback guards
- All preparation after successful admission must remain inside guaranteed cleanup,
  including coverage/banner initialization. Failed preparation must not strand depth.
- Connect cleanup and register references transactionally before dispatch. Partial
  signal/reference registration must not leave a non-running owner worker.
- Native cleanup is idempotent; disconnected/late callbacks cannot retire a newer
  operation. A start exception alone is not proof that no worker ran.
- Preserve original errors if UI restoration/delete scheduling fails. Never delete
  or release a live/dispatched worker to recover the coordinator.

### Shutdown / HTTP regression guards (Increment 4 Stage 4F)
- Wait for actual Qt completion and the current assessment chain, not only a
  logical command outcome or `isRunning() == False`. Never clear live references.
- Cancel shutdown restores admission without cancelling work. New work stays
  blocked while waiting; current run UUID/continuations remain valid.
- Socket timeout alone cannot bound DNS/headers/trickling response bodies. HTTP
  helpers share a 60-second batch budget and bounded responses; errors/expiry
  cannot count as usable CVE evidence. Only the owned unprivileged helper is killed.
- Full GUI close/cancel/platform teardown, external termination and frozen Python
  packaging are not validated by these tests. Kernel/process creation stalls may
  exceed deadlines; do not claim real-time bounds or confirmed cancellation.

### Guided-fix startup failure regression guards (Stage 4F correction)
- First/later pre-dispatch failure must reset `_fix_running`, clear pending commands
  and temporary password references, restore Run and permit dismissal once no
  workers remain. A status-refresh failure must not strand the core fix state.
- Do not infer pre-dispatch from a startup exception. Running, finished-but-queued
  and uncertain Qt state retain protection until actual completion. No worker is
  killed, discarded or released by guided-fix recovery.
- Defer outcomes during startup; fast success followed by an exception cannot
  advance the chain. Handle each command terminal outcome at most once so old
  callbacks cannot stop or unlock a newer fix. Failed startup is never completion
  success and does not alter existing findings or undo records.

### Guided-fix command/thread completion boundary
- A command outcome is not QThread completion. Ordinary success must not start the
  next fix command until `finished`; failure must not restore controls or clear the
  pending chain/password while its thread remains active.
- Both notifications feed the same once-only guard. Duplicate/stale notifications
  cannot dispatch twice or release another worker. Pre-dispatch startup rollback
  remains immediate; no command, shutdown or HTTP execution semantics change.
