# BUGS

**Function:** Defect tracker — only real, reproducible incorrectness. Preferences and stylistic concerns belong in [CODE_REVIEW.md](CODE_REVIEW.md); resource issues belong in [PERFORMANCE.md](PERFORMANCE.md); attack surfaces belong in [SECURITY.md](SECURITY.md).

Last reviewed: 2026-05-03

---

## Open

### B-001 — README claims 12 languages "including RTL Arabic and Japanese"; the code ships neither

- **Where claimed:** [README.md:38](README.md#L38) — *"12 built in (English, German, French, Spanish, Italian, Portuguese, Dutch, Japanese, Chinese Simplified, Arabic with RTL, and more)"*. Also [README.md:153](README.md#L153) and the `.deb` description in [debian/control](debian/control).
- **What ships:** [linux-security-dashboard.py:445-568](linux-security-dashboard.py#L445-L568). Exactly 12 languages but the set is **EN, DE, ES, FR, PT, IT, NL, PL, RU, SV, TR, ZH** — no Arabic, no Japanese, no RTL handling.
- **Repro:** `python3 linux-security-dashboard.py`, open the Lang dropdown — the items are the keys of `LANGS`.
- **Fix sketch:** Either remove the claim from README and `debian/control`, or add `AR` and `JA` entries to `LANGS` and verify Qt picks RTL layout for the Arabic locale (Qt 6 does this via `QLocale.textDirection()`).

### B-002 — Saved system profile is read but never applied

- **Where:** [linux-security-dashboard.py:6715](linux-security-dashboard.py#L6715) reads `saved_profile = cfg.get("prefs", "profile", fallback=None)` — the variable is then unused. Startup goes straight to `_detect_profile` ([6890-6891](linux-security-dashboard.py#L6890-L6891)) which prompts the user via `ProfileDialog` regardless of what they previously chose.
- **Repro:** Run the wizard, choose "Gaming Rig", tick "Remember this profile" in the post-startup `ProfileDialog`. Restart. The profile dialog appears again with detection results, not the remembered choice.
- **Why it matters:** The `ProfileDialog`'s "Remember this profile" checkbox writes to `~/.audit-dashboard.conf` ([6920-6921](linux-security-dashboard.py#L6920-L6921)) but nothing on the read side honours it.
- **Fix sketch:**
  ```python
  saved_profile = cfg.get("prefs", "profile", fallback=None)
  if saved_profile and saved_profile in PROFILES:
      self.profile_key = saved_profile
      # skip auto-detect; show profile in panel
      QTimer.singleShot(0, lambda: self.risk_panel.set_profile(self.profile_key))
  else:
      QTimer.singleShot(400, self._detect_profile)
  ```
- **Cross-ref:** [ARCHITECTURE.md — open question 2](ARCHITECTURE.md#open-architectural-questions).

### B-003 — `_fix_coredump` produces a non-idempotent system change

- **Where:** [linux-security-dashboard.py:3525](linux-security-dashboard.py#L3525) — `["sh", "-c", "echo fs.suid_dumpable=0 >> /etc/sysctl.conf"]`. The check (`_check_coredump`, [3693-3695](linux-security-dashboard.py#L3693-L3695)) reads the runtime `sysctl` value, so re-applying after a successful run reports "already configured" but still appends another duplicate line if forced.
- **Repro:**
  1. Open the wizard, run "Restrict Core Dumps".
  2. Click the same fix again ("RE-APPLY THIS FIX").
  3. `grep fs.suid_dumpable /etc/sysctl.conf` shows two lines.
  4. Repeat — count grows.
- **Fix sketch:** Mirror the sibling fixes — write to a dedicated drop-in:
  ```python
  ["sh", "-c", "printf 'fs.suid_dumpable=0\\n' > /etc/sysctl.d/99-coredump-hardening.conf"]
  ```
  Followed by `sysctl -p /etc/sysctl.d/99-coredump-hardening.conf` to apply.
- **Cross-ref:** [S-005](SECURITY.md#s-005), [PERFORMANCE.md — Idempotency](PERFORMANCE.md#idempotency).

### B-004 — `apply_theme` mutates the global `T` instead of replacing it

- **Where:** [linux-security-dashboard.py:170-173](linux-security-dashboard.py#L170-L173) — `T.update(THEMES.get(name, THEMES["Dark"]))`. If a future theme dictionary omits a key, the previous theme's value silently leaks through.
- **Repro:** Synthetic — add a theme `"Mini": {"BG_DARK": "#000"}` to `THEMES`. Switch from Dark to Mini. The Mini theme picks up Dark's ACCENT/WARN/etc.
- **Why it matters today:** All shipped themes have all keys, so no live impact. But the contract `apply_theme(name)` should produce a self-consistent palette; the `update`-merge pattern hides typos in future themes.
- **Fix sketch:** `T.clear(); T.update(THEMES.get(name, THEMES["Dark"]))` — or `T = dict(THEMES.get(name, THEMES["Dark"]))` and remove the `global T` mutation pattern entirely.

### B-005 — Synchronous scans bypass the async `_post_scan_check` ordering

- **Where:** `_quick_checks` ([5792-5795](linux-security-dashboard.py#L5792-L5795)), `_scan_temperature` ([5808-5812](linux-security-dashboard.py#L5808-L5812)), and `_scan_drives` ([5814-5818](linux-security-dashboard.py#L5814-L5818)) call their underlying scan **synchronously on the main thread**, then call `_post_scan_check` immediately. Compare with `_run_cmd` ([5464-5477](linux-security-dashboard.py#L5464-L5477)) which connects `_post_scan_check` to `finished_ok`.
- **Why it matters:**
  - The GUI freezes while the synchronous scan runs (visible for `run_quick_checks` and `run_drive_health_check`). See [P-004](PERFORMANCE.md#p-004) and [PERFORMANCE.md — Blocking I/O on the main thread](PERFORMANCE.md#blocking-io-on-the-main-thread-audit) for the full audit.
  - During RUN EVERYTHING the queue's `_re_tick` ([5763-5789](linux-security-dashboard.py#L5763-L5789)) waits 400 ms then 500 ms after `fn()` returns. For sync scans `fn()` blocks, so the wait happens **after** the scan, not during. Net effect is correct but timing is non-obvious.
- **Repro:** Click "Quick Security Checks" with `lynis` recently run (sudo cached). Watch the window stop responding for 300-500 ms.
- **Fix sketch:** Wrap `run_quick_checks`, `run_temperature_check`, and `run_drive_health_check` in `CommandWorker`-style helpers that emit `finished_ok` when done, so the call pattern matches `_run_cmd`. This also unifies the polling logic in `_re_tick`.

### B-006 — `RunEverythingSummaryDialog._open_report` silently overwrites within the same minute

- **Where:** [linux-security-dashboard.py:6360-6383](linux-security-dashboard.py#L6360-L6383). Filename uses `%Y%m%d-%H%M` precision (no seconds). Two RUN EVERYTHING runs within 60 s overwrite the first report without warning.
- **Repro:** Click RUN EVERYTHING twice within the same minute and accept "Open Full Report" both times. Only the second report exists on disk.
- **Why it matters:** Low — most users won't hit this. But the toolbar `_generate_report` ([7022-7064](linux-security-dashboard.py#L7022-L7064)) uses the same minute precision and goes through `QFileDialog` which does prompt; this code path bypasses that.
- **Fix sketch:** Append `-%S` to the timestamp, OR check `Path(path).exists()` and append a numeric suffix.

### B-007 — `LynisPanel._read_lynis_log` sudo-fallback can fail silently if the audit took longer than the sudo timestamp

- **Where:** [linux-security-dashboard.py:3886-3897](linux-security-dashboard.py#L3886-L3897). `sudo -n cat /var/log/lynis.log` only succeeds while the sudo timestamp is fresh. Default `timestamp_timeout` is 5 minutes; Lynis with `--quick` typically finishes in 60-90 s, so usually OK. But on slow systems, or if the user paused the dialog, the cached timestamp may have expired.
- **Repro:** Force-edit `/etc/sudoers.d/zz-test` to `Defaults timestamp_timeout=0` (don't actually do this; mention as a thought experiment). Run Lynis. Direct read of `/var/log/lynis.log` fails with PermissionError; sudo-fallback also fails because no cached timestamp.
- **Result today:** The fallback silently swallows the error and the panel falls through to "live output" parsing ([3958-4012](linux-security-dashboard.py#L3958-L4012)). The user gets a degraded but non-empty result. Not a crash; a silent quality drop.
- **Fix sketch:** When the sudo-fallback fails, surface a single-line message to the user (`self._lappend("⚠ Could not read /var/log/lynis.log even with cached sudo. Showing live output only.")`) instead of falling through silently.

### B-008 — `cmd.split()` in `_act` and `replace("sudo ", "").split()` in `_run_undo`

- **Where:** [linux-security-dashboard.py:2554](linux-security-dashboard.py#L2554), [5115](linux-security-dashboard.py#L5115).
- **Why it's also a bug, not just a security smell:** A future contributor adding a finding with shell-special characters in `cmd_remove` would silently get the wrong argv. Today the inputs are constrained, but the convention exists ([agent_docs/code_conventions.md](agent_docs/code_conventions.md)) precisely to prevent this regression.
- **Cross-ref:** Tracked as [S-001](SECURITY.md#s-001) (action) and [S-002](SECURITY.md#s-002) (undo) — the security framing is the primary one. The functional bug here is "argv mis-parse on shell-special inputs."

### B-009 — `_change_lang` does not update the live UI

- **Where:** [linux-security-dashboard.py:7001-7010](linux-security-dashboard.py#L7001-L7010). Sets the `LANG` global and saves to config; the dialog explicitly tells the user "Restart the app to apply all labels fully." Strictly speaking the message acknowledges this, so it's a documented limitation rather than a defect — but a user expecting WYSIWYG language switching may file it as a bug.
- **Repro:** Switch from EN to DE. Sidebar buttons stay in English until restart.
- **Fix sketch:** Either remove the dropdown and require restart-only via Settings, OR rebuild every panel after the change. Most labels are set at construction with `L(...)` strings, so a true live switch needs a "rebuild UI" path.
- **Status:** Documented behaviour. Listed here so a future contributor doesn't spend time chasing it without understanding the design constraint.

### B-010 — Many language packs are missing keys; English silently fills in

- **Where:** Compare the EN block ([446-490](linux-security-dashboard.py#L446-L490)) with DE ([491-513](linux-security-dashboard.py#L491-L513)). DE lacks `btn_os_installed`, `btn_user_installed`, `btn_temperature`, `btn_drives`. Other languages have similar gaps.
- **Result:** `L(k)` falls back to English ([574](linux-security-dashboard.py#L574)) so users in those languages see mixed-language buttons.
- **Why it matters:** Looks like a translation bug to a native speaker. `L()` doing the fallback is good defence; the data is the problem.
- **Fix sketch:** Add a quick sanity script (or test) that asserts every translation has the same key set as EN. Fill the gaps.

---

## Fixed

### B-011 — Buffered command failures triggered success callbacks — Fixed locally (uncommitted)

`CommandWorker.run` previously emitted `finished_ok` unconditionally. Failed
service actions could clear findings, failed undo could clear its displayed
entry, and the wizard continued dependent commands. It now separates success
from failure, restores failure-path UI state, and preserves unconditional
thread completion for cleanup. Lynis installation and update failures now
notify separate failure callbacks; they clear pending sidebar state without a
healthy-completion banner. Update callback references are cleared on either
outcome. Partial wizard failure refreshes indicators without announcing that
the entire remediation succeeded. Mocked regression tests are in
`tests/test_command_outcomes.py`; actual privileged operations and full GUI
behavior have not been tested. Review scope: this finding only, 2026-11-15.

The list of *prior* fixes documented in [agent_docs/known_bugs.md](agent_docs/known_bugs.md) (SSH regex anchoring, UFW exact-equality match, shlex parsing in the wizard, undo row 4-field key, smartctl `-H` only, drive name regex, Timeshift abort) predates this tracker and is not renumbered into B- IDs.

---

## Won't fix

### W-001 — `has_internet` probes Cloudflare by default

User-configurable internet probe is a future enhancement. Today Cloudflare's `1.1.1.1:443` is the dependable cross-network choice; the privacy concern is logged as [S-004](SECURITY.md#s-004) but not blocking.

### W-002 — Sudo password retained in `bytes` for the worker lifetime

Acceptable for a desktop tool. Logged as [S-003](SECURITY.md#s-003) for visibility, not for action.

### W-003 — Single-file architecture

The constraint is documented in [CLAUDE.md](CLAUDE.md) and [agent_docs/code_conventions.md](agent_docs/code_conventions.md). Splitting is an architecture decision, not a bug fix. Tracked as [R-001](CODE_REVIEW.md#r-001) and [ARCHITECTURE.md — open question 1](ARCHITECTURE.md#open-architectural-questions).

---

## Cross-references

- [SECURITY.md](SECURITY.md) — every finding here that has a security angle has an `S-` ID; consult both.
- [PERFORMANCE.md — Idempotency](PERFORMANCE.md#idempotency) — B-003 is also a perf concern (file growth) and an idempotency gap.
- [CODE_REVIEW.md — R-010](CODE_REVIEW.md#r-010) — B-008 surfaces in the code review pass too.
