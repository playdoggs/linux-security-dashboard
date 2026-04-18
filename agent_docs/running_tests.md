# Running Tests
<!-- AGENT: No automated test suite. Use this checklist after any change. -->
<!-- Only check items relevant to what you changed. -->

## Quick sanity check (run first, always)
```bash
python3 -c "
import ast, sys
with open('linux-audit-dashboard-v4.2.py') as f: src = f.read()
ast.parse(src)
print('syntax ok —', src.count('\n'), 'lines')
"
```

## Launch check
```bash
python3 linux-audit-dashboard-v4.2.py
```
Watch for: ImportError, AttributeError at startup, blank window, missing widgets.

---

## Checklist by area — only run what you touched

### Findings table
- [ ] Add a finding → appears in table with correct risk badge colour
- [ ] Sort: HIGH rows at top, then MEDIUM, LOW, INFO
- [ ] Sort: REMOVE/DISABLE buttons on sorted rows target the correct item (not the pre-sort item)
- [ ] Ignore (✕): row removed, risk score decreases, item skipped on next scan
- [ ] Double-click row: ExplainDialog opens with correct name/risk/detail
- [ ] Search box: filters rows live; clear search restores all
- [ ] Clear button: table empty, score 0, "all looks well" banner hidden

### Risk score
- [ ] Score increments when finding added (HIGH=20, MEDIUM=8, LOW=3, INFO=0)
- [ ] Score decrements when finding removed/ignored/fixed
- [ ] Face image updates at score thresholds
- [ ] "All looks well" banner appears only when zero HIGH/MEDIUM findings

### Scans
- [ ] Unused software scan: orphans appear as LEFTOVER findings
- [ ] Network scan: open ports appear; RISKY ports get correct risk level
- [ ] Services scan: known risky services flagged; clean services show INFO
- [ ] Quick checks: 8 checks run; pass=INFO, fail=MEDIUM; fix text shown
- [ ] Full scan: all three scans run AND findings from all three are visible (no clear between)
- [ ] CVE check: packages queried; results appear in CVE tab
- [ ] Upgrades check: outdated packages listed as OUTDATED/LOW

### Sudo / actions
- [ ] REMOVE: PreActionDialog shown before command runs
- [ ] REMOVE: on success, row removed and score drops
- [ ] REMOVE: undo log entry written to `~/.audit-dashboard-undo.log`
- [ ] No sudo cached: QInputDialog password prompt appears (not terminal prompt)
- [ ] Cancel password dialog: nothing happens, no command runs

### Theme
- [ ] Switch theme: toolbar, sidebar, risk bar, table, terminal ALL update
- [ ] Switch theme: section header buttons update colour (not stuck on startup theme)
- [ ] Switch theme: risk bar chunk colour updates
- [ ] "All looks well" banner (if visible) updates colour on theme switch
- [ ] Lock theme: relaunching the app uses the locked theme

### Workers / threading
- [ ] Scan that times out: error shown in terminal, UI not permanently stuck on "please wait"
- [ ] Start scan while another is running: no crash, no duplicate findings (dedup prevents it)
- [ ] Close window during scan: no crash (WorkerMixin._stop_all_workers)

### Language
- [ ] Switch language: sidebar buttons, tab labels, section titles update
- [ ] Missing key: app does not crash (L() falls back to EN)

### Undo panel
- [ ] After remove action: entry appears live in Undo panel
- [ ] Relaunch: previous session undo entries loaded from file
- [ ] Empty state: "No actions taken yet" label visible when no entries

---

## Known-good state (v4.2 as committed)
All items below were confirmed fixed and should not regress:
- ✅ sudo does not block behind terminal window (uses DEVNULL / sudo -S)
- ✅ apt list --upgradable does not hang (DEBIAN_FRONTEND=noninteractive)
- ✅ `_sort_by_risk` rebuilds action cells — buttons target correct items after sort
- ✅ `_ignore()` decrements risk score
- ✅ Full scan does not clear previous sub-scan results (_do_scan_* pattern)
- ✅ `CommandWorker.finished_ok` emitted in `finally:` — UI never stuck on timeout
- ✅ SSH PasswordAuthentication check uses regex for explicit "no" (no false-pass)
- ✅ Fail2ban check uses `systemctl is-active` (not just `which`)
- ✅ `check_update_age` tries `/var/lib/apt/periodic/update-success-stamp` first
- ✅ `build_palette()` sets all Fusion frame/bevel roles — Light mode has no dark borders
- ✅ Theme change updates all persistent widgets via objectName + make_style()
- ✅ Profile re-detected at every startup (not silently reused from config)
