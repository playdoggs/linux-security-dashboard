# Known Bugs — Root Causes & Fixes
<!-- AGENT: Read before touching sudo handling, theme system, or scan flow. -->
<!-- These are non-obvious. The fixes are already in the code — don't revert them. -->

---

## ✅ FIXED: sudo blocks silently on background terminal

### Symptom
User clicks Remove/Disable. Nothing happens. Terminal behind the GUI shows `[sudo] password for user:`.

### Root cause
`subprocess.run(capture_output=True)` does not set stdin. The child inherits the parent's stdin fd — the terminal. sudo reads from there and blocks.

### Fix (in CommandWorker.run)
```python
if self.sudo and self.password:
    full = ["sudo", "-S"] + self.cmd
    p = subprocess.run(full, input=self.password + b"\n", capture_output=True, ...)
else:
    full = (["sudo"] + self.cmd) if self.sudo else self.cmd
    p = subprocess.run(full, stdin=subprocess.DEVNULL, capture_output=True, ...)
```
When no password: `stdin=DEVNULL` → sudo gets EOF → fails fast with clean error message.
When password: `sudo -S` reads from stdin line 1 → no TTY required.

### Password collection
`_act()` calls `check_sudo_cached()`. If False: `QInputDialog.getText(EchoMode.Password)` → `.encode()` → passed as `CommandWorker(password=bytes)`. Cancel → `_act()` returns early, nothing runs.

---

## ✅ FIXED: Theme change leaves areas stuck on startup colours

### Root cause (three separate problems)

**A — bare setStyleSheet cascades over global stylesheet**
`widget.setStyleSheet("background: X")` (no selector) applies to widget AND all descendants with higher specificity than `app.setStyleSheet()`. Any bare call in `_change_theme()` wins over `make_style()` rules.
Fix: remove bare calls from `_change_theme()`. Use objectName + `make_style()` CSS rule.

**B — persistent widgets built at startup bake in startup-theme T[] values**
Inline `setStyleSheet(f"background:{T['BG_CARD']}")` in `__init__` freezes colour at construction time.
Fix: `setObjectName("foo")` + add `QWidget#foo { background: {T['BG_CARD']}; }` to `make_style()`.

Widgets and their objectNames:
| Widget | objectName |
|--------|-----------|
| SideBar | `sidebar_widget` |
| TerminalPanel header | `terminal_hdr` |
| FindingsTable header | `findings_hdr` |
| ToolCard frame | `tool_card` |
| Toolbar bar | `toolbar_bar` |
| Risk panel bar | `risk_panel_bar` |
| Sidebar info box | `sidebar_info_box` |
| Section header btn | `section_btn` |
| Section sub-label | `section_sub` |

**C — risk bar chunk colour not refreshed on theme change**
`QProgressBar::chunk { background: colour }` set in `update_score()` — only fires on score changes.
Fix: `_change_theme()` calls `self.risk_panel.update_score()`.

### Rule
> Never call `widget.setStyleSheet(f"...{T['X']}...")` on a persistent widget.
> Dialogs (PreActionDialog, ExplainDialog, etc.) are rebuilt on each open — inline styles there are fine.

### Remaining inline styles (low risk — text colour only, no background)
- Info QLabels in CvePanel, LynisPanel, GuidedWizard, UndoPanel: `color:{T['TEXT_DIM']}` frozen at startup. Looks acceptable in all themes.
- `_ok_banner`: refreshed by `_apply_ok_banner_style()` called from `refresh_theme_styles()` → `_change_theme()`.
- ToolCard category badges (Security=DANGER, Monitoring=ACCENT): frozen at startup. Fix if user reports colour issues: add `refresh_theme()` to ToolCard.

---

## ✅ FIXED: Full scan clears results from previous sub-scans

### Symptom
"Run Full Scan" shows only service findings. Orphan and network results disappear.

### Root cause
Each `_scan_foo()` button method calls `_pre_scan()` which calls `clear_findings()`. `_run_full_scan()` calling `_scan_unused()`, `_scan_network()`, `_scan_services()` would clear findings 3 times.

### Fix: _do_scan_* pattern
```python
def _scan_foo(self):      # button handler — pre-scan + work
    self._pre_scan(...)
    self._do_scan_foo()

def _do_scan_foo(self):   # work only — no clear
    self._run_cmd(...)

def _run_full_scan(self): # one pre-scan, then _do_ variants
    self._pre_scan("Full System Scan", ...)
    self._do_scan_unused()
    QTimer.singleShot(1000, self._do_scan_network)
    QTimer.singleShot(2000, self._do_scan_services)
```

---

## ✅ FIXED: apt list --upgradable hangs / returns 0 results

### Root causes
1. **Filter bug**: old `"upgradable" not in l` excluded every result (apt includes "upgradable from:" in every line). Fix: `not l.startswith("Listing")`.
2. **Hang**: apt without a TTY + without `DEBIAN_FRONTEND=noninteractive` may wait for input. Fix: `env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}` in CommandWorker.

---

## ✅ FIXED: _sort_by_risk misaligns action buttons after sort

### Root cause
Old sort rewrote text cells 0–4 but left `setCellWidget` column 5 untouched. Button at row 0 remained bound to the item originally at row 0, not the HIGH-risk item now showing there.

### Fix
Store `{name, ftype, risk, detail, cmd_remove, cmd_disable}` as `UserRole` data on col 0 at insert time. In `_sort_by_risk()`: capture `action_data` per row, sort, then call `_build_action_cell()` and `setCellWidget` for every row in sorted order.

---

## ✅ FIXED: GuidedWizard check functions return wrong state

### Symptom
Wizard list recommends enabling UFW even when firewall is already active.

### Root cause
Three fragile matchers in `_check_*`:
1. `"active" in o.lower()` — `"active"` is a substring of `"inactive"`, so the test returns True for both states (false positive, not the reported symptom but latent).
2. `_check_ssh` root check used `"no" in o.lower()` against full grep output — matches any line containing "no", including commented examples.
3. Commented-out config lines were treated the same as effective settings.

### Fix (GuidedWizard._check_ufw, _check_fail2ban, _check_ssh)
- systemd active-state: compare `o.strip() == "active"` against the exact output of `systemctl is-active`.
- sshd_config: anchored regex `^\s*PermitRootLogin\s+(no|prohibit-password)\b` with `(?im)` flags so comments (`^#`) don't match and the directive must appear at line start.

### Rule
> Never test systemd status with substring matches — `"active" in "inactive"` is True.
> Always anchor config-file regexes to line start with `(?m)^\s*<directive>\s+<value>\b`.

---

## ✅ FIXED: _ignore() did not update risk score

### Root cause
`_ignore()` removed the table row but never called `RISK.remove_entry()` or emitted `score_changed`.

### Fix
```python
data = item.data(Qt.ItemDataRole.UserRole)
row_risk = data.get("risk") if isinstance(data, dict) else data
if row_risk in ("HIGH", "MEDIUM", "LOW", "INFO"):
    RISK.remove_entry(row_risk)
self.table.removeRow(r)
# ...
self.score_changed.emit()
```
