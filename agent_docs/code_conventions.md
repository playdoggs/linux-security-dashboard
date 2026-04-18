# Code Conventions
<!-- AGENT: Read before writing any new code or modifying existing patterns. -->

## Style
- PEP 8. Single-file. No external Python deps beyond PyQt6.
- Comments explain WHY, not what. Existing comments stay intact.
- Don't add docstrings/type hints to unchanged code.

## GUI Thread Safety
- **Never touch GUI widgets from a QThread.** Use signals only.
- All `CommandWorker` and `HttpWorker` output → emit signal → main thread handler.
- `finished_ok` is in a `finally:` block — always emits even on exception.

## Styling — THE critical rule
> **Never call `widget.setStyleSheet(f"...{T['X']}...")` on a persistent widget.**

Persistent = any widget that lives beyond a single dialog open/close.

| Instead of | Use |
|------------|-----|
| `w.setStyleSheet(f"background:{T['BG_CARD']}")` | `w.setObjectName("foo")` + rule in `make_style()` |

Dialogs (PreActionDialog, ExplainDialog, etc.) are rebuilt each open — inline styles there are fine.

Exceptions that ARE safe (updated at runtime by their owner methods):
- `RiskScorePanel.update_score()` sets `QProgressBar::chunk` color — called on every score change AND on theme change.
- `FindingsTable._apply_ok_banner_style()` — called by `refresh_theme_styles()` on theme change.

## Theme change sequence
```python
apply_theme(name)           # updates global T dict
app.setPalette(build_palette())
app.setStyleSheet(make_style())
self.risk_panel.update_score()   # refreshes bar chunk colour
# FindingsTable.refresh_theme_styles() called if banner visible
```
Always do all four. `build_palette()` sets Fusion frame/bevel roles — skip it and Light mode gets dark borders.

## Adding a new persistent widget with a custom background
1. `widget.setObjectName("my_widget")`
2. Add to `make_style()`: `QWidget#my_widget { background: {T['BG_CARD']}; ... }`
3. If the widget has dynamic inline color (not in make_style), add a `refresh_theme_styles()` call on it.

## Workers — always use WorkerMixin._start_worker()
```python
w = CommandWorker(cmd, sudo=False, timeout=60)
w.output_ready.connect(self.terminal.append)
w.error_ready.connect(self.terminal.append_err)
w.finished_ok.connect(self._post_scan_check)
self._start_worker(w)    # registers cleanup, calls w.start()
```
Never call `w.start()` directly — `_start_worker` adds `finished→discard` and `finished→deleteLater`.

## sudo
- `check_sudo_cached()` first. If False → `QInputDialog.getText(EchoMode.Password)`.
- Pass bytes: `CommandWorker(cmd, sudo=True, password=pw.encode())`.
- `stdin=DEVNULL` when no password — prevents blocking behind terminal window.

## Scan pattern — individual vs full scan
```python
def _scan_foo(self):          # user-facing button: pre-scan + do
    self._pre_scan(...)
    self._do_scan_foo()

def _do_scan_foo(self):       # work only — no clear, no terminal reset
    self._run_cmd(...)

def _run_full_scan(self):     # one pre-scan, then _do_ variants
    self._pre_scan("Full System Scan", ...)
    self._do_scan_foo()
    QTimer.singleShot(1000, self._do_scan_bar)
```
Never call `_scan_*` from `_run_full_scan` — each would call `_pre_scan` and clear previous results.

## Bulk findings insert
```python
self.findings.begin_bulk_update()
try:
    for item in items:
        self.findings.add_finding(...)
finally:
    self.findings.end_bulk_update()
```
`end_bulk_update` re-enables table updates, sorts, and emits `score_changed` once.

## Input validation
```python
valid_pkg(name)   # always validate before building apt/dnf/pacman commands
```
`PKG_RE = r"^[a-z0-9][a-z0-9.+\-]{0,99}$"` — lowercase only, no leading digit `0-9` (Debian standard).

## Language / L()
```python
L("btn_quick")   # returns translation or falls back to EN silently
```
All user-visible strings use `L()`. Hardcoded English is only for developer-facing terminal messages.

## Config writes — always atomic
```python
tmp = CONFIG_FILE.with_suffix(".tmp")
with open(str(tmp), "w") as f: c.write(f)
tmp.replace(CONFIG_FILE)    # atomic rename — no partial writes
```
