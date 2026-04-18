# Communication Patterns
<!-- AGENT: Understand signal flow before adding scans or workers. -->

## Shell commands → GUI
```
User button click
  → AuditDashboard._scan_foo()
    → _pre_scan()         # clears findings + terminal
    → _do_scan_foo()
      → CommandWorker(cmd) started via _start_worker()
        ↓ (background thread)
        subprocess.run(cmd)
        ↓
        output_ready.emit(stdout)  →  terminal.append(text)
        error_ready.emit(stderr)   →  terminal.append_err(text)
        finished_ok.emit()         →  _post_scan_check()
                                   →  parse callback (via output_ready)
```

## CVE checks → GUI (HTTP)
```
_scan_cve()
  → HttpWorker(targets) started via _start_worker()
    ↓ (background thread)
    urllib.request.urlopen(ubuntu CVE API)  [MAX_ATTEMPTS=2, TIMEOUT=8s, backoff=attempt*1s]
    ↓
    result_ready.emit(pkg, (version, data))  →  _handle_cve_result(pkg, data, scan_id)
    finished_ok.emit()                       →  _finish_cve_scan(scan_id)
```
Stale-scan guard: `_cve_active_scan_id` compared in every handler. `cancel_active_scan()` increments serial and calls `worker.cancel()`.

## Worker lifecycle (WorkerMixin)
```
_start_worker(w):
  w.finished → _workers.discard(w)   # cleanup tracking set
  w.finished → w.deleteLater          # Qt memory cleanup
  _workers.add(w)
  w.start()

_stop_all_workers():                  # call on widget close
  for w in _workers: w.quit(); w.wait(500)
  _workers.clear()
```

## Risk score signal chain
```
FindingsTable.add_finding()
  → RISK.add(risk)
  → score_changed.emit()      ← pyqtSignal on FindingsTable
    → RiskScorePanel.update_score()
      → bar.setValue(score)
      → bar.setStyleSheet(chunk colour)
      → face_lbl.setPixmap(face for score)
```
`score_changed` also emitted by: `_ignore()`, `_remove_finding_and_update_score()`, `clear_findings()`, `end_bulk_update()`.

## Scan action buttons → findings
```
_build_action_cell(name, ftype, risk, detail, cmd_remove, cmd_disable)
  → "?" button  → ExplainDialog(n, ft, r, d).exec()
  → "✕" button  → _ignore(name)
                    → RISK.remove_entry(risk)
                    → table.removeRow(r)
                    → score_changed.emit()
  → REMOVE btn  → _act(cmd_remove, name, "remove", risk)
  → DISABLE btn → _act(cmd_disable, name, "disable", risk)
```
Row metadata stored as `Qt.ItemDataRole.UserRole` dict on col 0: `{name, ftype, risk, detail, cmd_remove, cmd_disable}`. Used by `_sort_by_risk()` to rebuild action cells after sort.

## Full scan coordination
```
_run_full_scan():
  _pre_scan()           # clear once
  _do_scan_unused()     # deborphan — async via CommandWorker
  QTimer.singleShot(1000, _do_scan_network)    # ss -tunlp
  QTimer.singleShot(2000, _do_scan_services)   # pkg_installed() loop
```
Timers prevent simultaneous subprocess launches. Each `_do_scan_*` adds to existing findings (no clear).

## Undo log write path
```
_verify() → success →
  UNDO_LOG.append(entry)         # in-memory list
  save_undo_entry(entry)         # append JSON line to ~/.audit-dashboard-undo.log
  app.undo_panel_ref.add_live_entry(entry)   # live-update UndoPanel if open
```

## Config persistence
```
save_config(section, key, value)  # atomic write via .tmp rename
load_config()                     # returns ConfigParser — read-only snapshot
```
Called from: theme lock, language change, sidebar collapse toggle, profile save.
