"""Stage 4F: production close/ownership methods, QThreads and local HTTP only."""
import json
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace, MethodType
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QThread, pyqtSignal
from test_command_outcomes import NS, CLASSES, load_definition, method
import test_scan_isolation as isolation
import test_assessment_sequence as sequence

HTTP_NS = dict(QThread=QThread, pyqtSignal=pyqtSignal, socket=socket,
               urllib=urllib, subprocess=subprocess, sys=sys, time=time, json=json)
HttpWorker = load_definition(CLASSES['HttpWorker'], HTTP_NS)


class Timer:
    def __init__(self, parent):
        self.timeout = sequence.Signal()
        self.active = False
    def setInterval(self, value): self.interval = value
    def start(self): self.active = True
    def stop(self): self.active = False


class Shutdown(unittest.TestCase):
    def setUp(self):
        self.case = isolation.ScanIsolation()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.owner = self.case.owner
        self.window = SimpleNamespace(terminal=self.case.terminal,
                                      statusBar=Mock(return_value=Mock()), close=Mock())
        for name in ('closeEvent', '_check_shutdown', '_shutdown_busy'):
            setattr(self.window, name, MethodType(method('AuditDashboard', name), self.window))
        self.dialog = SimpleNamespace(StandardButton=SimpleNamespace(Yes=1, No=2), question=Mock(return_value=1))
        self.patches = patch.dict(NS, QMessageBox=self.dialog, QTimer=Timer)
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def request(self):
        event = Mock()
        self.window.closeEvent(event)
        return event

    def test_idle_close_and_late_callback_rejection(self):
        event = self.request()
        event.accept.assert_called_once()
        self.assertEqual(self.owner.shutdown_state, 'safe_to_close')
        self.assertFalse(self.case.sidebar._scan_network())
        self.assertEqual(sequence.ManualWorker.created, [])

    def test_command_close_waits_for_actual_finished_not_result(self):
        worker = self.case.network()
        token = self.owner.token
        self.request().ignore.assert_called_once()
        worker.output_ready.emit('partial result')
        worker.outcome()
        self.window._check_shutdown()
        self.window.close.assert_not_called()
        self.assertIn(worker, self.owner.workers)
        self.assertEqual(self.owner.token, token)
        self.assertFalse(self.case.sidebar._scan_network())
        self.assertFalse(self.case.sidebar.run_everything())
        worker.end()
        self.window._check_shutdown()
        self.window.close.assert_called_once()
        self.assertEqual(self.owner.shutdown_state, 'safe_to_close')
        before = list(self.case.rows)
        worker.output_ready.emit('stale'); worker.end(); worker.end()
        self.assertEqual(self.case.rows, before)
        self.assertFalse(self.window._shutdown_timer.active)

    def test_shutdown_cancel_restores_admission_without_abandoning_worker(self):
        worker = self.case.network()
        self.request()
        self.dialog.question.return_value = 2
        self.request()
        self.assertEqual(self.owner.shutdown_state, 'running')
        self.assertIn(worker, self.owner.workers)
        self.window._check_shutdown()
        self.assertFalse(self.window._shutdown_timer.active)
        self.window.close.assert_not_called()
        worker.end()
        self.case.network()
        self.assertEqual(len(self.owner.workers), 1)

    def test_repeated_close_reuses_timer_and_reentrant_close_is_ignored(self):
        worker = self.case.network()
        def nested(*args):
            self.request().ignore.assert_called_once()
            return 1
        self.dialog.question.side_effect = nested
        self.request()
        timer = self.window._shutdown_timer
        self.request()
        self.assertIs(self.window._shutdown_timer, timer)
        self.assertEqual(len(timer.timeout.slots), 1)
        self.assertEqual(self.dialog.question.call_count, 2)
        worker.end()
        self.window._check_shutdown()
        self.window._check_shutdown()
        self.window.close.assert_called_once()

    def test_worker_finishes_during_close_question(self):
        worker = self.case.network()
        self.dialog.question.side_effect = lambda *args: (worker.end(), 1)[1]
        self.request()
        self.window.close.assert_called_once()
        self.assertFalse(self.owner.workers)

    def test_seven_step_run_completes_while_shutdown_pending(self):
        self.case.sidebar.run_everything(on_complete=self.case.case.summary)
        self.request()
        for index in (0, 1):
            self.case.case.finish_command(sequence.ManualWorker.created[index])
            self.window._check_shutdown()
            self.window.close.assert_not_called()
        cve = sequence.ManualWorker.created[2]
        self.assertTrue(cve.isRunning())
        self.assertFalse(self.case.panel.scan_cve())
        self.window._check_shutdown()
        self.window.close.assert_not_called()
        self.case.case.finish_cve(cve)
        update = sequence.ManualWorker.created[3]
        self.case.case.finish_command(update)
        self.window._check_shutdown()
        self.assertEqual(len(self.case.sidebar._re_run['outcomes']), 7)
        self.assertFalse(self.case.sidebar._re_run['active'])
        self.window.close.assert_called_once()
        self.case.case.summary.assert_called_once()

    def test_legacy_full_scan_retains_three_steps_during_shutdown(self):
        self.case.sidebar._run_full_scan()
        self.request()
        self.case.case.finish_command(sequence.ManualWorker.created[0])
        self.window._check_shutdown()
        self.window.close.assert_not_called()
        self.case.case.finish_command(sequence.ManualWorker.created[1])
        self.window._check_shutdown()
        self.assertEqual(len(self.case.sidebar._re_run['outcomes']), 3)
        self.window.close.assert_called_once()

    def test_guided_fix_close_and_escape_are_deferred(self):
        wizard = SimpleNamespace(_workers={object()}, _fix_running=True, terminal=Mock())
        event = Mock()
        method('GuidedWizard', 'closeEvent')(wizard, event)
        event.ignore.assert_called_once()
        method('GuidedWizard', 'done')(wizard, 0)
        self.assertEqual(len(wizard._workers), 1)

    def test_real_qthread_remains_owned_until_finished_during_close(self):
        app = QCoreApplication.instance() or QCoreApplication([])
        gate = threading.Event()
        class Thread(QThread):
            output_ready = pyqtSignal(str)
            error_ready = pyqtSignal(str)
            finished_ok = pyqtSignal()
            failed = pyqtSignal()
            def __init__(self, *args, **kwargs): super().__init__()
            def run(self):
                self.output_ready.emit('queued result')
                self.finished_ok.emit()
                gate.wait(2)
        workers = []
        start = self.case.sidebar._start_worker
        self.case.sidebar._start_worker = lambda w: (workers.append(w), start(w))[-1]
        try:
            with patch.dict(NS, CommandWorker=Thread):
                self.case.sidebar._scan_network()
                self.request()
                end = time.monotonic() + 1
                while 'queued result' not in self.case.rows and time.monotonic() < end:
                    app.processEvents(); time.sleep(.001)
                self.assertIn('queued result', self.case.rows)
                self.window._check_shutdown()
                self.window.close.assert_not_called()
                self.assertEqual(self.owner.workers, {workers[0]})
                gate.set()
                self.assertTrue(workers[0].wait(2000))
                app.processEvents()
                self.window._check_shutdown()
                self.window.close.assert_called_once()
        finally:
            gate.set()
            for w in workers:
                try: w.wait(2500)
                except RuntimeError: pass

    def test_http_qthread_close_retains_results_until_actual_completion(self):
        app = QCoreApplication.instance() or QCoreApplication([])
        gate = threading.Event()
        worker = HttpWorker([('example', '1')])
        worker._fetch = lambda *args: (gate.wait(2), {'cves': []})[1]
        results = []
        token = self.owner.enter('CVE request')
        callback = NS['scan_slot'](self.case.panel, worker, lambda *args: results.append(args))
        worker.result_ready.connect(callback)
        method('WorkerMixin', '_start_worker')(self.case.panel, worker)
        self.owner.leave(token)
        try:
            self.request()
            self.window._check_shutdown()
            self.window.close.assert_not_called()
            self.assertIn(worker, self.owner.workers)
            gate.set()
            self.assertTrue(worker.wait(2000))
            app.processEvents()
            self.assertEqual(len(results), 1)
            self.window._check_shutdown()
            self.window.close.assert_called_once()
            callback('example', ('1', {'cves': []}))
            self.assertEqual(len(results), 1)
        finally:
            gate.set()
            try: worker.wait(2500)
            except RuntimeError: pass

    def test_fast_completed_worker_still_waits_for_queued_cleanup(self):
        worker = self.case.network()
        # Native execution has ended, but its finished notification is queued.
        worker.running = False
        worker.ended = True
        self.request()
        self.window._check_shutdown()
        self.window.close.assert_not_called()
        self.assertIn(worker, self.owner.workers)
        worker.end()
        self.window._check_shutdown()
        self.window.close.assert_called_once()

    def test_shutdown_blocks_clear_profile_remediation_without_changing_rows(self):
        self.case.rows.append('preserve finding')
        worker = self.case.network()
        self.case.rows.append('active finding')
        self.request()
        before = list(self.case.rows)
        self.assertFalse(self.case.display.clear_findings())
        self.assertFalse(method('FindingsTable', '_act')(self.case.display, 'unused', 'x', 'remove', 'HIGH'))
        self.assertFalse(method('AuditDashboard', '_detect_profile')(self.window))
        self.assertEqual(self.case.rows, before)
        self.assertEqual(self.owner.workers, {worker})
        worker.end()


class HttpDeadlines(unittest.TestCase):
    def collect(self, worker):
        values, completed = [], []
        worker.result_ready.connect(lambda name, result: values.append((name, result)))
        worker.finished_ok.connect(lambda: completed.append(True))
        worker.run()
        self.assertEqual(completed, [True])
        return values

    def test_connection_timeout_and_expired_budget_produce_error_records(self):
        worker = HttpWorker([('one', '1'), ('two', '2')])
        worker.TOTAL_DEADLINE_SECS = .02
        def stalled(*args):
            time.sleep(.03)
            raise subprocess.TimeoutExpired('HTTP helper', .02)
        with patch.object(worker, '_fetch', side_effect=stalled) as fetch:
            values = self.collect(worker)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([value[1][1]['_error'] for value in values], ['timeout', 'timeout'])

    def test_socket_timeout_retries_and_invalid_json_are_not_success(self):
        worker = HttpWorker([('one', '1')])
        with patch.object(worker, '_fetch', side_effect=socket.timeout('timed out')):
            values = self.collect(worker)
        self.assertEqual(values[0][1][1]['_error'], 'timeout')
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'[]')):
            with self.assertRaises(ValueError): worker._fetch('http://unused', 1)

    def test_deadline_wins_over_late_success(self):
        worker = HttpWorker([('one', '1')]); worker.TOTAL_DEADLINE_SECS = .01
        def late(*args): time.sleep(.02); return {'cves': []}
        with patch.object(worker, '_fetch', side_effect=late): values = self.collect(worker)
        self.assertEqual(values[0][1][1]['_error'], 'timeout')

    def test_http_failure_cannot_complete_seven_step_coverage(self):
        # Real CVE result handler, not the permissive sequencing fixture handler.
        case = isolation.ScanIsolation(); case.setUp()
        try:
            case.panel._handle_cve_result = MethodType(method('CvePanel', '_handle_cve_result'), case.panel)
            case.sidebar.run_everything(on_complete=case.case.summary)
            for index in (0, 1): case.case.finish_command(sequence.ManualWorker.created[index])
            worker = sequence.ManualWorker.created[2]
            worker.result_ready.emit('example', ('1', {'_error':'timeout', '_detail':'total deadline'}))
            worker.outcome(); worker.end()
            case.case.finish_command(sequence.ManualWorker.created[3])
            coverage = case.display._assessment_coverage
            self.assertNotEqual(coverage['outcomes'][5]['outcome'], 'succeeded')
            self.assertFalse(NS['assessment_complete'](coverage))
        finally: case.doCleanups()

    def test_local_stalled_headers_body_trickle_and_response_limit(self):
        stop = threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                try:
                    if self.path == '/headers':
                        stop.wait(2); return
                    self.send_response(200); self.end_headers()
                    if self.path == '/stall':
                        self.wfile.write(b'{'); self.wfile.flush(); stop.wait(2)
                    elif self.path == '/trickle':
                        while not stop.wait(.02):
                            self.wfile.write(b' '); self.wfile.flush()
                    elif self.path == '/large':
                        self.wfile.write(b'x' * 4096)
                    else: self.wfile.write(b'{"cves": []}')
                except (BrokenPipeError, ConnectionResetError): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = False
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        worker = HttpWorker([])
        worker.MAX_RESPONSE_BYTES = 1024
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            self.assertEqual(worker._fetch(base+'/ok', 2), {'cves': []})
            for path in ('/headers', '/stall', '/trickle'):
                with self.subTest(path=path):
                    start = time.monotonic()
                    children = []
                    original = subprocess.Popen
                    def create(*args, **kwargs):
                        child = original(*args, **kwargs); children.append(child); return child
                    with patch.object(subprocess, 'Popen', side_effect=create):
                        with self.assertRaises(subprocess.TimeoutExpired): worker._fetch(base+path, .35)
                    self.assertTrue(children)
                    self.assertTrue(all(child.poll() is not None for child in children))
                    self.assertLess(time.monotonic()-start, 1.5)
            self.assertIn('_error', worker._fetch(base+'/large', 2))
            # A shorter socket timeout is distinct from the total request budget.
            worker.TIMEOUT_SECS = .1
            result = worker._fetch(base+'/stall', 1)
            self.assertEqual(result['_error'], 'timeout')
        finally:
            stop.set(); server.shutdown(); server.server_close(); thread.join(2)


class DialogStub:
    """Only the base close/dismiss contract; no GUI or production probes."""
    def isEnabled(self): return True
    def setEnabled(self, enabled): pass
    def done(self, result): self.dismissed = True
    def closeEvent(self, event): event.accept()


class GuidedFixStartup(unittest.TestCase):
    def setUp(self):
        self.owner = NS['ScanOwnership']()
        self.box = SimpleNamespace(StandardButton=SimpleNamespace(Yes=1, No=2),
                                   question=Mock(return_value=1), information=Mock())
        self.namespace = dict(NS, QDialog=DialogStub, QMessageBox=self.box,
                              prompt_for_sudo_password=Mock(return_value=b'fake-password'))
        mixin = load_definition(CLASSES['WorkerMixin'], self.namespace)
        self.namespace['WorkerMixin'] = mixin
        wizard_type = load_definition(CLASSES['GuidedWizard'], self.namespace)
        self.wizard = wizard_type.__new__(wizard_type)
        w = self.wizard
        w._scan_owner = self.owner
        w.terminal = Mock(_scan_owner=self.owner)
        w._workers = set()
        w._fix_running = False
        w._fix_password = None
        w._pending_fix_cmds = []
        w._selected_fix_idx = 0
        w._cmds = ['fake-first', 'fake-second', 'fake-third']
        w._refresh_fix_statuses = Mock()
        w._show_fix_detail = Mock()
        w.run_btn = Mock()
        w.dismissed = False
        self.findings = ['existing finding']
        self.history = [{'record': 'existing history'}]
        w.findings = self.findings
        w.undo_history = self.history
        self.workers = []
        self.namespace['CommandWorker'] = self.construct
        self.fail_at = None
        self.post_dispatch = False
        self.fast = False

    def construct(self, *args, **kwargs):
        worker = sequence.ManualWorker(*args, **kwargs)
        worker.password = kwargs.get("password")
        self.workers.append(worker)
        start = worker.start
        def dispatch():
            if len(self.workers) == self.fail_at:
                if self.post_dispatch:
                    start()
                    if self.fast:
                        worker.outcome(); worker.end()
                raise RuntimeError('injected guided startup failure')
            start()
        worker.start = dispatch
        return worker

    def assert_idle_failure(self):
        w = self.wizard
        self.assertFalse(w._fix_running)
        self.assertEqual(w._pending_fix_cmds, [])
        self.assertIsNone(w._fix_password)
        self.assertEqual(w._workers, set())
        self.assertEqual(self.owner.workers, set())
        self.assertIsNone(self.owner.token)
        self.assertIsNone(self.workers[-1].password)
        w.run_btn.setEnabled.assert_called_with(True)
        self.box.information.assert_not_called()
        self.assertEqual(self.findings, ['existing finding'])
        self.assertEqual(self.history, [{'record': 'existing history'}])
        w.done(0)
        self.assertTrue(w.dismissed)
        event = Mock(); w.closeEvent(event); event.accept.assert_called_once()
        self.assertTrue(any('injected guided startup failure' in str(call)
                            for call in w.terminal.append_err.call_args_list))

    def test_first_command_pre_dispatch_failure_restores_dismissal(self):
        self.fail_at = 1
        self.wizard._run_fix()
        self.assert_idle_failure()
        self.assertEqual(len(self.workers), 1)
        self.assertFalse(self.workers[0].isRunning())

    def test_subsequent_command_pre_dispatch_failure_restores_dismissal(self):
        self.fail_at = 2
        self.wizard._run_fix()
        self.workers[0].outcome(); self.workers[0].end()
        self.assert_idle_failure()
        self.assertEqual(len(self.workers), 2)
        self.assertFalse(self.workers[1].isRunning())
        self.wizard._refresh_fix_statuses.assert_called_once()

    def test_post_dispatch_exception_waits_for_actual_completion(self):
        self.fail_at = 1
        self.post_dispatch = True
        self.wizard._run_fix()
        worker = self.workers[0]
        self.assertTrue(worker.isRunning())
        self.assertTrue(self.wizard._fix_running)
        self.assertEqual(self.wizard._fix_password, b'fake-password')
        self.assertIn(worker, self.wizard._workers)
        self.assertEqual(worker.password, b'fake-password')
        self.assertEqual(self.owner.workers, {worker})
        event = Mock(); self.wizard.closeEvent(event); event.ignore.assert_called_once()
        self.wizard.done(0); self.assertFalse(self.wizard.dismissed)
        worker.outcome()  # An outcome is not actual Qt completion.
        self.assertEqual(len(self.workers), 1)
        self.assertTrue(self.wizard._fix_running)
        self.assertEqual(self.wizard._fix_password, b'fake-password')
        worker.end()
        self.assert_idle_failure()

    def test_subsequent_post_dispatch_failure_does_not_abandon_worker(self):
        self.fail_at = 2
        self.post_dispatch = True
        self.wizard._run_fix()
        self.workers[0].outcome(); self.workers[0].end()
        active = self.workers[1]
        self.assertEqual(self.owner.workers, {active})
        self.assertTrue(self.wizard._fix_running)
        self.assertEqual(self.wizard._fix_password, b'fake-password')
        active.outcome(); active.end()
        self.assert_idle_failure()

    def test_fast_completion_then_start_exception_is_failure(self):
        self.fail_at = 1
        self.post_dispatch = self.fast = True
        self.wizard._run_fix()
        self.assert_idle_failure()
        self.assertEqual(len(self.workers), 1)

    def test_old_callbacks_cannot_unlock_new_fix_chain(self):
        self.fail_at = 1
        self.wizard._run_fix()
        self.assert_idle_failure()
        old = self.workers[0]
        self.fail_at = None
        self.wizard.dismissed = False
        self.wizard._run_fix()
        token = self.owner.token
        active = self.workers[1]
        for _ in range(2):
            old.outcome(); old.outcome(False); old.end()
        self.assertEqual(self.owner.token, token)
        self.assertEqual(self.owner.workers, {active})
        self.assertTrue(self.wizard._fix_running)
        event = Mock(); self.wizard.closeEvent(event); event.ignore.assert_called_once()
        self.box.information.assert_not_called()

    def test_normal_multi_command_chain_and_duplicate_terminals(self):
        self.wizard._run_fix()
        first = self.workers[0]
        first.outcome()
        self.assertEqual(len(self.workers), 1)
        first.end()
        second = self.workers[1]
        # Contradictory duplicate terminal notification must not stop the next step.
        first.outcome(False); first.outcome(); first.end()
        self.assertTrue(self.wizard._fix_running)
        self.assertEqual(len(self.workers), 2)
        second.outcome(); second.end()
        third = self.workers[2]
        third.outcome(); third.end()
        self.assertFalse(self.wizard._fix_running)
        self.assertIsNone(self.wizard._fix_password)
        self.assertFalse(self.owner.workers)
        self.assertIsNone(self.owner.token)
        self.box.information.assert_called_once()
        self.wizard.done(0); self.assertTrue(self.wizard.dismissed)


    def test_cleanup_connection_failure_restores_dismissal(self):
        construct = self.construct
        def fail_connect(*args, **kwargs):
            worker = construct(*args, **kwargs)
            connect = worker.finished.connect
            calls = [0]
            def connection(slot):
                calls[0] += 1
                if calls[0] == 2:
                    raise RuntimeError('injected guided startup failure')
                connect(slot)
            worker.finished.connect = connection
            return worker
        self.namespace['CommandWorker'] = fail_connect
        self.wizard._run_fix()
        self.assert_idle_failure()

    def test_refresh_error_does_not_mask_startup_error_or_strand_state(self):
        self.fail_at = 1
        self.wizard._refresh_fix_statuses.side_effect = ValueError('status unavailable')
        self.wizard._run_fix()
        self.assert_idle_failure()

    def test_real_qthread_post_dispatch_exception_keeps_close_protection(self):
        app = QCoreApplication.instance() or QCoreApplication([])
        gate = threading.Event()
        workers = self.workers
        class Thread(QThread):
            output_ready = pyqtSignal(str)
            error_ready = pyqtSignal(str)
            finished_ok = pyqtSignal()
            failed = pyqtSignal()
            def __init__(self, *args, **kwargs):
                super().__init__()
                self.password = kwargs['password']
                workers.append(self)
            def start(self):
                super().start()
                raise RuntimeError('injected guided startup failure')
            def run(self):
                self.finished_ok.emit()
                gate.wait(2)
        self.namespace['CommandWorker'] = Thread
        try:
            self.wizard._run_fix()
            app.processEvents()
            self.assertTrue(self.wizard._fix_running)
            self.assertEqual(self.owner.workers, {workers[0]})
            self.assertEqual(workers[0].password, b'fake-password')
            event = Mock(); self.wizard.closeEvent(event); event.ignore.assert_called_once()
            self.wizard.done(0); self.assertFalse(self.wizard.dismissed)
            self.box.information.assert_not_called()
            gate.set()
            self.assertTrue(workers[0].wait(2000))
            app.processEvents()
            self.assert_idle_failure()
            self.assertEqual(len(workers), 1)
        finally:
            gate.set()
            for worker in workers:
                try: worker.wait(2500)
                except RuntimeError: pass


    def test_success_outcome_waits_for_thread_completion_and_advances_once(self):
        self.wizard._run_fix()
        first = self.workers[0]
        first.outcome(); first.outcome()
        self.assertEqual(len(self.workers), 1)
        self.assertTrue(self.wizard._fix_running)
        self.assertEqual(self.owner.workers, {first})
        self.wizard.run_btn.setEnabled.assert_called_once_with(False)
        event = Mock(); self.wizard.closeEvent(event); event.ignore.assert_called_once()
        first.end()
        self.assertEqual(len(self.workers), 2)
        second = self.workers[1]
        token = self.owner.token
        first.end(); first.outcome(); first.outcome(False)
        self.assertEqual(len(self.workers), 2)
        self.assertEqual(self.owner.token, token)
        self.assertEqual(self.owner.workers, {second})
        second.outcome(); second.end()
        third = self.workers[2]
        third.outcome(); third.end()
        self.box.information.assert_called_once()
        self.assertFalse(self.wizard._workers)
        self.wizard.done(0); self.assertTrue(self.wizard.dismissed)

    def test_failure_outcome_retains_controls_and_protection_until_finished(self):
        self.wizard._run_fix()
        worker = self.workers[0]
        worker.outcome(False); worker.outcome(False)
        self.assertTrue(self.wizard._fix_running)
        self.assertEqual(self.wizard._fix_password, b'fake-password')
        self.assertEqual(self.owner.workers, {worker})
        self.wizard.run_btn.setEnabled.assert_called_once_with(False)
        self.wizard._refresh_fix_statuses.assert_not_called()
        event = Mock(); self.wizard.closeEvent(event); event.ignore.assert_called_once()
        worker.end(); worker.end(); worker.outcome()
        self.assertFalse(self.wizard._fix_running)
        self.assertEqual(self.wizard._pending_fix_cmds, [])
        self.assertIsNone(self.wizard._fix_password)
        self.wizard.run_btn.setEnabled.assert_called_with(True)
        self.wizard._refresh_fix_statuses.assert_called_once()
        self.assertEqual(len(self.workers), 1)
        self.assertFalse(self.owner.workers)
        self.assertIsNone(self.owner.token)
        self.box.information.assert_not_called()
        self.wizard.done(0); self.assertTrue(self.wizard.dismissed)

    def test_real_qthread_terminal_signals_do_not_advance_before_finished(self):
        app = QCoreApplication.instance() or QCoreApplication([])
        for success in (True, False):
            with self.subTest(success=success):
                self.setUp()
                self.wizard._cmds = ['fake-first', 'fake-second']
                gate = threading.Event()
                workers, observed = self.workers, []
                class Thread(QThread):
                    output_ready = pyqtSignal(str)
                    error_ready = pyqtSignal(str)
                    finished_ok = pyqtSignal()
                    failed = pyqtSignal()
                    def __init__(self, *args, **kwargs):
                        super().__init__()
                        self.password = kwargs['password']
                        workers.append(self)
                        signal = self.finished_ok if success else self.failed
                        signal.connect(lambda: observed.append(True))
                    def run(self):
                        (self.finished_ok if success else self.failed).emit()
                        gate.wait(3)
                self.namespace['CommandWorker'] = Thread
                try:
                    self.wizard._run_fix()
                    deadline = time.monotonic() + 2
                    while not observed and time.monotonic() < deadline:
                        app.processEvents(); time.sleep(.001)
                    app.processEvents()
                    self.assertTrue(observed)
                    self.assertEqual(len(workers), 1)
                    self.assertTrue(workers[0].isRunning())
                    self.assertEqual(self.owner.workers, {workers[0]})
                    self.assertTrue(self.wizard._fix_running)
                    self.wizard.run_btn.setEnabled.assert_called_once_with(False)
                    event = Mock(); self.wizard.closeEvent(event); event.ignore.assert_called_once()
                    gate.set()
                    self.assertTrue(workers[0].wait(2000))
                    deadline = time.monotonic() + 2
                    while self.owner.workers and time.monotonic() < deadline:
                        app.processEvents(); time.sleep(.001)
                    self.assertFalse(self.owner.workers)
                    self.assertFalse(self.wizard._fix_running)
                    self.assertEqual(len(workers), 2 if success else 1)
                    self.assertEqual(self.box.information.call_count, 1 if success else 0)
                    self.wizard.done(0); self.assertTrue(self.wizard.dismissed)
                finally:
                    gate.set()
                    for worker in workers:
                        try: worker.wait(3500)
                        except RuntimeError: pass
                    app.processEvents()
