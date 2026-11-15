"""Production orchestration/callback methods, controlled worker signals; no commands."""
from types import SimpleNamespace, MethodType
import unittest
from unittest.mock import Mock, patch
import uuid
import os

from test_command_outcomes import NS, method


class Signal:
    def __init__(self):
        self.slots = []

    def connect(self, slot):
        self.slots.append(slot)

    def disconnect(self, slot):
        self.slots.remove(slot)

    def emit(self, *args):
        for slot in list(self.slots):
            slot(*args)


class ManualWorker:
    created = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.ended = False
        for name in ('finished_ok', 'failed', 'finished', 'output_ready', 'error_ready', 'result_ready'):
            setattr(self, name, Signal())
        self.created.append(self)

    def start(self):
        self.running = True

    def deleteLater(self):
        pass

    def isRunning(self):
        return self.running

    def isFinished(self):
        return self.ended

    def cancel(self):
        self.cancelled = True

    def outcome(self, success=True):
        (self.finished_ok if success else self.failed).emit()

    def end(self):
        self.running = False
        self.ended = True
        self.finished.emit()


class AssessmentSequence(unittest.TestCase):
    def setUp(self):
        ManualWorker.created = []
        self.summary = Mock()
        self.quick, self.temps = Mock(return_value={'outcome':'succeeded'}), Mock(return_value={'outcome':'succeeded'})
        self.sidebar = SimpleNamespace(terminal=Mock(), findings=Mock(), stack=Mock(),
                                       _workers=set(), _any_running=False,
                                       lynis_panel=SimpleNamespace(_any_running=False),
                                       isEnabled=Mock(return_value=True), setEnabled=Mock(),
                                       _pending_section_action=None, _post_scan_check=Mock(),
                                       _scan_failed=Mock(), _parse_unused=Mock(return_value='succeeded'), _parse_network=Mock(return_value='succeeded'))
        self.panel = SimpleNamespace(terminal=self.sidebar.terminal, findings=self.sidebar.findings,
                                     cve_table=Mock(), status=Mock(), _workers=set(), _any_running=False,
                                     isEnabled=Mock(return_value=True), setEnabled=Mock(),
                                     _get_installed_version=Mock(return_value='1'), HIGH_VALUE_PKGS=['example'],
                                     _cve_scan_serial=0, _cve_active_scan_id=0,
                                     _scan_cve_done_cb=None, _scan_upgrades_done_cb=None,
                                     _scan_upgrades_failed_cb=None, _parse_upgrades=Mock(return_value='succeeded'))
        self.sidebar.cve_panel = self.panel
        for name in ('run_everything', '_re_advance', '_re_step_done', '_re_finalize',
                     '_run_cmd', '_do_scan_unused', '_do_scan_network', '_do_scan_services'):
            setattr(self.sidebar, name, MethodType(method('SideBar', name), self.sidebar))
        for name in ('scan_cve', 'scan_upgrades', '_finish_cve_scan', '_finish_upgrades_scan', 'cancel_active_scan'):
            setattr(self.panel, name, MethodType(method('CvePanel', name), self.panel))
        guard = method('WorkerMixin', '_start_assessment_worker')
        self.sidebar._start_assessment_worker = MethodType(guard, self.sidebar)
        self.panel._start_assessment_worker = MethodType(guard, self.panel)
        start = method('WorkerMixin', '_start_worker')
        self.sidebar._start_worker = lambda worker: start(self.sidebar, worker)
        self.panel._start_worker = lambda worker: start(self.panel, worker)
        def result(pkg, data, scan_id):
            if scan_id == self.panel._cve_active_scan_id:
                self.panel._cve_ok += 1
                self.panel._cve_done += 1
        self.panel._handle_cve_result = Mock(side_effect=result)
        patcher = patch.dict(NS, uuid=uuid, os=os, CommandWorker=ManualWorker,
                             HttpWorker=ManualWorker, has_internet=lambda: True,
                             shutil=SimpleNamespace(which=lambda name: '/fake/'+name),
                             run_quick_checks=self.quick, run_temperature_check=self.temps,
                             probe_package=lambda name: (True, '1') if name == 'example' else (False, None),
                             pkg_installed=lambda name: False, L=lambda key: key, SESSION=Mock())
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self):
        self.sidebar.run_everything(on_complete=self.summary)
        return self.sidebar._re_run

    def finish_command(self, worker, success=True):
        if success and worker.args[0] in (['ss', '-tunlp'], ['apt', 'list', '--upgradable']):
            worker.output_ready.emit('recognized fixture output')
        worker.outcome(success)
        worker.end()

    def reach_cve(self):
        run = self.start()
        self.finish_command(ManualWorker.created[0])
        self.finish_command(ManualWorker.created[1])
        self.assertEqual(run['waiting'], 5)
        return run, ManualWorker.created[2]

    def finish_cve(self, worker, success=True):
        if success:
            worker.result_ready.emit('example', ('1', {'cves': []}))
        worker.outcome()
        worker.end()

    def finish_run(self):
        run, cve = self.reach_cve()
        self.finish_cve(cve)
        self.finish_command(ManualWorker.created[3])
        return run

    def test_all_seven_order_and_delayed_cve_update_threads(self):
        run = self.start()
        self.assertEqual(ManualWorker.created[0].args[0], ['deborphan'])
        self.finish_command(ManualWorker.created[0])
        self.assertEqual(ManualWorker.created[1].args[0], ['ss', '-tunlp'])
        self.finish_command(ManualWorker.created[1])
        self.quick.assert_called_once()
        self.temps.assert_called_once()
        cve = ManualWorker.created[2]
        self.assertEqual(run['waiting'], 5)
        cve.result_ready.emit('example', ('1', {'cves': []}))
        cve.outcome()
        self.assertEqual(len(ManualWorker.created), 3)  # Logical success is not thread completion.
        self.summary.assert_not_called()
        cve.end()
        update = ManualWorker.created[3]
        self.assertEqual(update.args[0], ['apt', 'list', '--upgradable'])
        update.outcome()
        self.sidebar._re_finalize(run['id'])
        self.assertEqual(run['waiting'], 6)
        self.summary.assert_not_called()
        update.end()
        self.summary.assert_called_once_with()
        self.assertEqual([r['name'] for r in run['outcomes']], [
            'Unused software', 'Open network ports', 'Risky services', 'Quick security checks',
            'Hardware temperatures', 'CVE vulnerabilities', 'Available updates'])
        self.assertFalse(run['active'])
        self.sidebar.findings.clear_findings.assert_not_called()
        self.sidebar.terminal.output.clear.assert_not_called()
        self.sidebar.setEnabled.assert_called_with(True)
        self.assertIsNone(self.panel._assessment_owner)

    def test_duplicate_and_stale_callbacks_cannot_advance_or_finalize(self):
        run = self.finish_run()
        old_id = run['id']
        for _ in range(2):
            self.sidebar._re_step_done(old_id, 6, 'succeeded')
            self.sidebar._re_finalize(old_id)
            ManualWorker.created[-1].end()
        self.summary.assert_called_once_with()
        self.sidebar.run_everything(on_complete=self.summary)
        current = self.sidebar._re_run
        self.assertNotEqual(old_id, current['id'])
        self.sidebar._re_step_done(old_id, 0, 'failed')
        self.assertEqual(current['outcomes'], [])
        self.assertEqual(current['waiting'], 0)

    def test_repeated_click_keeps_same_run_and_callback(self):
        run = self.start()
        other = Mock()
        self.sidebar.run_everything(on_complete=other)
        self.assertIs(self.sidebar._re_run, run)
        self.assertEqual(len(ManualWorker.created), 1)
        self.assertIs(run['on_complete'], self.summary)
        other.assert_not_called()

    def test_synchronous_duplicate_callbacks_advance_once_without_recursion(self):
        def synchronous(on_terminal):
            on_terminal('succeeded')
            on_terminal('failed')
        for name in ('_do_scan_unused', '_do_scan_network', '_do_scan_services'):
            setattr(self.sidebar, name, synchronous)
        self.panel.scan_cve = synchronous_with_id = lambda on_terminal, assessment_id: synchronous(on_terminal)
        self.panel.scan_upgrades = synchronous_with_id
        run = self.start()
        self.assertEqual(len(run['outcomes']), 7)
        self.summary.assert_called_once_with()
        self.assertEqual(ManualWorker.created, [])

    def test_failed_skipped_and_exception_steps_all_finish(self):
        def failure(on_terminal):
            raise RuntimeError('step failed')
        self.sidebar._do_scan_unused = lambda on_terminal: on_terminal('skipped')
        self.sidebar._do_scan_network = failure
        self.quick.side_effect = RuntimeError('quick failed')
        self.panel.scan_cve = lambda on_terminal, assessment_id: on_terminal('skipped')
        run = self.start()
        update = ManualWorker.created[0]
        self.finish_command(update, success=False)
        self.assertEqual(len(run['outcomes']), 7)
        self.assertEqual([r['outcome'] for r in run['outcomes']],
                         ['skipped','failed','succeeded','failed','succeeded','skipped','failed'])
        self.sidebar._scan_failed.assert_called_once_with()
        self.sidebar._post_scan_check.assert_not_called()
        self.summary.assert_called_once_with()

    def test_cve_cancel_waits_for_worker_exit_and_then_advances(self):
        run, cve = self.reach_cve()
        self.panel.cancel_active_scan()
        self.assertTrue(cve.cancelled)
        self.assertEqual(run['waiting'], 5)
        self.assertEqual(len(ManualWorker.created), 3)
        cve.outcome()
        cve.end()
        self.assertEqual(run['outcomes'][5]['outcome'], 'cancelled')
        self.finish_command(ManualWorker.created[3])
        self.summary.assert_called_once_with()

    def test_offline_and_no_cve_targets_are_terminal(self):
        for online in (True, False):
            with self.subTest(online=online):
                ManualWorker.created = []
                self.summary.reset_mock()
                self.panel._get_installed_version.return_value = None
                with patch.dict(NS, has_internet=lambda: online, probe_package=lambda name: (False, None)):
                    self.start()
                    self.finish_command(ManualWorker.created[0])
                    self.finish_command(ManualWorker.created[1])
                    run = self.sidebar._re_run
                    self.assertEqual(run['outcomes'][5]['outcome'], 'skipped')
                    self.finish_command(ManualWorker.created[2])
                self.summary.assert_called_once_with()

    def test_unknown_worker_exit_and_parser_failure_do_not_stall(self):
        run = self.start()
        self.sidebar._parse_unused.side_effect = RuntimeError('bad output')
        worker = ManualWorker.created[0]
        worker.output_ready.emit('bad')
        self.finish_command(worker)
        self.assertEqual(run['outcomes'][0]['outcome'], 'failed')
        ManualWorker.created[1].end()  # No logical outcome: unknown.
        self.assertEqual(run['outcomes'][1]['outcome'], 'unknown')
        self.panel._handle_cve_result.side_effect = RuntimeError('bad response')
        self.finish_cve(ManualWorker.created[2])
        self.assertEqual(run['outcomes'][5]['outcome'], 'unknown')
        update = ManualWorker.created[3]
        self.panel._parse_upgrades.side_effect = RuntimeError('bad update output')
        update.output_ready.emit('bad')
        self.finish_command(update)
        self.assertEqual(run['outcomes'][6]['outcome'], 'failed')
        self.summary.assert_called_once_with()

    def test_existing_work_is_not_cancelled_and_conflicting_panel_start_is_rejected(self):
        self.panel._any_running = True
        self.sidebar.run_everything(on_complete=self.summary)
        self.assertFalse(hasattr(self.sidebar, '_re_run'))
        self.panel._any_running = False
        self.start()
        self.panel.scan_cve()
        self.panel.scan_upgrades()
        self.assertEqual(len(ManualWorker.created), 1)

    def test_cve_summary_exception_is_unknown_and_does_not_stall(self):
        run, worker = self.reach_cve()
        self.panel._finish_cve_scan = Mock(side_effect=RuntimeError('summary failed'))
        self.finish_cve(worker)
        self.assertEqual(run['outcomes'][5]['outcome'], 'unknown')
        self.finish_command(ManualWorker.created[3])
        self.summary.assert_called_once_with()

    def test_missing_deborphan_skips_without_waiting_for_a_worker(self):
        with patch.dict(NS, shutil=SimpleNamespace(which=lambda name: None)):
            run = self.start()
        self.assertEqual(run['outcomes'][0]['outcome'], 'skipped')
        self.assertEqual(run['waiting'], 1)
        self.assertEqual(ManualWorker.created[0].args[0], ['ss', '-tunlp'])

    def test_all_cve_requests_failed_still_reaches_final_summary(self):
        run, worker = self.reach_cve()
        self.finish_cve(worker, success=False)
        self.assertEqual(run['outcomes'][5]['outcome'], 'failed')
        self.finish_command(ManualWorker.created[3])
        self.summary.assert_called_once_with()

    def test_no_timer_chain_is_created(self):
        timer = Mock()
        with patch.dict(NS, QTimer=timer):
            self.finish_run()
        timer.singleShot.assert_not_called()

    def test_cve_bookkeeping_failure_is_pre_dispatch(self):
        def log_scan(name, *args):
            if name == 'CVE Vulnerability Check':
                raise RuntimeError('CVE bookkeeping failed')
        NS['SESSION'].log_scan.side_effect = log_scan
        run = self.start()
        self.finish_command(ManualWorker.created[0])
        self.finish_command(ManualWorker.created[1])
        cve, update = ManualWorker.created[2:4]
        self.assertFalse(cve.isRunning())
        self.assertEqual(run['outcomes'][5]['outcome'], 'failed')
        self.finish_command(update)
        self.summary.assert_called_once_with()

    def test_post_dispatch_cve_error_waits_and_retains_error(self):
        original = self.panel._start_worker
        def start_then_raise(worker):
            original(worker)
            raise RuntimeError('post-dispatch CVE bookkeeping failed')
        self.panel._start_worker = start_then_raise
        run, cve = self.reach_cve()
        self.assertTrue(cve.isRunning())
        self.assertEqual(len(ManualWorker.created), 3)
        self.assertEqual(len(run['outcomes']), 5)
        self.summary.assert_not_called()
        self.assertEqual(self.panel._assessment_owner, run['id'])
        self.sidebar.setEnabled.assert_called_once_with(False)
        cve.outcome()
        self.assertEqual(len(ManualWorker.created), 3)
        cve.end()
        self.assertEqual(run['outcomes'][5]['outcome'], 'failed')
        self.assertIn('post-dispatch CVE', run['outcomes'][5]['error'])
        self.assertEqual(len(ManualWorker.created), 4)
        update = ManualWorker.created[3]
        self.finish_command(update)
        self.assertEqual(run['outcomes'][6]['outcome'], 'failed')
        cve.end()
        update.end()
        self.summary.assert_called_once_with()
        self.assertEqual(len(run['outcomes']), 7)

    def test_post_dispatch_sidebar_error_waits_for_thread(self):
        original = self.sidebar._start_worker
        def start_then_raise(worker):
            original(worker)
            raise RuntimeError('post-dispatch sidebar failure')
        self.sidebar._start_worker = start_then_raise
        run = self.start()
        first = ManualWorker.created[0]
        self.assertTrue(first.isRunning())
        self.assertEqual(len(ManualWorker.created), 1)
        self.assertEqual(run['waiting'], 0)
        first.outcome()
        self.assertEqual(len(ManualWorker.created), 1)
        first.end()
        self.assertEqual(run['outcomes'][0]['outcome'], 'failed')
        self.assertIn('sidebar failure', run['outcomes'][0]['error'])
        self.assertEqual(len(ManualWorker.created), 2)

    def test_post_dispatch_update_error_cannot_finalize_early(self):
        run, cve = self.reach_cve()
        original = self.panel._start_worker
        def start_then_raise(worker):
            original(worker)
            raise RuntimeError('post-dispatch update failure')
        self.panel._start_worker = start_then_raise
        self.finish_cve(cve)
        update = ManualWorker.created[3]
        self.assertTrue(update.isRunning())
        self.assertEqual(run['waiting'], 6)
        self.summary.assert_not_called()
        self.assertEqual(self.panel._assessment_owner, run['id'])
        self.finish_command(update)
        self.assertEqual(run['outcomes'][6]['outcome'], 'failed')
        self.assertIn('update failure', run['outcomes'][6]['error'])
        self.summary.assert_called_once_with()

    def test_pre_dispatch_start_failure_advances_without_worker(self):
        self.sidebar._start_worker = Mock(side_effect=RuntimeError('start refused'))
        run = self.start()
        self.assertEqual(run['waiting'], 5)
        self.assertEqual([r['outcome'] for r in run['outcomes'][:2]], ['failed', 'failed'])
        self.assertFalse(ManualWorker.created[0].isRunning())
        self.assertFalse(ManualWorker.created[1].isRunning())
        self.finish_cve(ManualWorker.created[2])
        self.finish_command(ManualWorker.created[3])
        self.summary.assert_called_once_with()

    def test_fast_exit_still_waits_for_queued_finished_notification(self):
        original = self.sidebar._start_worker
        def start_then_exit_raise(worker):
            original(worker)
            worker.running = False
            worker.ended = True  # Qt thread exited; finished slot not delivered yet.
            raise RuntimeError('fast-exit setup failure')
        self.sidebar._start_worker = start_then_exit_raise
        run = self.start()
        worker = ManualWorker.created[0]
        self.assertEqual(run['waiting'], 0)
        self.assertEqual(run['outcomes'], [])
        self.assertEqual(len(ManualWorker.created), 1)
        worker.outcome()
        worker.end()
        self.assertEqual(run['outcomes'][0]['outcome'], 'failed')
        self.assertIn('fast-exit', run['outcomes'][0]['error'])
        self.assertEqual(run['waiting'], 1)

    def test_inline_finished_waits_until_startup_returns_and_retains_error(self):
        original = self.sidebar._start_worker
        def start_then_finish_raise(worker):
            original(worker)
            if worker.args[0] == ['deborphan']:
                worker.outcome()
                worker.end()
                raise RuntimeError('after-inline-completion setup failure')
        self.sidebar._start_worker = start_then_finish_raise
        run = self.start()
        self.assertEqual(run['outcomes'][0]['outcome'], 'failed')
        self.assertIn('after-inline-completion', run['outcomes'][0]['error'])
        self.assertEqual(run['waiting'], 1)
        self.assertEqual(len(ManualWorker.created), 2)
        ManualWorker.created[0].end()
        self.assertEqual(len(run['outcomes']), 1)

    def test_terminal_outcome_calculation_error_is_retained(self):
        callback = Mock()
        worker = ManualWorker(['fake'])
        self.sidebar._start_assessment_worker(
            worker, Mock(side_effect=RuntimeError('outcome failed')), callback)
        worker.end()
        worker.end()
        callback.assert_called_once_with({'outcome':'failed', 'error':'outcome failed'})

    def test_exception_after_cve_adapter_dispatch_keeps_boundary(self):
        original = self.panel.scan_cve
        def adapter_then_raise(**kwargs):
            original(**kwargs)
            raise RuntimeError('after-adapter dispatch failure')
        self.panel.scan_cve = adapter_then_raise
        run, cve = self.reach_cve()
        self.assertTrue(cve.isRunning())
        self.assertEqual(len(ManualWorker.created), 3)
        self.summary.assert_not_called()
        self.finish_cve(cve)
        self.assertEqual(run['outcomes'][5]['outcome'], 'failed')
        self.assertIn('after-adapter', run['outcomes'][5]['error'])
        self.finish_command(ManualWorker.created[3])
        self.summary.assert_called_once_with()

    def test_no_privileged_steps_are_added(self):
        run = self.finish_run()
        names = ' '.join(name for name, _ in run['steps']).lower()
        self.assertNotIn('lynis', names)
        self.assertNotIn('drive', names)
        for worker in ManualWorker.created:
            self.assertFalse(worker.kwargs.get('sudo', False))
            self.assertNotIn('sudo', worker.args[0])


if __name__ == '__main__':
    unittest.main()
