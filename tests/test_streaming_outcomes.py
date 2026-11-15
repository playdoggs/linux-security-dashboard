"""Stage 4A: production streaming outcomes/callbacks with mocked subprocesses."""
import io
import logging
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication
from test_command_outcomes import CLASSES, NS, load_definition, method

StreamingWorker = load_definition(CLASSES['StreamingCommandWorker'])


def process(returncode=0, wait_error=None):
    return SimpleNamespace(stdout=io.StringIO('progress\n'), stderr=io.StringIO(''),
                           stdin=io.StringIO(), returncode=returncode,
                           wait=Mock(side_effect=wait_error), kill=Mock())


class StreamingOutcomes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def exercise(self, proc=None, popen_error=None, threaded=False):
        worker = StreamingWorker(['fake-command'], timeout=1)
        events, errors, finished = [], [], []
        worker.finished_ok.connect(lambda: events.append('success'))
        worker.failed.connect(lambda: events.append('failure'))
        worker.error_ready.connect(errors.append)
        worker.finished.connect(lambda: finished.append('finished'))
        with patch.object(subprocess, 'Popen', return_value=proc, side_effect=popen_error), \
                patch.object(logging, 'error'):
            if threaded:
                worker.start()
                self.assertTrue(worker.wait(2000))
                self.app.processEvents()
            else:
                worker.run()
        self.assertEqual(len(events), 1)
        self.assertEqual(finished, ['finished'] if threaded else [])
        return worker, events, errors

    def test_zero_exit_only_success_even_with_stderr(self):
        proc = process()
        proc.stderr = io.StringIO('ordinary warning\n')
        worker, events, errors = self.exercise(proc)
        self.assertEqual(events, ['success'])
        self.assertIsNone(worker.failure_reason)
        self.assertEqual(worker.full_output, 'progress\n')
        self.assertEqual(errors, [])

    def test_nonzero_exit_with_and_without_stderr(self):
        for stderr in ('', 'audit failed\n', '[sudo] password prompt\n'):
            with self.subTest(stderr=stderr):
                proc = process(2)
                proc.stderr = io.StringIO(stderr)
                worker, events, errors = self.exercise(proc)
                self.assertEqual(events, ['failure'])
                self.assertEqual(worker.failure_reason, 'nonzero_exit')
                self.assertTrue(errors)

    def test_missing_executable(self):
        worker, events, errors = self.exercise(popen_error=FileNotFoundError())
        self.assertEqual(events, ['failure'])
        self.assertEqual(worker.failure_reason, 'missing_executable')
        self.assertIn('not found', errors[0])

    def test_timeout_and_failed_kill_still_have_one_failure(self):
        for kill_error in (None, PermissionError('not permitted')):
            with self.subTest(kill_error=kill_error):
                proc = process(wait_error=subprocess.TimeoutExpired('fake', 1))
                proc.kill.side_effect = kill_error
                worker, events, errors = self.exercise(proc)
                self.assertEqual(events, ['failure'])
                self.assertEqual(worker.failure_reason, 'timeout')
                proc.kill.assert_called_once_with()
                self.assertIn('timed out', errors[0])

    def test_unexpected_start_read_and_password_write_exceptions(self):
        for stage in ('start', 'read', 'password'):
            with self.subTest(stage=stage):
                worker = StreamingWorker(['fake'], sudo=True, password=b'fake')
                proc = process()
                if stage == 'read':
                    proc.stderr = Mock()
                    proc.stderr.read.side_effect = RuntimeError('read failed')
                if stage == 'password':
                    proc.stdin = Mock()
                    proc.stdin.write.side_effect = RuntimeError('write failed')
                outcomes = []
                worker.finished_ok.connect(lambda: outcomes.append('success'))
                worker.failed.connect(lambda: outcomes.append('failure'))
                with patch.object(subprocess, 'Popen', return_value=proc,
                                  side_effect=RuntimeError('start failed') if stage == 'start' else None), \
                        patch.object(logging, 'error'):
                    worker.run()
                self.assertEqual(outcomes, ['failure'])
                self.assertEqual(worker.failure_reason, 'exception')

    def test_worker_mixin_cleanup_waits_for_real_thread_completion(self):
        for exitcode in (0, 1):
            with self.subTest(exitcode=exitcode):
                worker = StreamingWorker(['fake'])
                owner = SimpleNamespace(_workers=set())
                start = method('WorkerMixin', '_start_worker')
                outcomes = []
                worker.finished_ok.connect(lambda: outcomes.append('success'))
                worker.failed.connect(lambda: outcomes.append('failure'))
                with patch.object(subprocess, 'Popen', return_value=process(exitcode)), \
                        patch.object(worker, 'deleteLater') as delete:
                    start(owner, worker)
                    self.assertTrue(worker.wait(2000))
                    self.app.processEvents()
                    self.assertEqual(owner._workers, set())
                    delete.assert_called_once_with()
                self.assertEqual(outcomes, ['success' if exitcode == 0 else 'failure'])

    def test_lynis_actual_callback_chain_for_each_outcome(self):
        audit = method('LynisPanel', 'run_lynis')
        sidebar_entry = method('SideBar', '_run_lynis')
        for case in ('success', 'nonzero', 'missing', 'timeout', 'exception'):
            with self.subTest(case=case):
                sidebar = SimpleNamespace(_pre_scan=Mock(), stack=Mock(),
                                          _post_scan_check=Mock(), _scan_failed=Mock())
                panel = SimpleNamespace(status=Mock(), terminal=Mock(), output=Mock(),
                                        _get_sudo_password=Mock(return_value=b'fake'),
                                        _lappend=Mock(), _parse_lynis_output=Mock())
                panel.run_lynis = lambda **kwargs: audit(panel, **kwargs)
                sidebar.lynis_panel = panel
                workers = []
                def start(worker):
                    workers.append(worker)
                    worker.start()
                    self.assertTrue(worker.wait(2000))
                    self.app.processEvents()
                panel._start_worker = start
                proc = process(1 if case == 'nonzero' else 0,
                               subprocess.TimeoutExpired('fake', 1) if case == 'timeout' else None)
                error = {'missing': FileNotFoundError(), 'exception': RuntimeError('failed')}.get(case)
                with patch.dict(NS, StreamingCommandWorker=StreamingWorker,
                                shutil=SimpleNamespace(which=lambda name: '/fake/lynis'),
                                L=lambda key: key, T=dict(OK='green', DANGER='red', ACCENT='blue', TEXT_DIM='grey')), \
                        patch.object(subprocess, 'Popen', return_value=proc, side_effect=error), \
                        patch.object(logging, 'error'):
                    sidebar_entry(sidebar)
                self.assertEqual(len(workers), 1)
                if case == 'success':
                    panel._parse_lynis_output.assert_called_once_with('progress\n')
                    sidebar._post_scan_check.assert_called_once_with()
                    sidebar._scan_failed.assert_not_called()
                    panel.terminal.append_ok.assert_called_once()
                else:
                    panel._parse_lynis_output.assert_not_called()
                    sidebar._post_scan_check.assert_not_called()
                    panel.terminal.append_ok.assert_not_called()
                    sidebar._scan_failed.assert_called_once_with()
                    self.assertIn('incomplete/unknown', panel.status.setText.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
