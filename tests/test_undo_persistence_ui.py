"""Production UI methods + temporary SQLite stores, mocked widgets/commands."""
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication
from test_structured_undo import NS, method, record
from test_undo_history_store import Store, StorageError


class UndoPersistenceUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state'
        self.store = Store(self.path, manager='apt')
        self.panel = self.panel_for(self.store)
        self.value = record(operation='package_install', manager='apt', package='example')
        self.value.update(time='now', action='remove example', cmd='historical', undo_cmd='never execute')
        self.record_id = self.store.create(self.value)
        self.workers = []
        self.panel._start_worker = self.run_worker
        self.box = SimpleNamespace(question=Mock(return_value=1),
                                   StandardButton=SimpleNamespace(Yes=1, No=2))
        self.prompt = Mock(return_value=b'fake-password')

    def panel_for(self, store):
        panel = SimpleNamespace(history_store=store, _inflight=set(), _store_error=None,
                                _history_view='actionable', _history_cursor=None,
                                _history_cursors=[], _next_cursor=None, terminal=Mock(),
                                table=Mock(), detail=Mock(), history_status=Mock(),
                                history_next=Mock(), history_previous=Mock(),
                                _add_row=Mock(), _update_empty_state=Mock())
        for name in ('_run_undo', '_finish_undo', '_undo_worker_failed', 'record_remediation',
                     'add_live_entry', '_reload_history', '_history_error',
                     '_next_history_page', '_previous_history_page', '_load_previous_sessions'):
            setattr(panel, name, MethodType(method('UndoPanel', name), panel))
        return panel

    def run_worker(self, worker):
        # This assertion also covers dispatch ordering for every outcome test.
        saved = self.store.get(self.record_id)
        self.assertEqual(saved['state'], 'pending')
        self.assertEqual(self.store.events(self.record_id)[0]['state'], 'pending')
        self.workers.append(worker)
        worker.start()
        self.assertTrue(worker.wait(2000))
        self.app.processEvents()

    @contextmanager
    def command(self, outcome=None):
        outcome = outcome or subprocess.CompletedProcess([], 0, b'', b'')
        with patch.dict(NS, QMessageBox=self.box, prompt_for_sudo_password=self.prompt, UNDO_LOG=[]):
            with patch.object(subprocess, 'run',
                              return_value=outcome if isinstance(outcome, subprocess.CompletedProcess) else None,
                              side_effect=outcome if isinstance(outcome, Exception) else None) as run:
                yield run

    def test_pending_commit_precedes_worker_construction_and_completion_precedes_success_ui(self):
        original = NS['CommandWorker']
        def construct(*args, **kwargs):
            self.assertEqual(self.store.get(self.record_id)['state'], 'pending')
            return original(*args, **kwargs)
        def report_success(*args):
            self.assertEqual(self.store.get(self.record_id)['state'], 'completed')
            self.assertEqual(self.store.events(self.record_id)[0]['state'], 'completed')
        self.panel.terminal.append_ok.side_effect = report_success
        with self.command() as run, patch.dict(NS, CommandWorker=Mock(side_effect=construct)):
            self.panel._run_undo({'record_id': self.record_id})
        self.assertEqual(run.call_count, 1)
        self.assertEqual(self.panel._inflight, set())
        reopened = Store(self.path, manager='apt')
        self.assertEqual(reopened.page(view='actionable'), [])
        self.assertEqual(reopened.page(view='history')[0]['record_id'], self.record_id)
        self.assertEqual(reopened.get(self.record_id)['state'], 'completed')

    def test_nonzero_timeout_missing_command_and_unexpected_failure_are_persisted(self):
        cases = [(subprocess.CompletedProcess([], 1, b'', b'failed'), 'failed'),
                 (subprocess.TimeoutExpired('fake', 1), 'outcome-unknown'),
                 (FileNotFoundError(), 'failed'), (RuntimeError('unexpected'), 'outcome-unknown')]
        for outcome, state in cases:
            with self.subTest(outcome=outcome):
                self.record_id = self.store.create(self.value)
                with self.command(outcome), patch.object(NS['logging'], 'error'):
                    self.panel._run_undo({'record_id': self.record_id})
                self.assertEqual(self.store.get(self.record_id)['state'], state)
                self.panel.terminal.append_ok.assert_not_called()
                self.assertEqual(self.panel._inflight, set())

    def test_failed_or_uncertain_claim_never_constructs_worker(self):
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain):
                self.record_id = self.store.create(self.value)
                real_claim = self.store.claim
                def claim(record_id):
                    if uncertain:
                        real_claim(record_id)
                    raise StorageError('write/commit unavailable')
                with self.command() as run, patch.object(self.store, 'claim', side_effect=claim), \
                     patch.dict(NS, CommandWorker=Mock()) as namespace:
                    worker = NS['CommandWorker']
                    self.panel._run_undo({'record_id': self.record_id})
                    worker.assert_not_called()
                    run.assert_not_called()
                self.assertEqual(self.panel._inflight, set())
                self.assertEqual(self.store.get(self.record_id)['state'], 'pending' if uncertain else 'available')
                self.assertIn('could not be safely dispatched', self.panel.history_status.setText.call_args.args[0])

    def test_outcome_write_failure_does_not_report_success_or_reactivate(self):
        with self.command(), patch.object(self.store, 'finish', side_effect=StorageError('disk full')):
            self.panel._run_undo({'record_id': self.record_id})
        self.panel.terminal.append_ok.assert_not_called()
        self.assertEqual(self.store.get(self.record_id)['state'], 'pending')
        self.assertEqual(Store(self.path, manager='apt').page(view='actionable'), [])
        self.assertIn('could not be confirmed saved', self.panel.history_status.setText.call_args.args[0])

    def test_repeated_clicks_and_nested_authorization_cannot_dispatch_twice(self):
        entry = {'record_id': self.record_id}
        def nested(*args):
            self.panel._run_undo(entry)
            return 1
        self.box.question.side_effect = nested
        self.panel._start_worker = self.workers.append  # Leave a real worker unstarted.
        with self.command() as run:
            self.panel._run_undo(entry)
            self.panel._run_undo(entry)
            run.assert_not_called()
        self.assertEqual(len(self.workers), 1)
        self.box.question.assert_called_once()
        self.prompt.assert_called_once()
        self.assertEqual(self.store.get(self.record_id)['state'], 'pending')
        self.assertEqual(self.panel._inflight, {self.record_id})
        # A restarted instance also rejects it, without a confirmation/password prompt.
        other = self.panel_for(Store(self.path, manager='apt'))
        other._start_worker = Mock()
        self.box.question.reset_mock()
        self.prompt.reset_mock()
        with self.command():
            other._run_undo(entry)
        self.box.question.assert_not_called()
        self.prompt.assert_not_called()
        other._start_worker.assert_not_called()

    def test_all_non_available_states_rejected_before_authorization(self):
        for state, reason in [('completed', 'exit_zero'), ('failed', 'nonzero_exit'),
                              ('outcome-unknown', 'interrupted')]:
            with self.subTest(state=state):
                record_id = self.store.create(self.value)
                claim = self.store.claim(record_id)
                self.store.finish(record_id, claim['attempt_id'], state, reason)
                self.box.question.reset_mock()
                self.prompt.reset_mock()
                with self.command() as run:
                    self.panel._run_undo({'record_id': record_id, 'state': 'available'})
                    run.assert_not_called()
                self.box.question.assert_not_called()
                self.prompt.assert_not_called()

    def test_store_and_malformed_id_rejection_no_authorization_or_fallback(self):
        self.panel.history_store = None
        with self.command() as run:
            for value in ({'record_id': self.record_id}, {'undo_cmd': 'sudo arbitrary'},
                          {'record_id': []}, None):
                self.panel._run_undo(value)
            run.assert_not_called()
        self.prompt.assert_not_called()
        self.box.question.assert_not_called()
        self.panel._add_row.assert_not_called()

    def test_dispatch_construction_failure_is_persisted_as_uncertain(self):
        with self.command() as run, patch.dict(NS, CommandWorker=Mock(side_effect=RuntimeError('construction failed'))):
            self.panel._run_undo({'record_id': self.record_id})
            run.assert_not_called()
        self.assertEqual(self.store.get(self.record_id)['state'], 'outcome-unknown')
        self.assertEqual(self.panel._inflight, set())

    def test_record_remediation_persists_before_display_and_does_not_write_jsonl(self):
        path = Path(self.temp.name) / 'legacy.jsonl'
        old = b'{"schema_version":2,"undo_cmd":"sudo never-execute"}\n'
        path.write_bytes(old)
        with patch.dict(NS, UNDO_LOG_FILE=path), patch.object(self.panel, 'add_live_entry') as show:
            saved = self.panel.record_remediation(self.value)
        show.assert_called_once_with(saved)
        self.assertEqual(self.store.get(saved['record_id'])['state'], 'available')
        self.assertEqual(path.read_bytes(), old)
        with patch.object(self.store, 'create', side_effect=StorageError('disk full')), \
             patch.object(self.panel, 'add_live_entry') as show:
            with self.assertRaises(StorageError):
                self.panel.record_remediation(self.value)
            show.assert_not_called()

    def test_actual_remediation_verification_has_no_memory_only_fallback(self):
        verify = method('FindingsTable', '_verify')
        obj = SimpleNamespace(terminal=Mock(), _remove_finding_and_update_score=Mock())
        value = dict(self.value, undo_cmd='generated only')
        session = Mock()
        app = SimpleNamespace(undo_panel_ref=self.panel)
        for failing in (True, False):
            with self.subTest(failing=failing):
                session_records = []
                with patch.dict(NS, SESSION=session, UNDO_LOG=session_records,
                                QApplication=SimpleNamespace(instance=lambda: app),
                                valid_pkg=lambda pkg: True, pkg_installed=lambda pkg: False):
                    if failing:
                        with patch.object(self.store, 'create', side_effect=StorageError('disk full')):
                            verify(obj, 'apt purge example', 'example', 'LOW', value)
                        self.assertEqual(session_records, [])
                        self.assertIn('could not be confirmed saved', obj.terminal.append_err.call_args.args[0])
                    else:
                        verify(obj, 'apt purge example', 'example', 'LOW', value)
                        self.assertEqual(len(session_records), 1)
                        self.assertEqual(self.store.get(session_records[0]['record_id'])['state'], 'available')

    def test_pages_replace_rows_and_separate_current_states(self):
        for _ in range(204):
            self.store.create(self.value)
        self.panel._reload_history(reset=True)
        self.assertEqual(self.panel._add_row.call_count, 200)
        first = [call.args[0]['record_id'] for call in self.panel._add_row.call_args_list]
        self.panel._add_row.reset_mock()
        self.panel._next_history_page()
        self.assertEqual(self.panel._add_row.call_count, 5)
        second = [call.args[0]['record_id'] for call in self.panel._add_row.call_args_list]
        self.assertFalse(set(first) & set(second))
        self.panel._add_row.reset_mock()
        self.panel._previous_history_page()
        self.assertEqual(self.panel._add_row.call_count, 200)
        self.panel.table.setRowCount.assert_called_with(0)
        claim = self.store.claim(self.record_id)
        self.store.finish(self.record_id, claim['attempt_id'], 'completed', 'exit_zero')
        self.panel._history_view = 'history'
        self.panel._add_row.reset_mock()
        self.panel._reload_history(reset=True)
        self.assertEqual(self.panel._add_row.call_count, 1)
        self.assertEqual(self.panel._add_row.call_args.args[0]['state'], 'completed')

    def test_legacy_structured_and_freeform_history_bounded_read_only(self):
        path = Path(self.temp.name) / 'legacy.jsonl'
        import json
        data = ('\n'.join(json.dumps(self.value if n % 2 else {'undo_cmd': 'sudo anything'})
                          for n in range(205)) + '\n').encode()
        path.write_bytes(data)
        self.panel._history_view = 'legacy'
        with patch.dict(NS, UNDO_LOG_FILE=path):
            self.panel._reload_history(reset=True)
            self.assertEqual(self.panel._add_row.call_count, 200)
            for call in self.panel._add_row.call_args_list:
                self.assertIsNone(call.args[0]['record_id'])
                self.assertEqual(call.args[0]['state'], 'legacy')
            self.panel._add_row.reset_mock()
            self.panel._next_history_page()
            self.assertEqual(self.panel._add_row.call_count, 5)
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(len(self.store.page()), 1)  # No imports.

    def test_store_load_failure_clears_actionable_widgets_and_reports_error(self):
        with patch.object(self.store, 'page', side_effect=StorageError('corrupt store')):
            self.panel._reload_history()
        self.panel._add_row.assert_not_called()
        self.panel.table.setRowCount.assert_called_with(0)
        self.assertIn('Cannot load undo history', self.panel.history_status.setText.call_args.args[0])
        self.panel.history_next.setEnabled.assert_called_with(False)
