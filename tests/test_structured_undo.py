"""Pure undo validation tests; no application import or subprocess execution."""
import ast
import json
import logging
import tempfile
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch
from PyQt6.QtCore import QCoreApplication, QThread, pyqtSignal
from pathlib import Path
import re
import shlex
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'
TREE = ast.parse(SOURCE.read_text())
NS = dict(re=re, shlex=shlex, PKG_MGR='apt', json=json, logging=logging,
          subprocess=subprocess, QThread=QThread, pyqtSignal=pyqtSignal,
          T={'OK': 'green'}, strip_ansi=lambda text: text)
NAMES = {'UNDO_SERVICE_TARGETS', 'UNDO_PACKAGE_RE', 'build_undo_argv',
         'make_undo_operation', 'make_undo_cmd', 'UNDO_METADATA_FIELDS',
         'MAX_UNDO_LINE_BYTES', 'MAX_UNDO_HISTORY_BYTES', 'normalize_undo_record',
         'undo_presentation', 'save_undo_entry', 'load_undo_log', 'CommandWorker'}
for node in TREE.body:
    name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else None
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        name = node.targets[0].id
    if name in NAMES:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), NS)
build = NS['build_undo_argv']
derive = NS['make_undo_operation']


def record(**operation):
    return dict(schema_version=2, undo=operation)


class StructuredUndo(unittest.TestCase):
    def test_supported_operations(self):
        for backend in ('apt', 'dnf'):
            self.assertEqual(build(record(operation='package_install', manager=backend,
                                          package='libexample1.2+dev'), backend),
                             [backend, 'install', '-y', 'libexample1.2+dev'])
        for target in ('xrdp', 'avahi-daemon', 'rpcbind'):
            self.assertEqual(build(record(operation='service_enable', service=target), 'apt'),
                             ['systemctl', 'enable', '--now', target])
        self.assertEqual(build(record(operation='service_unmask', service='cups'), 'apt'),
                         ['systemctl', 'unmask', 'cups'])

    def test_reject_package_arguments_and_backend(self):
        for value in ('', '-oAPT::Update::Pre-Invoke=x', '/tmp/file.deb', 'https://example/x',
                      'a b', ' a', 'a\n', 'a;id', 'a=1', 'a/stable', 'a*', 'a:amd64',
                      'example-', 'example+', 'example.rpm', 'example.deb',
                      'a\x00', 'a' * 101, None, [], 42):
            with self.subTest(package=value), self.assertRaises(ValueError):
                build(record(operation='package_install', manager='apt', package=value), 'apt')
        for backend in ('pacman', 'apt-get', 'bash', None, [], 'dnf'):
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                build(record(operation='package_install', manager=backend, package='example'), 'apt')

    def test_package_manager_action_and_local_file_syntax_rejected(self):
        for backend in ('apt', 'dnf'):
            for package in ('example-', 'example+', 'example.rpm', 'example.deb'):
                with self.subTest(backend=backend, package=package), self.assertRaises(ValueError):
                    build(record(operation='package_install', manager=backend, package=package), backend)

    def test_reject_schema_and_service_shapes(self):
        bad = [None, [], {}, {'undo_cmd': 'sudo example'},
               {'schema_version': True, 'undo': {}}, {'schema_version': '2', 'undo': {}},
               {'schema_version': 3, 'undo': {}}, {'schema_version': 2, 'undo': None},
               record(operation=[]), record(operation='shell', command='anything'),
               record(operation='package_install', manager='apt', package='a', argv=['anything'])]
        for target in ('ssh', '/tmp/example.service', '*.service', '-now', 'cups.service', [], None):
            bad.append(record(operation='service_enable', service=target))
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                build(value, 'apt')

    def test_exact_forward_shapes_only(self):
        for command in ('apt purge example', 'apt purge -y example', 'apt-get purge example'):
            self.assertEqual(derive(command, 'apt'),
                             dict(operation='package_install', manager='apt', package='example'))
        self.assertEqual(derive('dnf remove -y example', 'dnf')['manager'], 'dnf')
        self.assertEqual(derive('systemctl mask cups', 'apt')['operation'], 'service_unmask')
        self.assertEqual(derive('systemctl disable --now xrdp', 'apt')['operation'], 'service_enable')
        for command in ('echo apt purge example', 'apt purge example extra',
                        'apt purge -- -ooption', 'apt purge example;id', 'ufw enable',
                        'pacman -R example', 'systemctl mask ssh', 'apt purge "unfinished'):
            with self.subTest(command=command):
                self.assertIsNone(derive(command, 'apt'))
        self.assertIsNone(derive('dnf remove example', 'apt'))

    def test_free_form_metadata_cannot_override_generated_command(self):
        value = record(operation='package_install', manager='apt', package='example')
        value.update(undo_cmd='sudo attacker-command', cmd='forged', risk_level='LOW')
        self.assertEqual(build(value, 'apt'), ['apt', 'install', '-y', 'example'])


CLASSES = {node.name: node for node in TREE.body if isinstance(node, ast.ClassDef)}


def method(class_name, name):
    node = next(node for node in CLASSES[class_name].body
                if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), NS)
    return NS[name]


class UndoIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def valid(self):
        value = record(operation='package_install', manager='apt', package='example')
        value.update(time='now', action='forged description', cmd='historical',
                     undo_cmd='sudo attacker-command', risk_level='LOW',
                     rollback_risk='forged reassuring text')
        return value

    def test_successful_action_creates_structured_undo(self):
        act = method('FindingsTable', '_act')
        obj = SimpleNamespace(terminal=Mock(), _verify=Mock())
        obj._start_worker = lambda worker: worker.run()
        dialog = Mock()
        dialog.exec.return_value = 1
        dialog.snapshot_cb = None
        with patch.dict(NS, prompt_for_sudo_password=Mock(return_value=b'fake'),
                        PreActionDialog=Mock(return_value=dialog),
                        QDialog=SimpleNamespace(DialogCode=SimpleNamespace(Accepted=1)),
                        datetime=__import__('datetime')):
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
                act(obj, 'apt purge -y example', 'example', 'remove', 'LOW')
        entry = obj._verify.call_args.args[-1]
        self.assertEqual(entry['schema_version'], 2)
        self.assertEqual(entry['undo'], dict(operation='package_install', manager='apt', package='example'))
        self.assertEqual(build(entry, 'apt'), ['apt', 'install', '-y', 'example'])
        self.assertEqual(entry['risk_level'], 'HIGH')

    def test_mixed_history_loading_is_bounded_and_does_not_rewrite(self):
        legacy = dict(time='old', action='old action', undo_cmd='sudo arbitrary-command')
        wrong = dict(time=[], action=None, schema_version=999, undo={'operation': 'shell'})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'history.jsonl'
            data = ('bad json\nnull\n[]\n' + json.dumps(legacy) + '\n' +
                    json.dumps(wrong) + '\n' + 'x' * 17000 + '\n' +
                    json.dumps(self.valid()) + '\n').encode()
            path.write_bytes(data)
            with patch.dict(NS, UNDO_LOG_FILE=path):
                with patch.object(logging, 'warning') as warning:
                    values = NS['load_undo_log']()
            self.assertEqual(len(values), 3)
            self.assertIsNone(NS['undo_presentation'](values[0], 'apt')['argv'])
            self.assertEqual(values[1]['time'], '[Invalid field]')
            self.assertIsNone(NS['undo_presentation'](values[1], 'apt')['argv'])
            self.assertEqual(build(values[2], 'apt'), ['apt', 'install', '-y', 'example'])
            self.assertTrue(warning.called)
            self.assertEqual(path.read_bytes(), data)

    def test_saving_appends_new_record_without_migrating_legacy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'history.jsonl'
            old = b'{"undo_cmd":"sudo old-command"}\n'
            path.write_bytes(old)
            with patch.dict(NS, UNDO_LOG_FILE=path):
                NS['save_undo_entry'](self.valid())
                values = NS['load_undo_log']()
            self.assertTrue(path.read_bytes().startswith(old))
            self.assertEqual(len(values), 2)
            self.assertEqual(build(values[-1], 'apt'), ['apt', 'install', '-y', 'example'])

    def test_invalid_or_legacy_input_never_prompts_or_constructs_worker(self):
        execute = method('UndoPanel', '_run_undo')
        for value in ({'undo_cmd': 'sudo attacker-command'}, None,
                      {'schema_version': 99, 'undo': {}},
                      record(operation='package_install', manager='apt', package='-option')):
            with self.subTest(value=value):
                obj = SimpleNamespace(terminal=Mock())
                prompt, worker, question = Mock(), Mock(), Mock()
                with patch.dict(NS, prompt_for_sudo_password=prompt, CommandWorker=worker,
                                QMessageBox=SimpleNamespace(question=question)):
                    execute(obj, value)
                prompt.assert_not_called()
                worker.assert_not_called()
                question.assert_not_called()

    def test_confirmation_and_worker_use_generated_operation_only(self):
        execute = method('UndoPanel', '_run_undo')
        for outcome in (subprocess.CompletedProcess([], 0, b'', b''),
                        subprocess.CompletedProcess([], 1, b'', b'failed'),
                        subprocess.TimeoutExpired('fake', 1), FileNotFoundError()):
            with self.subTest(outcome=outcome):
                obj = SimpleNamespace(terminal=Mock(), _remove_undo_entry_after_rollback=Mock())
                workers = []
                def start(worker):
                    workers.append(worker)
                    worker.start()
                    self.assertTrue(worker.wait(2000))
                    self.app.processEvents()
                obj._start_worker = start
                box = SimpleNamespace(question=Mock(return_value=1),
                                      StandardButton=SimpleNamespace(Yes=1, No=2))
                with patch.dict(NS, QMessageBox=box, prompt_for_sudo_password=Mock(return_value=b'fake')):
                    with patch.object(subprocess, 'run',
                                      return_value=outcome if isinstance(outcome, subprocess.CompletedProcess) else None,
                                      side_effect=outcome if isinstance(outcome, Exception) else None) as run:
                        execute(obj, self.valid())
                command = run.call_args.args[0]
                self.assertEqual(command[-4:], ['apt', 'install', '-y', 'example'])
                text = box.question.call_args.args[2]
                self.assertIn('sudo apt install -y example', text)
                self.assertNotIn('attacker-command', text)
                self.assertNotIn('forged', text)
                self.assertIn('HIGH RISK', text)
                if isinstance(outcome, subprocess.CompletedProcess) and outcome.returncode == 0:
                    obj._remove_undo_entry_after_rollback.assert_called_once()
                else:
                    obj._remove_undo_entry_after_rollback.assert_not_called()

    def test_cancellation_and_mutation_during_dialogs_execute_nothing(self):
        execute = method('UndoPanel', '_run_undo')
        for mode in ('cancel', 'password_cancel', 'confirm_mutation', 'password_mutation'):
            with self.subTest(mode=mode):
                value = self.valid()
                def confirm(*args):
                    if mode == 'confirm_mutation':
                        value['undo']['package'] = 'different'
                    return 2 if mode == 'cancel' else 1
                def password(*args, **kwargs):
                    if mode == 'password_mutation':
                        value['undo']['package'] = '-invalid'
                    return None if mode == 'password_cancel' else b'fake'
                box = SimpleNamespace(question=Mock(side_effect=confirm),
                                      StandardButton=SimpleNamespace(Yes=1, No=2))
                prompt, worker = Mock(side_effect=password), Mock()
                with patch.dict(NS, QMessageBox=box, prompt_for_sudo_password=prompt,
                                CommandWorker=worker):
                    execute(SimpleNamespace(terminal=Mock()), value)
                worker.assert_not_called()
                if mode in ('cancel', 'confirm_mutation'):
                    prompt.assert_not_called()

    def test_table_disables_legacy_and_invalid_but_enables_valid_records(self):
        add = method('UndoPanel', '_add_row')
        for value, enabled in (({'undo_cmd': 'sudo attacker-command'}, False),
                               ({'schema_version': 999, 'undo': {}}, False),
                               (self.valid(), True)):
            with self.subTest(enabled=enabled, value=value):
                table = Mock()
                table.rowCount.return_value = 0
                button = Mock()
                obj = SimpleNamespace(table=table, _update_empty_state=Mock())
                palette = dict(OK='green', DANGER='red', WARN='yellow', TEXT_DIM='gray', TEXT_MAIN='black')
                with patch.dict(NS, T=palette, QTableWidgetItem=Mock(), QColor=lambda c: c,
                                QFont=Mock(Weight=SimpleNamespace(Bold=1)), fs=lambda *args: 10,
                                Qt=SimpleNamespace(ItemDataRole=SimpleNamespace(UserRole=1)),
                                QWidget=Mock(), QHBoxLayout=Mock(), QPushButton=button, QLabel=Mock()):
                    add(obj, value)
                self.assertEqual(button.call_count, 1 if enabled else 0)
                obj._update_empty_state.assert_called_once()

    def test_detail_uses_generated_preview_and_safety_text(self):
        detail = method('UndoPanel', '_show_detail')
        table = Mock()
        table.item.return_value.data.return_value = self.valid()
        obj = SimpleNamespace(table=table, detail=Mock())
        with patch.dict(NS, Qt=SimpleNamespace(ItemDataRole=SimpleNamespace(UserRole=1))):
            detail(obj, 0, 0)
        text = obj.detail.setPlainText.call_args.args[0]
        self.assertIn('GENERATED UNDO: sudo apt install -y example', text)
        self.assertNotIn('attacker-command', text)
        self.assertNotIn('forged reassuring text', text)
