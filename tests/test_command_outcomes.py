"""Exercise production worker/caller definitions without importing the GUI module.

AST extraction avoids module-level logging, distro detection and widget setup.
Every subprocess call is mocked; these tests never invoke sudo or host commands.
"""
import ast
import logging
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QThread, pyqtSignal

SOURCE = Path(__file__).resolve().parents[1] / "linux-security-dashboard.py"
TREE = ast.parse(SOURCE.read_text())
CLASSES = {node.name: node for node in TREE.body if isinstance(node, ast.ClassDef)}
NS = dict(QThread=QThread, pyqtSignal=pyqtSignal, subprocess=subprocess,
          logging=logging, T={"OK": "green"}, strip_ansi=lambda text: text)


def load_definition(node, namespace=NS):
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace[node.name]


CommandWorker = load_definition(CLASSES["CommandWorker"])


def method(class_name, name):
    return load_definition(next(node for node in CLASSES[class_name].body
                                if isinstance(node, ast.FunctionDef) and node.name == name))


class CommandOutcomes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def run_worker(self, result=None, error=None, **kwargs):
        worker = CommandWorker(["fake-command"], **kwargs)
        events = SimpleNamespace(output=[], errors=[], success=[], failure=[])
        worker.output_ready.connect(events.output.append)
        worker.error_ready.connect(events.errors.append)
        worker.finished_ok.connect(lambda: events.success.append(True))
        worker.failed.connect(lambda: events.failure.append(True))
        with patch.object(subprocess, "run", return_value=result, side_effect=error) as run:
            worker.run()
        return worker, events, run

    def test_success_and_warning_are_not_failure(self):
        result = subprocess.CompletedProcess([], 0, b"done", b"warning")
        _, events, _ = self.run_worker(result)
        self.assertEqual(events.output, ["done", "warning"])
        self.assertEqual(events.success, [True])
        self.assertEqual(events.failure, [])
        self.assertEqual(events.errors, [])

    def test_nonzero_exit_with_and_without_stderr(self):
        for stderr in (b"permission denied", b""):
            with self.subTest(stderr=stderr):
                _, events, _ = self.run_worker(subprocess.CompletedProcess([], 1, b"", stderr))
                self.assertEqual(events.success, [])
                self.assertEqual(events.failure, [True])
                self.assertTrue(events.errors)

    def test_exceptions_never_signal_success(self):
        for error in (subprocess.TimeoutExpired("fake-command", 1),
                      FileNotFoundError("missing"), RuntimeError("unexpected")):
            with self.subTest(error=type(error).__name__):
                with patch.object(logging, "error"):
                    _, events, _ = self.run_worker(error=error)
                self.assertEqual(events.success, [])
                self.assertEqual(events.failure, [True])
                self.assertTrue(events.errors)

    def test_sudo_arguments_are_inspected_not_executed(self):
        for password in (b"fake-password", b""):
            with self.subTest(password_supplied=bool(password)):
                _, events, run = self.run_worker(
                    subprocess.CompletedProcess([], 0, b"", b""),
                    sudo=True, password=password)
                self.assertEqual(run.call_args.args[0][0], "sudo")
                self.assertEqual(events.success, [True])
                if password:
                    self.assertEqual(run.call_args.kwargs["input"], password + b"\n")
                else:
                    self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_thread_finished_still_runs_after_failure(self):
        worker = CommandWorker(["fake-command"])
        completed = []
        worker.finished.connect(lambda: completed.append(True))
        with patch.object(subprocess, "run", side_effect=FileNotFoundError()):
            worker.start()
            self.assertTrue(worker.wait(2000))
        self.app.processEvents()
        self.assertTrue(worker.isFinished())
        self.assertEqual(completed, [True])

    def test_wizard_stops_after_failed_step_and_restores_controls(self):
        advance = method("GuidedWizard", "_run_next_fix_cmd")
        stop = method("GuidedWizard", "_fix_failed")
        obj = SimpleNamespace(_pending_fix_cmds=[(["first"], "first"), (["second"], "second")],
                              _fix_running=True, _fix_password=b"fake-password",
                              run_btn=Mock(), terminal=Mock(), _selected_fix_idx=0,
                              _refresh_fix_statuses=Mock(), _show_fix_detail=Mock())
        obj._run_next_fix_cmd = lambda: advance(obj)
        obj._fix_failed = lambda: stop(obj)
        obj._start_worker = lambda worker: worker.run()
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"failed")) as run:
            advance(obj)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(obj._pending_fix_cmds, [])
        self.assertFalse(obj._fix_running)
        self.assertIsNone(obj._fix_password)
        obj.run_btn.setEnabled.assert_called_once_with(True)
        obj.terminal.append_warn.assert_called_once()
        obj._refresh_fix_statuses.assert_called_once_with()
        obj._show_fix_detail.assert_called_once_with(0)

    def test_failed_action_retains_finding_and_does_not_verify(self):
        act = method("FindingsTable", "_act")
        obj = SimpleNamespace(terminal=Mock(), _verify=Mock())
        obj._start_worker = lambda worker: worker.run()
        dialog = Mock()
        dialog.exec.return_value = 1
        dialog.snapshot_cb = None
        with patch.dict(NS, prompt_for_sudo_password=Mock(return_value=b"fake"),
                        PreActionDialog=Mock(return_value=dialog),
                        QDialog=SimpleNamespace(DialogCode=SimpleNamespace(Accepted=1)),
                        make_undo_cmd=Mock(return_value="reverse"),
                        get_rollback_info=Mock(return_value=dict(level="LOW", does="", risk="", exploit="")),
                        datetime=__import__('datetime')):
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"failed")):
                act(obj, "systemctl disable example", "example", "disable", "LOW")
        obj._verify.assert_not_called()
        obj.terminal.append_err.assert_called_once()

    def test_failed_undo_retains_entry(self):
        undo = method("UndoPanel", "_run_undo")
        obj = SimpleNamespace(terminal=Mock(), _remove_undo_entry_after_rollback=Mock())
        obj._start_worker = lambda worker: worker.run()
        box = SimpleNamespace(question=Mock(return_value=1),
                              StandardButton=SimpleNamespace(Yes=1, No=2))
        with patch.dict(NS, QMessageBox=box, prompt_for_sudo_password=Mock(return_value=b"fake")):
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"failed")):
                undo(obj, dict(undo_cmd="sudo systemctl enable example", action="disable example"))
        obj._remove_undo_entry_after_rollback.assert_not_called()

    def test_successful_wizard_runs_steps_and_restores_controls(self):
        advance = method("GuidedWizard", "_run_next_fix_cmd")
        obj = SimpleNamespace(_pending_fix_cmds=[(["first"], "first"), (["second"], "second")],
                              _fix_running=True, _fix_password=b"fake",
                              _selected_fix_idx=None, run_btn=Mock(), terminal=Mock(),
                              _refresh_fix_statuses=Mock(), _fix_failed=Mock())
        obj._run_next_fix_cmd = lambda: advance(obj)
        obj._start_worker = lambda worker: worker.run()
        with patch.dict(NS, QMessageBox=SimpleNamespace(information=Mock())):
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as run:
                advance(obj)
        self.assertEqual(run.call_count, 2)
        self.assertFalse(obj._fix_running)
        self.assertIsNone(obj._fix_password)
        obj.run_btn.setEnabled.assert_called_once_with(True)
        obj._fix_failed.assert_not_called()

    def sidebar(self):
        sidebar = SimpleNamespace(terminal=Mock(), findings=Mock(), stack=Mock(),
                                  _pre_scan=Mock(), _mark_section_action_done=Mock(),
                                  _pending_section_action=("checks", "test"))
        complete = method("SideBar", "_post_scan_check")
        failure = method("SideBar", "_scan_failed")
        sidebar._post_scan_check = lambda: complete(sidebar)
        sidebar._scan_failed = lambda: failure(sidebar)
        return sidebar

    def start_thread(self, workers, worker):
        workers.append(worker)
        worker.start()
        self.assertTrue(worker.wait(2000))
        self.app.processEvents()

    def test_update_outcomes_reach_actual_sidebar_handlers(self):
        scan = method("CvePanel", "scan_upgrades")
        finish = method("CvePanel", "_finish_upgrades_scan")
        entry = method("SideBar", "_scan_upgrades")
        outcomes = [subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 1, b"", b"failed"),
                    subprocess.TimeoutExpired("fake", 1), FileNotFoundError()]
        for outcome in outcomes:
            with self.subTest(outcome=outcome):
                sidebar = self.sidebar()
                panel = SimpleNamespace(status=Mock(), terminal=sidebar.terminal,
                                        cve_table=Mock(), _parse_upgrades=Mock())
                panel._finish_upgrades_scan = lambda succeeded=True: finish(panel, succeeded)
                panel.scan_upgrades = lambda **kwargs: scan(panel, **kwargs)
                sidebar.cve_panel = panel
                workers = []
                panel._start_worker = lambda worker: self.start_thread(workers, worker)
                succeeded = isinstance(outcome, subprocess.CompletedProcess) and outcome.returncode == 0
                with patch.dict(NS, has_internet=lambda: True, os=__import__('os'), L=lambda key: key):
                    with patch.object(subprocess, "run",
                                      return_value=outcome if isinstance(outcome, subprocess.CompletedProcess) else None,
                                      side_effect=outcome if isinstance(outcome, Exception) else None):
                        entry(sidebar)
                self.assertIsNone(panel._scan_upgrades_done_cb)
                self.assertIsNone(panel._scan_upgrades_failed_cb)
                self.assertIsNone(sidebar._pending_section_action)
                if succeeded:
                    sidebar._mark_section_action_done.assert_called_once()
                    sidebar.findings.show_all_ok_banner.assert_called_once()
                    sidebar.findings.hide_all_ok_banner.assert_not_called()
                    self.assertEqual(panel.status.setText.call_args.args[0], "Update check complete.")
                else:
                    sidebar._mark_section_action_done.assert_not_called()
                    sidebar.findings.show_all_ok_banner.assert_not_called()
                    sidebar.findings.hide_all_ok_banner.assert_called_once()
                    self.assertEqual(panel.status.setText.call_args.args[0],
                                     "Update check failed — see terminal output.")

    def test_lynis_install_failures_reach_actual_sidebar_failure_handler(self):
        install = method("LynisPanel", "run_lynis")
        entry = method("SideBar", "_run_lynis")
        for outcome in (subprocess.CompletedProcess([], 1, b"", b"failed"),
                        subprocess.TimeoutExpired("fake", 1), FileNotFoundError()):
            with self.subTest(outcome=outcome):
                sidebar = self.sidebar()
                panel = SimpleNamespace(status=Mock(), terminal=sidebar.terminal,
                                        _get_sudo_password=Mock(return_value=b"fake"))
                panel.run_lynis = lambda **kwargs: install(panel, **kwargs)
                sidebar.lynis_panel = panel
                workers = []
                panel._start_worker = lambda worker: self.start_thread(workers, worker)
                box = SimpleNamespace(question=Mock(return_value=1),
                                      StandardButton=SimpleNamespace(Yes=1, No=2))
                with patch.dict(NS, shutil=SimpleNamespace(which=lambda name: None),
                                QMessageBox=box, L=lambda key: key):
                    with patch.object(subprocess, "run",
                                      return_value=outcome if isinstance(outcome, subprocess.CompletedProcess) else None,
                                      side_effect=outcome if isinstance(outcome, Exception) else None) as run:
                        entry(sidebar)
                self.assertEqual(run.call_count, 1)  # No retry or audit after failure.
                self.assertIsNone(sidebar._pending_section_action)
                sidebar._mark_section_action_done.assert_not_called()
                sidebar.findings.show_all_ok_banner.assert_not_called()
                sidebar.findings.hide_all_ok_banner.assert_called_once()
                self.assertEqual(panel.status.setText.call_args.args[0], "Lynis installation failed.")

    def test_partial_wizard_failure_refreshes_without_claiming_completion(self):
        advance = method("GuidedWizard", "_run_next_fix_cmd")
        failure = method("GuidedWizard", "_fix_failed")
        obj = SimpleNamespace(_pending_fix_cmds=[([name], name) for name in ("first", "second", "third")],
                              _fix_running=True, _fix_password=b"fake", _selected_fix_idx=0,
                              run_btn=Mock(), terminal=Mock(), _refresh_fix_statuses=Mock(),
                              _show_fix_detail=Mock())
        obj._run_next_fix_cmd = lambda: advance(obj)
        obj._fix_failed = lambda: failure(obj)
        workers = []
        obj._start_worker = lambda worker: self.start_thread(workers, worker)
        completed = Mock()
        with patch.dict(NS, QMessageBox=SimpleNamespace(information=completed)):
            with patch.object(subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 1, b"", b"failed")]) as run:
                advance(obj)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(obj._pending_fix_cmds, [])
        self.assertFalse(obj._fix_running)
        self.assertIsNone(obj._fix_password)
        obj.run_btn.setEnabled.assert_called_once_with(True)
        obj._refresh_fix_statuses.assert_called_once_with()
        obj._show_fix_detail.assert_called_once_with(0)
        completed.assert_not_called()
        obj.terminal.append_warn.assert_called_once()

    def test_failed_scan_clears_pending_state_without_all_ok(self):
        scan = method("SideBar", "_run_cmd")
        failure = method("SideBar", "_scan_failed")
        obj = SimpleNamespace(terminal=Mock(), findings=Mock(),
                              _pending_section_action=("checks", "test"), _post_scan_check=Mock())
        obj._scan_failed = lambda: failure(obj)
        obj._start_worker = lambda worker: worker.run()
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"failed")):
            scan(obj, ["fake-command"], "Test")
        self.assertIsNone(obj._pending_section_action)
        obj._post_scan_check.assert_not_called()
        obj.terminal.append_ok.assert_not_called()
        obj.findings.hide_all_ok_banner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
