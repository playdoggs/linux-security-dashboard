"""Workspace routing and isolated real-widget navigation regression tests."""
import ast
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'linux-security-dashboard.py').read_text())


class WorkspaceNavigation(unittest.TestCase):
    def test_legacy_router_routes_without_dispatch(self):
        ns = {}
        node = next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == 'WorkspaceRouter')
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<production>', 'exec'), ns)
        window = SimpleNamespace(_navigate=Mock(), assessment_tabs=Mock(), remediation_tabs=Mock())
        router = ns['WorkspaceRouter'](window)
        for index, section in ((0, 'Findings'), (1, 'Assessments'), (2, 'Assessments'),
                               (3, 'Remediation'), (4, 'Remediation')):
            router.setCurrentIndex(index)
            window._navigate.assert_called_with(section)
        window.assessment_tabs.setCurrentIndex.assert_any_call(1)
        window.assessment_tabs.setCurrentIndex.assert_any_call(2)
        window.remediation_tabs.setCurrentIndex.assert_any_call(0)
        window.remediation_tabs.setCurrentIndex.assert_any_call(1)
        calls = window._navigate.call_count
        router.setCurrentIndex(99)
        self.assertEqual(calls, window._navigate.call_count)

    def test_real_widgets_navigation_with_owned_qthread(self):
        env = dict(os.environ, QT_QPA_PLATFORM='offscreen', QT_QPA_PLATFORMTHEME='generic',
                   PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'tests/ui_navigation_probe.py')],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('real QThread execution preserves ownership', result.stdout)
        self.assertIn('normal shutdown passed', result.stdout)
