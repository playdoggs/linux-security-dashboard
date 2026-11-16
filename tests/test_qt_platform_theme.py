"""Process-local startup policy; AST extraction avoids all GUI/host side effects."""
import ast
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'
TREE = ast.parse(SOURCE.read_text())
HELPER = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
              and n.name == 'configure_qt_platform_theme')
KEYS = 'disabled-gtk-modules\nenabled-gtk-modules\noverrides\n'


class QtPlatformTheme(unittest.TestCase):
    def setUp(self):
        self.env = {'XDG_CURRENT_DESKTOP': 'ubuntu:GNOME'}
        self.run = Mock(return_value=subprocess.CompletedProcess([], 0, KEYS, ''))
        self.system = SimpleNamespace(platform='linux')
        self.namespace = dict(os=SimpleNamespace(environ=self.env), sys=self.system,
                              subprocess=SimpleNamespace(run=self.run, TimeoutExpired=subprocess.TimeoutExpired))
        exec(compile(ast.Module(body=[HELPER], type_ignores=[]), str(SOURCE), 'exec'), self.namespace)
        self.configure = self.namespace[HELPER.name]

    def test_affected_schema_selects_process_local_generic(self):
        self.env.update(GTK_THEME='unchanged', GTK_MODULES='unchanged', GDK_BACKEND='unchanged')
        self.assertTrue(self.configure())
        self.assertEqual(self.env['QT_QPA_PLATFORMTHEME'], 'generic')
        self.assertEqual(self.env['GTK_THEME'], 'unchanged')
        self.assertEqual(self.env['GTK_MODULES'], 'unchanged')
        self.assertEqual(self.env['GDK_BACKEND'], 'unchanged')
        self.run.assert_called_once_with(
            ['gsettings','list-keys','org.gnome.settings-daemon.plugins.xsettings'],
            capture_output=True, text=True, timeout=2, check=False)

    def test_explicit_gtk3_uses_compatibility_fallback(self):
        self.env['QT_QPA_PLATFORMTHEME'] = 'gtk3'
        self.assertTrue(self.configure())
        self.assertEqual(self.env['QT_QPA_PLATFORMTHEME'], 'generic')

    def test_explicit_non_gtk_theme_is_preserved(self):
        for theme in ('qt6ct', 'kde', 'generic', 'custom-theme'):
            with self.subTest(theme=theme):
                self.env['QT_QPA_PLATFORMTHEME'] = theme
                self.assertFalse(self.configure())
                self.assertEqual(self.env['QT_QPA_PLATFORMTHEME'], theme)
        self.run.assert_not_called()

    def test_other_platforms_are_unchanged(self):
        for platform in ('win32', 'darwin'):
            self.system.platform = platform
            self.assertFalse(self.configure())
        self.run.assert_not_called()
        self.assertNotIn('QT_QPA_PLATFORMTHEME', self.env)

    def test_other_or_unknown_desktops_are_unchanged(self):
        for desktop in ('KDE', 'XFCE', ''):
            self.env['XDG_CURRENT_DESKTOP'] = desktop
            self.assertFalse(self.configure())
        self.run.assert_not_called()

    def test_legacy_schema_with_font_key_preserves_native_theme(self):
        self.run.return_value.stdout = KEYS + 'antialiasing\n'
        self.assertFalse(self.configure())
        self.assertNotIn('QT_QPA_PLATFORMTHEME', self.env)

    def test_failed_or_unrecognized_schema_probe_does_not_override(self):
        for code, output in ((1, KEYS), (0, ''), (0, 'unrecognized-schema')):
            with self.subTest(code=code, output=output):
                self.run.return_value = subprocess.CompletedProcess([], code, output, '')
                self.assertFalse(self.configure())
                self.assertNotIn('QT_QPA_PLATFORMTHEME', self.env)

    def test_missing_or_stalled_gsettings_does_not_override(self):
        for error in (FileNotFoundError('gsettings'), subprocess.TimeoutExpired('gsettings', 2)):
            self.run.side_effect = error
            self.assertFalse(self.configure())
            self.assertNotIn('QT_QPA_PLATFORMTHEME', self.env)

    def test_policy_runs_before_qapplication_construction(self):
        main = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        calls = [n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        prepare = next(n.lineno for n in calls if n.func.id == HELPER.name)
        qt = next(n.lineno for n in calls if n.func.id == 'QApplication')
        self.assertLess(prepare, qt)
        self.assertEqual(main.body[1].value.func.id, HELPER.name)
