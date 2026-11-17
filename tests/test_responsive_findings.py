"""Production Qt resizing and dialog regressions in isolated child processes."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class ResponsiveFindings(unittest.TestCase):
    def run_probe(self, case):
        env = dict(os.environ, QT_QPA_PLATFORM='offscreen', QT_QPA_PLATFORMTHEME='generic', PYTHONDONTWRITEBYTECODE='1')
        probe = Path(__file__).with_name('ui_findings_probe.py')
        result = subprocess.run([sys.executable, '-B', str(probe), '--case', case],
                                env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('passed', result.stdout)

    def test_resizing_priority_visibility_and_tooltip(self): self.run_probe('table')
    def test_search_sort_double_click_and_action_routing(self): self.run_probe('behaviour')
    def test_short_explanation_compact_and_dismissible(self): self.run_probe('short-dialog')
    def test_long_explanation_scrolls_with_close_visible(self): self.run_probe('long-dialog')

    def test_thousand_findings_resize_uses_cached_minimums(self): self.run_probe('performance')
