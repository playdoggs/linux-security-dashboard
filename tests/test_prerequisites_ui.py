"""Real Qt approval/lifecycle path in a synthetic isolated process."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class PrerequisiteUi(unittest.TestCase):
    def test_table_approval_verification_stale_results_and_shutdown(self):
        env=dict(os.environ,QT_QPA_PLATFORM='offscreen',QT_QPA_PLATFORMTHEME='generic',PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('ui_prerequisites_probe.py'))],
                              capture_output=True,text=True,env=env,timeout=25)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('active package worker retained during shutdown',result.stdout)
        self.assertIn('duplicate completion',result.stdout)
