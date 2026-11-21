"""Real Qt keyboard/default regressions; child processes never import the app."""
import ast
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


class ConfirmationKeyboard(unittest.TestCase):
    def probe(self,case):
        env=dict(os.environ,QT_QPA_PLATFORM='offscreen',QT_QPA_PLATFORMTHEME='generic',PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run([sys.executable,'-B',str(ROOT/'tests/confirmation_keyboard_probe.py'),'--case',case],
                              env=env,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('passed',result.stdout)

    def test_preaction_default_focus_keyboard_and_content(self):self.probe('preaction')
    def test_privileged_message_default_focus_and_keyboard(self):self.probe('message')
    def test_profile_traversal_native_focus_and_keyboard(self):self.probe('profile')

    def test_all_existing_privileged_decision_sites_use_the_policy(self):
        tree=ast.parse((ROOT/'linux-security-dashboard.py').read_text())
        for cls,name in [('GuidedWizard','_run_fix'),('ToolCard','_install'),('UndoPanel','_run_undo')]:
            method=next(f for n in tree.body if isinstance(n,ast.ClassDef) and n.name==cls
                        for f in n.body if isinstance(f,ast.FunctionDef) and f.name==name)
            calls=[n for n in ast.walk(method) if isinstance(n,ast.Call)]
            self.assertTrue(any(isinstance(n.func,ast.Name) and n.func.id=='privileged_question' for n in calls),cls)
            self.assertFalse(any(isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name)
                                 and n.func.value.id=='QMessageBox' and n.func.attr=='question' for n in calls),cls)
        # Any new static question must be reviewed rather than silently skipping
        # the policy. The existing shutdown question only waits for authorized work.
        for cls in (n for n in tree.body if isinstance(n,ast.ClassDef)):
            for method in (n for n in cls.body if isinstance(n,ast.FunctionDef)):
                for call in (n for n in ast.walk(method) if isinstance(n,ast.Call)):
                    if (isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name)
                            and call.func.value.id=='QMessageBox' and call.func.attr=='question'):
                        self.assertEqual((cls.name,method.name),('AuditDashboard','closeEvent'))
