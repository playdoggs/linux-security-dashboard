"""Joint confidentiality policy through real production callers; no host commands."""
import ast
import logging
import os
import selectors
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from PyQt6.QtCore import QCoreApplication
from test_privileged_hardening import namespace
from privileged_test_support import TREE, SOURCE

PW=b'SpecimenPieceRemainder'
PREFIX=b'https://operator:SpecimenPiece'


def ns():
    result=namespace()
    for n in TREE.body:
        if getattr(n,'name',None) in ('create_timeshift_snapshot','run_drive_health_check','strip_ansi') or isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='ANSI_RE':
            exec(compile(ast.Module(body=[n],type_ignores=[]),str(SOURCE),'exec'),result)
    result['privileged_invocation']=lambda *a:(['fixture-never-executed'],{})
    result['T']={'ACCENT':'blue','WARN':'orange','TEXT_DIM':'grey'}
    return result


class PrivilegedBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QCoreApplication.instance() or QCoreApplication([])

    def test_generic_worker_split_both_orders_and_outcomes(self):
        for code in (0,2):
            for left,right in ((b'SpecimenPiece',b'Remainder'),(b'Remainder',b'SpecimenPiece')):
                with self.subTest(code=code,left=left):
                    n=ns();w=n['CommandWorker'](['systemctl','status','fixture'],sudo=True,password=PW)
                    outputs=[];errors=[];events=[]
                    w.output_ready.connect(outputs.append);w.error_ready.connect(errors.append)
                    w.finished_ok.connect(lambda:events.append('success'));w.failed.connect(lambda:events.append('failure'))
                    with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],code,left,right)),patch.object(logging,'error') as log:w.run()
                    self.assertNotIn('SpecimenPiece',str(outputs)+str(errors)+str(log.call_args_list))
                    self.assertEqual(events,['failure'])

    def test_timeshift_split_never_reaches_activity(self):
        n=ns();terminal=Mock()
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],2,b'SpecimenPiece',b'Remainder')):
            self.assertFalse(n['create_timeshift_snapshot'](PW,'fixture',terminal))
        self.assertNotIn('SpecimenPiece',str(terminal.mock_calls));self.assertNotIn('Remainder',str(terminal.mock_calls))

    def test_lynis_parser_cannot_reconstruct_normalized_secret(self):
        n=ns();method=next(m for c in TREE.body if isinstance(c,ast.ClassDef) and c.name=='LynisPanel' for m in c.body if isinstance(m,ast.FunctionDef) and m.name=='_parse_lynis_partial')
        exec(compile(ast.Module(body=[method],type_ignores=[]),str(SOURCE),'exec'),n)
        panel=SimpleNamespace(findings=Mock(),_lappend=Mock())
        from test_review_hardening import IncompletePrivilegedOutput
        fixture=IncompletePrivilegedOutput();fixture.setUpClass();self.addCleanup(fixture.doCleanups)
        value=fixture.exercise('complete',b'Warning SpecimenPiece[31mRemainder',returncode=2)
        evidence=value[0].full_output
        self.assertNotIn(PW.decode(),str(value[1:]))
        n['_parse_lynis_partial'](panel,evidence)
        self.assertNotIn(PW.decode(),str(panel.findings.mock_calls)+str(panel._lappend.mock_calls))

    def collect(self,mode='read',code=0):
        n=ns();proc=Mock();proc.stdin.closed=proc.stdout.closed=False;proc.wait.return_value=code;proc.poll.return_value=0;watches={}
        if mode=='inherited':proc.poll.side_effect=[None,0]
        class Selector:
            def register(self,stream,event):watches[stream]=SimpleNamespace(fileobj=stream)
            def unregister(self,stream):watches.pop(stream,None)
            def get_map(self):return watches
            def select(self,timeout):return [(v,None) for v in list(watches.values())]
            def close(self):
                if mode=='close':raise OSError(PREFIX.decode())
        chunks=[PREFIX,OSError(PREFIX.decode())] if mode=='read' else ([PREFIX,b''] if mode=='inherited' else ([b'X'*4096]*512+[PREFIX,b''] if mode=='overflow' else [b'safe evidence\n',b'']))
        clock=Mock(side_effect=[0,2]) if mode=='inherited' else n['time'].monotonic
        with patch.object(n['time'],'monotonic',clock),patch.object(subprocess,'Popen',return_value=proc),patch.object(selectors,'DefaultSelector',return_value=Selector()),patch.object(os,'set_blocking'),patch.object(os,'read',side_effect=chunks),patch.object(os,'write',side_effect=lambda fd,data:len(data)):
            result=n['run_package_transaction'](['apt','install','fixture'],PW,Mock())
        proc.terminate.assert_not_called();proc.kill.assert_not_called();proc.wait.assert_called_once_with()
        return n,result

    def test_package_capture_failures_discard_evidence_after_natural_exit(self):
        for mode in ('read','overflow','close','inherited'):
            for code in (0,2):
                with self.subTest(mode=mode,code=code):
                    n,result=self.collect(mode,code)
                    self.assertEqual(result['code'],code);self.assertEqual(result['output'],'')
                    self.assertFalse(result['capture_complete']);self.assertFalse(result['diagnostics_allowed'])
                    self.assertNotIn('SpecimenPiece',str(result));self.assertTrue(result['error'])

    def test_package_failure_forwarding_to_worker_and_activity_is_safe(self):
        n,result=self.collect();w=n['CommandWorker'](['apt','install','fixture'],sudo=True,password=PW);activity=Mock()
        w.output_ready.connect(activity.append);w.error_ready.connect(activity.append)
        with patch.dict(n,run_package_transaction=Mock(return_value=result)):w.run()
        # Prerequisites' Activity adapter sanitizes the same result field.
        if result['output']:activity.append(n['sanitize_diagnostic'](result['output']))
        self.assertNotIn('SpecimenPiece',str(activity.mock_calls))

    def test_real_prerequisite_completion_callback_receives_only_approved_output(self):
        n,result=self.collect()
        panel=SimpleNamespace(phase='installing',terminal=Mock(),notice=Mock(),_launch=Mock())
        n.update(self=panel,plan={},generation=1,selected=('fixture',))
        install=next(m for c in TREE.body if isinstance(c,ast.ClassDef) and c.name=='PrerequisitesPanel'
                     for m in c.body if isinstance(m,ast.FunctionDef) and m.name=='install')
        installed=next(m for m in ast.walk(install) if isinstance(m,ast.FunctionDef) and m.name=='installed')
        exec(compile(ast.Module(body=[installed],type_ignores=[]),str(SOURCE),'exec'),n)
        n['installed'](result,None)
        self.assertNotIn('SpecimenPiece',str(panel.terminal.mock_calls))
        self.assertEqual(panel.phase,'verifying');panel._launch.assert_called_once()

    def test_complete_safe_package_diagnostics_remain_usable(self):
        n,result=self.collect('complete',2)
        self.assertEqual(result['code'],2);self.assertIsNone(result['error'])
        self.assertIn('safe evidence',result['output'])
        self.assertTrue(result['capture_complete']);self.assertTrue(result['diagnostics_allowed'])

    def test_safe_generic_and_timeshift_outcomes_remain_usable(self):
        for code in (0,2):
            n=ns();terminal=Mock()
            result=subprocess.CompletedProcess([],code,b'safe stdout',b'safe stderr')
            with patch.object(subprocess,'run',return_value=result):
                self.assertEqual(n['create_timeshift_snapshot'](PW,'fixture',terminal),code==0)
                worker=n['CommandWorker'](['systemctl','status','fixture'],sudo=True,password=PW)
                out=[];errors=[];worker.output_ready.connect(out.append);worker.error_ready.connect(errors.append)
                worker.run()
            self.assertIn('safe stdout',out)
            self.assertIn('safe stderr',out if code==0 else errors)

    def test_smart_uses_joint_policy_before_finding_parser(self):
        n=ns();terminal=Mock();findings=Mock()
        n.update(prerequisite_gate=Mock(return_value=True),shutil=SimpleNamespace(which=Mock(return_value='/fixture')),
                 _list_physical_drives=Mock(return_value=['/dev/fixture']),prompt_for_sudo_password=Mock(return_value=PW),
                 SESSION=SimpleNamespace(log_scan=Mock()))
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'SpecimenPiece',b'Remainder')):
            n['run_drive_health_check'](terminal,findings,None)
        findings.add_finding.assert_not_called()
        self.assertNotIn('SpecimenPiece',str(terminal.mock_calls))

    def test_privileged_subprocess_exception_payloads_are_fixed(self):
        for target in ('generic','timeshift'):
            n=ns();terminal=Mock()
            with patch.object(subprocess,'run',side_effect=OSError(PREFIX.decode())),patch.object(logging,'error') as log:
                if target=='generic':
                    worker=n['CommandWorker'](['systemctl','status','fixture'],sudo=True,password=PW)
                    worker.error_ready.connect(terminal.append);worker.run()
                else:n['create_timeshift_snapshot'](PW,'fixture',terminal)
            self.assertNotIn('SpecimenPiece',str(terminal.mock_calls)+str(log.call_args_list))

    def test_significant_whitespace_boundary_both_orders_and_worker_surfaces(self):
        for password,left,right in ((b'alpha beta',b'alpha ',b'\nbeta'),
                                    (b'alpha beta',b'alpha',b'\n beta'),
                                    (b'alpha\tbeta',b'alpha\t',b'\nbeta'),
                                    (b'alpha beta',b'alpha \x1b[0m',b'\nbeta')):
            for a,b in ((left,right),(right,left)):
                for code in (0,2):
                    with self.subTest(password=password,a=a,code=code):
                        n=ns();worker=n['CommandWorker'](['systemctl','status','fixture'],sudo=True,password=password)
                        activity=Mock();events=[];worker.output_ready.connect(activity.append);worker.error_ready.connect(activity.append)
                        worker.finished_ok.connect(lambda:events.append('success'));worker.failed.connect(lambda:events.append('failure'))
                        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],code,a,b)),patch.object(logging,'error') as log:
                            worker.run()
                        self.assertEqual(events,['failure'])
                        self.assertNotIn('alpha',str(activity.mock_calls)+str(log.mock_calls))
                        capture=n['privileged_capture'](a,b,password)
                        self.assertFalse(capture['allowed']);self.assertEqual(capture['stdout'],'');self.assertEqual(capture['stderr'],'')

    def test_boundary_policy_does_not_invent_required_whitespace(self):
        for password,left,right in ((b'alpha beta',b'alpha',b'\nbeta'),
                                    (b'alpha  beta',b'alpha ',b'\nbeta'),
                                    (b'alpha\tbeta',b'alpha ',b'\nbeta')):
            with self.subTest(password=password):
                self.assertTrue(ns()['privileged_capture'](left,right,password)['allowed'])

    def test_whitespace_split_streaming_capture_has_no_retained_or_emitted_fragments(self):
        from test_review_hardening import IncompletePrivilegedOutput
        for left, right in ((b'alpha ', b'\nbeta'), (b'\nbeta', b'alpha ')):
            for code in (0, 2):
                with self.subTest(left=left, code=code):
                    fixture = IncompletePrivilegedOutput()
                    fixture.setUpClass()
                    fixture.PASSWORD = b'alpha beta'
                    try:
                        worker, outputs, errors, events, logs, activity = fixture.exercise(
                            'complete', left, stderr_payload=right, returncode=code)
                        self.assertEqual(worker.full_output, '')
                        self.assertEqual(events, ['failure'])
                        self.assertTrue(all(value == 'Privileged scan output received; incomplete captures will be discarded.'
                                            for value in outputs))
                        for surface in (outputs, errors, logs, activity):
                            self.assertNotIn('alpha', str(surface))
                            self.assertNotIn('beta', str(surface))
                    finally:
                        fixture.doCleanups()

    def test_derived_partial_finding_is_suppressed_before_publication(self):
        n=ns();method=next(m for c in TREE.body if isinstance(c,ast.ClassDef) and c.name=='LynisPanel' for m in c.body if isinstance(m,ast.FunctionDef) and m.name=='_parse_lynis_partial')
        exec(compile(ast.Module(body=[method],type_ignores=[]),str(SOURCE),'exec'),n)
        # Exercise the original method before it has a credential-context argument.
        import inspect
        accepts_context='password' in inspect.signature(n['_parse_lynis_partial']).parameters
        for password in (b'observation: warning Zebra42',b'observation: suggestion Zebra42'):
            line='warning Zebra42' if b'warning' in password else 'suggestion Zebra42'
            panel=SimpleNamespace(findings=Mock(),_lappend=Mock())
            args={'password':password} if accepts_context else {}
            with patch.object(logging,'error') as log:
                n['_parse_lynis_partial'](panel,line,**args)
            panel.findings.add_finding.assert_not_called()
            self.assertNotIn(password.decode(),str(panel._lappend.mock_calls)+str(log.mock_calls))

    def test_safe_partial_findings_survive_with_credential_context(self):
        n=ns();method=next(m for c in TREE.body if isinstance(c,ast.ClassDef) and c.name=='LynisPanel' for m in c.body if isinstance(m,ast.FunctionDef) and m.name=='_parse_lynis_partial')
        exec(compile(ast.Module(body=[method],type_ignores=[]),str(SOURCE),'exec'),n)
        import inspect
        args={'password':b'unrelated synthetic credential'} if 'password' in inspect.signature(n['_parse_lynis_partial']).parameters else {}
        panel=SimpleNamespace(findings=Mock(),_lappend=Mock())
        n['_parse_lynis_partial'](panel,'warning useful issue\nsuggestion useful advice',**args)
        self.assertEqual(panel.findings.add_finding.call_count,2)


if __name__=='__main__':unittest.main()
