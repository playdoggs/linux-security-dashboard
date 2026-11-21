"""H03/H05/H16: production boundaries, fake transactions, no real elevation."""
import ast
import io
import logging
import os
import selectors
import subprocess
import time
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication, QThread, pyqtSignal
from privileged_test_support import SOURCE, TREE, install_helpers


def namespace():
    ns = dict(QThread=QThread, pyqtSignal=pyqtSignal, strip_ansi=lambda s:s)
    install_helpers(ns, transaction_stub=False, trusted_stub=False)
    for node in TREE.body:
        if getattr(node, 'name', None) in {'CommandWorker', 'StreamingCommandWorker', 'PrerequisiteJob',
                                        'parse_prerequisite_simulation', 'prerequisite_redact'}:
            exec(compile(ast.Module(body=[node],type_ignores=[]), str(SOURCE), 'exec'), ns)
    return ns


class DiagnosticHardening(unittest.TestCase):
    def setUp(self): self.ns=namespace();self.clean=self.ns['sanitize_diagnostic']

    def test_url_credentials_queries_fragments_and_encoded_urls(self):
        for raw in ('https://operator:privatevalue@example.test/repo?unknown=privatevalue#privatevalue',
                    'HTTPS://operator:p%40ss@example.test/repo?token=privatevalue',
                    'https%3A%2F%2Foperator%3Aprivatevalue%40example.test%2Frepo'):
            text=self.clean('APT could not fetch '+raw)
            self.assertNotIn('privatevalue',text);self.assertNotIn('operator:',text)
            self.assertIn('APT could not fetch',text)
        self.assertIn('example.test/repo',self.clean('https://operator:privatevalue@example.test/repo'))

    def test_auth_headers_keys_cli_and_json(self):
        for raw in ('Authorization: Bearer privatevalue', 'Proxy-Authorization: Basic privatevalue',
                    'Cookie: session=privatevalue', 'Set-Cookie: session=privatevalue',
                    'token=privatevalue', 'access_token: privatevalue', 'API-Key=privatevalue',
                    '{"client_secret":"privatevalue"}', '--password privatevalue',
                    'Bearer privatevalue', 'username=privatevalue', 'AWS_SECRET_ACCESS_KEY=privatevalue', 'auth=privatevalue'):
            with self.subTest(raw=raw):self.assertNotIn('privatevalue',self.clean(raw))

    def test_password_private_key_controls_and_safe_diagnostics(self):
        raw='secretstdin\n-----BEGIN OPENSSH PRIVATE KEY-----\nprivatevalue\n-----END OPENSSH PRIVATE KEY-----\n\x1b[31mE: download failed\x00'
        result=self.clean(raw,b'secretstdin')
        for forbidden in ('secretstdin','privatevalue','\x1b','\x00'):self.assertNotIn(forbidden,result)
        self.assertIn('E: download failed',result)
        self.assertEqual(self.clean('E: package not found\nW: repository temporarily offline'),
                         'E: package not found\nW: repository temporarily offline')

    def test_unexpected_parser_errors_do_not_display_opaque_payload(self):
        job=self.ns['PrerequisiteJob'](lambda: (_ for _ in ()).throw(RuntimeError('privatevalue')))
        job.run();self.assertNotIn('privatevalue',job.error);self.assertIn('RuntimeError',job.error)
        self.assertIsNone(job.function)

    def test_parser_rejection_does_not_copy_input(self):
        with self.assertRaises(ValueError) as caught:
            self.ns['parse_prerequisite_simulation']('Inst lynis (1 Ubuntu [amd64])\nprivatevalue')
        self.assertNotIn('privatevalue',str(caught.exception))

    def test_logging_filter_redacts_traceback_and_format_args(self):
        output=io.StringIO();handler=logging.StreamHandler(output)
        handler.addFilter(self.ns['DiagnosticFilter']())
        logger=logging.Logger('synthetic');logger.addHandler(handler)
        try:raise RuntimeError('privatevalue')
        except RuntimeError:logger.error('APT token=%s','privatevalue',exc_info=True)
        self.assertNotIn('privatevalue',output.getvalue());self.assertIn('RuntimeError',output.getvalue())

    def test_logging_without_active_exception_cannot_break_failure_handling(self):
        record=logging.LogRecord('synthetic',logging.ERROR,'fixture',1,'token=%s',('privatevalue',),(None,None,None))
        record.exc_text='privatevalue';record.stack_info='privatevalue'
        self.assertTrue(self.ns['DiagnosticFilter']().filter(record))
        self.assertNotIn('privatevalue',record.getMessage())
        self.assertIsNone(record.exc_info);self.assertIsNone(record.exc_text);self.assertIsNone(record.stack_info)

    def test_bad_string_and_oversized_diagnostic_fail_safely(self):
        class Broken:
            def __str__(self):raise RuntimeError('privatevalue')
        self.assertEqual(self.clean(Broken()),'[Diagnostic unavailable]')
        text=self.clean('x'*70000+'\ntoken=privatevalue')
        self.assertLess(len(text),65600);self.assertNotIn('privatevalue',text)


class PrivilegedArguments(unittest.TestCase):
    def setUp(self): self.ns=namespace()

    def test_resolution_ignores_user_path_and_rejects_unsafe_system_file(self):
        trust=Mock(return_value=(True,'protected'))
        with patch.dict(os.environ,PATH='/tmp/attacker'),patch.object(os.path,'lexists',side_effect=lambda p:p=='/usr/bin/apt'),patch.dict(self.ns,executable_trust=trust):
            self.assertEqual(self.ns['resolve_privileged_executable']('apt'),'/usr/bin/apt')
        trust.assert_called_once_with('/usr/bin/apt')
        with patch.object(os.path,'lexists',return_value=True),patch.dict(self.ns,executable_trust=Mock(return_value=(False,'unsafe'))):
            with self.assertRaisesRegex(ValueError,'Untrusted'):self.ns['resolve_privileged_executable']('apt')

    def test_paths_options_relative_and_malformed_programs_rejected(self):
        for value in ('/tmp/apt','./apt','../bin/apt','/usr/bin/../bin/apt','-apt','apt\n',None):
            with self.subTest(value=value),patch.object(os.path,'lexists',return_value=False):
                with self.assertRaises((ValueError,FileNotFoundError)):self.ns['resolve_privileged_executable'](value)

    def test_clean_env_structured_argv_preserves_quoted_arguments(self):
        self.ns['resolve_privileged_executable']=lambda p:'/usr/bin/'+p.rsplit('/',1)[-1]
        argv=['systemctl','disable','name with spaces']
        with patch.dict(os.environ,APT_CONFIG='/tmp/hostile',LD_PRELOAD='/tmp/hostile'):
            full,env=self.ns['privileged_invocation'](argv,b'credential')
        self.assertEqual(full[-3:],['/usr/bin/systemctl','disable','name with spaces'])
        self.assertEqual(argv,['systemctl','disable','name with spaces'])
        self.assertIn('--',full);self.assertIn('-i',full)
        self.assertNotIn('APT_CONFIG',env);self.assertNotIn('LD_PRELOAD',env)
        self.assertEqual(self.ns['command_argv']('systemctl disable "name with spaces"'),argv)
        with self.assertRaises(ValueError):self.ns['privileged_invocation']('apt install example',b'x')
        for password in (b'a\nb',b'a\rb',b'x\x00',b'x'*4097,'not bytes'):
            with self.assertRaises(ValueError):self.ns['privileged_invocation'](['apt','install','example'],password)

    def test_dispatch_uses_protected_argv_not_user_path(self):
        self.ns['resolve_privileged_executable']=lambda p:'/usr/bin/'+p.rsplit('/',1)[-1]
        worker=self.ns['CommandWorker'](['systemctl','status','example'],sudo=True)
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
            worker.run()
        self.assertEqual(run.call_args.args[0][0],'/usr/bin/sudo')
        self.assertEqual(run.call_args.args[0][-3:],['/usr/bin/systemctl','status','example'])
        self.assertNotIn('APT_CONFIG',run.call_args.kwargs['env'])

    def test_cancelled_remediation_does_not_create_worker_or_modify_findings(self):
        from test_command_outcomes import method, NS
        obj=SimpleNamespace(terminal=Mock(),_start_worker=Mock(),_verify=Mock())
        with patch.dict(NS,prompt_for_sudo_password=Mock(return_value=None),CommandWorker=Mock()) as ignored:
            method('FindingsTable','_act')(obj,'apt purge example','example','remove','LOW')
            NS['CommandWorker'].assert_not_called()
        obj._start_worker.assert_not_called();obj._verify.assert_not_called()

    def test_transaction_backends_and_shells_use_no_kill_policy(self):
        for program in ('apt','apt-get','dpkg','dpkg-reconfigure','dnf','yum','pacman','rpm','sh','bash','dash','zsh','ksh'):
            self.assertTrue(self.ns['package_transaction'](['/usr/bin/'+program,'arg']))
        self.assertFalse(self.ns['package_transaction'](['systemctl','status','example']))

    def test_streaming_rejects_transaction_before_process_creation(self):
        for program in ('apt','dnf','sh'):
            worker=self.ns['StreamingCommandWorker']([program,'arg'],sudo=True,password=b'x')
            events=[];worker.failed.connect(lambda:events.append('failure'));worker.finished_ok.connect(lambda:events.append('success'))
            with patch.object(subprocess,'Popen') as start,patch.object(logging,'error'):worker.run()
            start.assert_not_called();self.assertEqual(events,['failure'])


class TransactionOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app=QCoreApplication.instance() or QCoreApplication([])
    def setUp(self):
        self.ns=namespace()
        self.ns['resolve_privileged_executable']=lambda p:'/usr/bin/'+p.rsplit('/',1)[-1]

    def test_all_legacy_package_workers_delegate_without_generic_timeout(self):
        for command in (['apt','purge','example'],['dpkg-reconfigure','-plow','unattended-upgrades'],['dnf','install','example'],['pacman','-S','example'],['sh','-c','apt install example']):
            worker=self.ns['CommandWorker'](command,sudo=True,password=b'privatevalue',timeout=.001)
            success=[];worker.finished_ok.connect(lambda:success.append(True))
            collect=Mock(return_value=dict(code=0,error=None,output='verified output'))
            with patch.dict(self.ns,run_package_transaction=collect),patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
                worker.run()
            run.assert_not_called();collect.assert_called_once();self.assertEqual(success,[True])

    def test_generic_and_stream_errors_sanitized_before_signals_and_logging(self):
        for cls in ('CommandWorker','StreamingCommandWorker'):
            worker=self.ns[cls](['systemctl','status','example'],sudo=True,password=b'privatevalue')
            errors=[];events=[];worker.error_ready.connect(errors.append)
            worker.failed.connect(lambda:events.append('failure'));worker.finished_ok.connect(lambda:events.append('success'))
            method='run' if cls=='CommandWorker' else 'Popen'
            with patch.object(subprocess,method,side_effect=RuntimeError('privatevalue')),patch.object(logging,'error') as log:
                worker.run()
            self.assertEqual(events,['failure']);self.assertNotIn('privatevalue',' '.join(errors))
            self.assertNotIn('privatevalue',str(log.call_args))

    def test_recovery_waits_naturally_after_selector_or_progress_failure(self):
        for error in (OSError('https://u:privatevalue@example.test/repo'),RuntimeError('privatevalue')):
            process=Mock();process.stdin.closed=process.stdout.closed=False
            process.poll.side_effect=[None,None,0];process.wait.return_value=0
            with patch.object(subprocess,'Popen',return_value=process) as start,patch.object(selectors,'DefaultSelector',side_effect=error),patch.object(os,'read',return_value=b''),patch.object(os,'set_blocking'),patch.object(time,'sleep') as sleep:
                result=self.ns['run_package_transaction'](['apt','install','example'],b'privatevalue',Mock())
            self.assertNotIn('privatevalue',result['error']);self.assertTrue(result['error'])
            self.assertEqual(sleep.call_count,2)
            process.kill.assert_not_called();process.terminate.assert_not_called()
            process.wait.assert_called_once_with();self.assertNotIn('timeout',start.call_args.kwargs)

    def test_actual_collector_drains_redacts_and_reaps_with_bounded_progress(self):
        process=Mock();process.stdin.closed=process.stdout.closed=False
        process.poll.return_value=None;process.wait.return_value=0;watches={}
        class Selector:
            def register(self,stream,event):watches[stream]=SimpleNamespace(fileobj=stream)
            def unregister(self,stream):del watches[stream]
            def get_map(self):return watches
            def select(self,timeout):return [(k,None) for k in list(watches.values())]
            def close(self):pass
        chunks=[b'E: https://user:private',b'value@example.test/repo?token=privatevalue\n',b'']
        progress=Mock()
        with patch.object(subprocess,'Popen',return_value=process),patch.object(selectors,'DefaultSelector',return_value=Selector()),patch.object(os,'set_blocking'),patch.object(os,'write',side_effect=lambda fd,data:len(data)),patch.object(os,'read',side_effect=chunks):
            result=self.ns['run_package_transaction'](['apt','install','example'],b'privatevalue',progress)
        self.assertEqual(result['code'],0);self.assertIsNone(result['error'])
        self.assertNotIn('privatevalue',result['output']);self.assertIn('example.test/repo',result['output'])
        self.assertNotIn('privatevalue',str(progress.call_args_list))
        process.kill.assert_not_called();process.terminate.assert_not_called();process.wait.assert_called_once_with()

    def test_progress_exception_waits_for_active_transaction(self):
        process=Mock();process.stdin.closed=process.stdout.closed=False
        process.poll.side_effect=[None,None,0];process.wait.return_value=0;watches={}
        class Selector:
            def register(self,stream,event):watches[stream]=SimpleNamespace(fileobj=stream)
            def unregister(self,stream):watches.pop(stream,None)
            def get_map(self):return watches
            def select(self,timeout):return [(k,None) for k in list(watches.values())]
            def close(self):pass
        with patch.object(subprocess,'Popen',return_value=process),patch.object(selectors,'DefaultSelector',return_value=Selector()),patch.object(os,'set_blocking'),patch.object(os,'read',return_value=b'output'),patch.object(time,'sleep') as sleep:
            value=self.ns['run_package_transaction'](['apt','install','example'],b'privatevalue',Mock(side_effect=RuntimeError('privatevalue')))
        self.assertIn('RuntimeError',value['error']);self.assertNotIn('privatevalue',str(value))
        sleep.assert_called_once_with(.05);process.wait.assert_called_once_with()
        process.kill.assert_not_called();process.terminate.assert_not_called()

    def test_cached_authentication_has_no_stdin_pipe_or_prompt(self):
        process=Mock();process.stdin=None;process.stdout.closed=False
        process.poll.return_value=0;process.wait.return_value=0;watches={}
        class Selector:
            def register(self,stream,event):watches[stream]=SimpleNamespace(fileobj=stream)
            def unregister(self,stream):del watches[stream]
            def get_map(self):return watches
            def select(self,timeout):return [(k,None) for k in list(watches.values())]
            def close(self):pass
        with patch.object(subprocess,'Popen',return_value=process) as start,patch.object(selectors,'DefaultSelector',return_value=Selector()),patch.object(os,'set_blocking'),patch.object(os,'read',return_value=b''),patch.object(os,'write') as write:
            result=self.ns['run_package_transaction'](['apt','install','example'],None,Mock())
        self.assertEqual(result['code'],0);self.assertIsNone(result['error'])
        self.assertEqual(start.call_args.args[0][:2],['/usr/bin/sudo','-n'])
        self.assertEqual(start.call_args.kwargs['stdin'],subprocess.DEVNULL);write.assert_not_called()

    def test_privileged_live_chunks_cannot_disclose_partial_credentials(self):
        worker=self.ns['StreamingCommandWorker'](['lynis','audit','system'],sudo=True,password=b'privatevalue')
        worker._progress_updates=0;output=[];worker.output_ready.connect(output.append)
        worker._emit_progress('https://user:private');worker._emit_progress('value@example.test/repo')
        self.assertEqual(len(output),2)
        self.assertTrue(all(line=='Privileged scan output received; incomplete captures will be discarded.' for line in output))

    def test_transaction_setup_failure_cannot_escape_diagnostics(self):
        worker=self.ns['CommandWorker'](['apt','install','example'],sudo=True,password=b'privatevalue')
        errors=[];events=[];worker.error_ready.connect(errors.append)
        worker.failed.connect(lambda:events.append('failure'));worker.finished_ok.connect(lambda:events.append('success'))
        with patch.object(subprocess,'Popen',side_effect=OSError('https://user:privatevalue@example.test/repo?token=privatevalue')),patch.object(logging,'error') as log:
            worker.run()
        self.assertEqual(events,['failure'])
        self.assertNotIn('privatevalue',' '.join(errors));self.assertNotIn('privatevalue',str(log.call_args))

    def test_transaction_io_failure_cannot_be_success_even_if_child_exits_zero(self):
        worker=self.ns['CommandWorker'](['apt','install','example'],sudo=True)
        events=[];worker.failed.connect(lambda:events.append('failure'));worker.finished_ok.connect(lambda:events.append('success'))
        with patch.dict(self.ns,run_package_transaction=Mock(return_value=dict(code=0,error='Pipe failure',output=''))):worker.run()
        self.assertEqual(events,['failure'])

    def test_pre_dispatch_resolution_failure_never_starts_child(self):
        self.ns['resolve_privileged_executable']=Mock(side_effect=ValueError('Untrusted executable'))
        worker=self.ns['CommandWorker'](['apt','install','example'],sudo=True)
        events=[];worker.failed.connect(lambda:events.append(True))
        with patch.object(subprocess,'Popen') as start,patch.object(subprocess,'run') as run,patch.object(logging,'error'):worker.run()
        start.assert_not_called();run.assert_not_called();self.assertEqual(events,[True])

    def test_transaction_worker_remains_owned_through_shutdown_and_stale_callbacks(self):
        # Real CommandWorker/QThread, production ownership and close methods;
        # only the package process body is replaced by a finite gate.
        from test_shutdown_http import Shutdown
        from test_command_outcomes import NS as callbacks, method
        fixture=Shutdown();fixture.setUp()
        gate=threading.Event();entered=threading.Event()
        worker=self.ns['CommandWorker'](['apt','install','example'],sudo=True,password=b'privatevalue',timeout=.001)
        def transaction(*args):
            entered.set()
            if not gate.wait(2):raise RuntimeError('fixture gate expired')
            return dict(code=0,error=None,output='transaction completed')
        owner=fixture.owner
        token=owner.enter('Approved package transaction')
        seen=[]
        guarded=callbacks['scan_slot'](fixture.case.panel,worker,seen.append,success=False,once=False)
        worker.output_ready.connect(guarded)
        try:
            with patch.dict(self.ns,run_package_transaction=transaction):
                method('WorkerMixin','_start_worker')(fixture.case.panel,worker)
                owner.leave(token)
                self.assertTrue(entered.wait(1))
                fixture.request().ignore.assert_called_once()
                fixture.window._check_shutdown()
                fixture.window.close.assert_not_called()
                self.assertIn(worker,owner.workers)
                self.assertEqual(worker.password,b'privatevalue')
                self.assertFalse(fixture.case.sidebar._scan_network())
                gate.set();self.assertTrue(worker.wait(2000));self.app.processEvents()
                fixture.window._check_shutdown()
                fixture.window.close.assert_called_once()
                self.assertNotIn(worker,owner.workers)
                self.assertEqual(seen,['transaction completed'])
                guarded('stale token=privatevalue');guarded('duplicate')
                self.assertEqual(seen,['transaction completed'])
        finally:
            gate.set()
            try:worker.wait(2500)
            except RuntimeError:pass
            fixture.doCleanups()


if __name__=='__main__':unittest.main()
