"""Stage 4D evidence/coverage/reporting tests. All subprocesses and widgets mocked."""
import ast
import html
import os
import datetime
from types import SimpleNamespace, MethodType
import subprocess
import unittest
from unittest.mock import Mock, patch

from test_command_outcomes import NS, TREE, method, load_definition
import test_assessment_sequence as sequence
ManualWorker = sequence.ManualWorker
NS.setdefault('os', os)

for node in TREE.body:
    name = node.name if isinstance(node, ast.FunctionDef) else None
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        name = node.targets[0].id
    if name in {'run_quick_checks','run_temperature_check','_SENSORS_LINE_RE', '_build_exec_statement', '_render_finding_rows'}:
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<production>','exec'),NS)


def coverage(state='succeeded', index=None):
    rows=[{'name':name,'outcome':'succeeded'} for name in NS['ASSESSMENT_STEPS']]
    if index is not None:
        rows[index]['outcome']=state
    return {'id':'fixture','active':False,'outcomes':rows}


class AssessmentCoverage(unittest.TestCase):
    def setUp(self):
        self.terminal=Mock()
        self.findings=Mock()

    def test_complete_without_findings_and_with_findings(self):
        value=coverage()
        self.assertTrue(NS['assessment_complete'](value))
        self.assertIn('Complete assessment — no findings detected', NS['assessment_verdict'](value,0))
        self.assertIn('Complete assessment — findings need attention', NS['assessment_verdict'](value,1))

    def test_every_incomplete_state_blocks_complete_verdict(self):
        for state in ('partial','failed','skipped','cancelled','unknown','completed'):
            with self.subTest(state=state):
                value=coverage(state,3)
                self.assertFalse(NS['assessment_complete'](value))
                text=NS['assessment_verdict'](value,0)
                self.assertIn('Incomplete assessment',text)
                self.assertNotIn('healthy',text)
                self.assertIn('Incomplete assessment — findings',NS['assessment_verdict'](value,2))

    def test_unknown_or_failed_entire_assessment_is_not_clean(self):
        for value in (None, {}, {'active':False,'outcomes':[]},
                      {'active':False,'outcomes':[{'name':name,'outcome':'failed'} for name in NS['ASSESSMENT_STEPS']]}):
            self.assertIn('failed or coverage is unknown', NS['assessment_verdict'](value,0))
            self.assertFalse(NS['assessment_complete'](value))

    def test_missing_duplicate_wrong_order_or_active_steps_cannot_be_complete(self):
        for mode in ('missing','duplicate','order','active'):
            value=coverage()
            if mode=='missing':value['outcomes'].pop()
            if mode=='duplicate':value['outcomes'][1]=dict(value['outcomes'][0])
            if mode=='order':value['outcomes'].reverse()
            if mode=='active':value['active']=True
            self.assertFalse(NS['assessment_complete'](value))

    def test_banner_cannot_recover_after_failure_from_later_success(self):
        display=SimpleNamespace(_ok_banner=Mock())
        for name in ('set_assessment_coverage','show_all_ok_banner','hide_all_ok_banner'):
            setattr(display,name,MethodType(method('FindingsTable',name),display))
        sidebar=SimpleNamespace(findings=display,_pending_section_action=None)
        with patch.dict(NS,RISK=SimpleNamespace(findings=[])):
            display.set_assessment_coverage(coverage('failed',0))
            method('SideBar','_post_scan_check')(sidebar)
            display._ok_banner.setVisible.assert_called_with(False)
            display.set_assessment_coverage(coverage())
            display._ok_banner.setVisible.assert_called_with(True)
            cves=coverage()
            cves['outcomes'][5]['findings']=1
            display.set_assessment_coverage(cves)
            display._ok_banner.setVisible.assert_called_with(False)
            NS['RISK'].findings=['LOW']
            display.show_all_ok_banner()
            display._ok_banner.setVisible.assert_called_with(False)

    def test_summary_and_report_share_coverage_verdict_and_escape_reasons(self):
        value=coverage('skipped',5)
        value['outcomes'][5]['reason']='<script>not trusted</script>'
        summary=SimpleNamespace(coverage=value)
        text=method('RunEverythingSummaryDialog','_verdict_text')(summary,0,0,0,0)
        self.assertIn('Incomplete assessment',text)
        with patch.dict(NS,html=html):
            report=NS['_build_exec_statement'](0,0,0,0,0,value)
        self.assertIn('Incomplete assessment',report)
        self.assertNotIn('<script>',report)
        self.assertIn('&lt;script&gt;',report)

    def test_executive_and_technical_exports_keep_incomplete_coverage(self):
        generate=load_definition(next(n for n in TREE.body if isinstance(n,ast.FunctionDef) and n.name=='generate_report'))
        value=coverage('failed',0)
        display=SimpleNamespace(_assessment_coverage=value)
        risk=SimpleNamespace(score=lambda:0, findings=[])
        with patch.dict(NS,html=html,datetime=datetime,RISK=risk,PROFILES={},TOOLS_DATA=[],UNDO_LOG=[],
                        get_system_info=lambda:{k:'fixture' for k in ('hostname','os','kernel','arch','cpu','ram','uptime')},
                        _collect_findings_by_section=lambda f:{'scan':[],'checks':[],'cve':[],'info':[]},
                        L=lambda key:key):
            for mode in ('executive','technical'):
                report=generate(display,'fixture',mode)
                self.assertIn('Incomplete assessment',report)
                self.assertNotIn('great shape',report)
                self.assertNotIn('mostly healthy',report)

    def test_cve_findings_remain_visible_independent_of_risk_score(self):
        value=coverage()
        value['outcomes'][5]['findings']=2
        self.assertIn('findings need attention',NS['assessment_verdict'](value,0))
        self.assertIn('2 CVE records',NS['assessment_details'](value))

    def test_package_probe_distinguishes_absent_from_error(self):
        cases=[(subprocess.CompletedProcess([],0,'ii \t1.0',''),(True,'1.0')),
               (subprocess.CompletedProcess([],1,'','dpkg-query: no packages found matching example'),(False,None)),
               (subprocess.CompletedProcess([],2,'','database unavailable'),(None,None)),
               (subprocess.CompletedProcess([],0,'garbage',''),(None,None))]
        for result,expected in cases:
            with patch.object(subprocess,'run',return_value=result),patch.dict(NS,PKG_MGR='apt'):
                self.assertEqual(NS['probe_package']('example'),expected)
        for exc in (FileNotFoundError(),subprocess.TimeoutExpired('fake',5)):
            with patch.object(subprocess,'run',side_effect=exc):
                self.assertEqual(NS['probe_package']('example'),(None,None))

    def quick(self, fail=None, insecure=False, directive_output=None, directive="PermitRootLogin"):
        def run(cmd,**kwargs):
            if cmd==fail:raise subprocess.TimeoutExpired('fake',5)
            output={('grep','PermitRootLogin'):'PermitRootLogin yes' if insecure else 'PermitRootLogin no',
                    ('grep','PasswordAuthentication'):'PasswordAuthentication yes' if insecure else 'PasswordAuthentication no'}
            if cmd[0]=='grep':
                text=directive_output if directive_output is not None and cmd[2]==directive else output[(cmd[0],cmd[2])]
            elif cmd[0]=='systemctl':text='active'
            elif cmd[0]=='dpkg':text='ii  unattended-upgrades 1.0 all description'
            elif cmd[0]=='ls':text='-rw-r--r-- 1 root root 1 /etc/passwd'
            elif cmd[1]=='fs.suid_dumpable':text='fs.suid_dumpable = 0'
            else:text='kernel.randomize_va_space = 2'
            return subprocess.CompletedProcess(cmd,0,text,'')
        with patch.dict(NS,SESSION=Mock(),T={'ACCENT':'blue','DANGER':'red','WARN':'yellow','TEXT_DIM':'grey'}),patch.object(subprocess,'run',side_effect=run):
            return NS['run_quick_checks'](self.terminal,self.findings,with_coverage=True)

    def test_quick_check_insecure_setting_is_finding_not_missing_coverage(self):
        result=self.quick(insecure=True)
        self.assertEqual(result['outcome'],'succeeded')
        rows=[call.args for call in self.findings.add_finding.call_args_list]
        self.assertEqual(sum(row[2]=='MEDIUM' for row in rows),2)

    def test_quick_timeout_and_unrecognized_results_are_incomplete(self):
        result=self.quick(fail=['sysctl','fs.suid_dumpable'])
        self.assertEqual(result['outcome'],'partial')
        self.assertIn('7/8',result['reason'])
        with patch.dict(NS,SESSION=Mock(),T={'ACCENT':'blue'}),patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,'unrecognized','')):
            result=NS['run_quick_checks'](self.terminal,self.findings,with_coverage=True)
        self.assertNotEqual(result['outcome'],'succeeded')

    def test_findings_survive_later_quick_check_timeout(self):
        result=self.quick(fail=['sysctl','fs.suid_dumpable'],insecure=True)
        self.assertEqual(result['outcome'],'partial')
        self.assertEqual(sum(call.args[2]=='MEDIUM' for call in self.findings.add_finding.call_args_list),2)
        self.findings.clear_findings.assert_not_called()

    def test_ssh_directive_evidence_regression(self):
        for directive in ('PermitRootLogin','PasswordAuthentication'):
            for output,state,risk in [
                (f'{directive} no','succeeded','INFO'),
                (f'{directive} yes','succeeded','MEDIUM'),
                (f'{directive} yes\n{directive} no','partial',None),
                (f'{directive} no\n{directive} yes','partial',None),
                (f'{directive} no\n{directive} no','succeeded','INFO'),
                (f'{directive} prohibit-password', 'succeeded' if directive=='PermitRootLogin' else 'partial',
                 'INFO' if directive=='PermitRootLogin' else None),
                (f'{directive} NO\n{directive} no','succeeded','INFO'),
                (f'  {directive} no # explicit setting\n# {directive} yes','succeeded','INFO'),
                ('','partial',None),
                (f'{directive} no unexpected tokens','partial',None),
                (f'{directive} nonsense','partial',None),
            ]:
                with self.subTest(directive=directive,output=output):
                    self.terminal.reset_mock()
                    self.findings.reset_mock()
                    result=self.quick(directive_output=output,directive=directive)
                    self.assertEqual(result['outcome'],state)
                    name='SSH '+directive+' disabled'
                    rows=[call.args for call in self.findings.add_finding.call_args_list if call.args[0]==name]
                    self.assertEqual([row[2] for row in rows], [] if risk is None else [risk])
                    if risk is None:
                        self.assertFalse(any(name in call.args[0] for call in self.terminal.append_ok.call_args_list))
                        value=coverage()
                        value['outcomes'][3].update(result)
                        self.assertFalse(NS['assessment_complete'](value))
                        self.assertIn('Incomplete assessment', NS['assessment_verdict'](value,0))

    def test_temperature_diagnostics_evidence_regression(self):
        cases=[
            (0,'Core: +45.0°C','','succeeded',1),
            (0,'Core: +45.0°C','ERROR: Cannot read another temperature sensor','partial',1),
            (0,'','ERROR: Cannot read another temperature sensor','failed',0),
            (0,'Core: +45.0°C','WARNING: using default limits','succeeded',1),
            (0,'Core: +45.0°C','Warning: unable to read sensor temp2','partial',1),
            (1,'Core: +45.0°C','','partial',1),
            (1,'','sensor command failed','failed',0),
            (0,'Core: +95.0°C','ERROR: Cannot read another temperature sensor','partial',1),
        ]
        for code,stdout,stderr,state,count in cases:
            with self.subTest(code=code,stderr=stderr):
                self.findings.reset_mock()
                with patch.dict(NS,shutil=SimpleNamespace(which=lambda n:'fake'),SESSION=Mock(),
                                T={'ACCENT':'blue','DANGER':'red','WARN':'yellow','TEXT_DIM':'grey'}), \
                        patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],code,stdout,stderr)) as run:
                    result=NS['run_temperature_check'](self.terminal,self.findings,with_coverage=True)
                self.assertEqual(run.call_args.kwargs['env']['LC_ALL'],'C')
                self.assertEqual(result['outcome'],state)
                self.assertEqual(self.findings.add_finding.call_count,count)
                if stdout=='Core: +95.0°C':
                    self.assertEqual(self.findings.add_finding.call_args.args[2],'MEDIUM')
                if state!='succeeded':
                    value=coverage()
                    value['outcomes'][4].update(result)
                    self.assertFalse(NS['assessment_complete'](value))
                    self.assertIn('Incomplete assessment',NS['assessment_verdict'](value,count))
                self.findings.clear_findings.assert_not_called()

    def test_sensor_read_failure_wording_regression(self):
        messages=[
            'WARNING: sensor temp2_input read failed',
            'ERROR: Cannot read another temperature sensor',
            'Sensor reading failed',
            'Failed reading sensor',
            'Failed to read sensor',
            'Unable to read sensor',
            'warning: temp2_input: READING \t FAILED',
            'Warning: Failed \t to \t read sensor temp3_input',
            'Warning: read \t error on sensor temp4_input',
        ]
        for message in messages:
            for stdout in ('Core: +45.0°C','Core: +95.0°C',''):
                with self.subTest(message=message,stdout=stdout):
                    self.findings.reset_mock()
                    with patch.dict(NS,shutil=SimpleNamespace(which=lambda n:'fake'),SESSION=Mock(),
                                    T={'ACCENT':'blue','DANGER':'red','WARN':'yellow'}), \
                            patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout,message)) as run:
                        result=NS['run_temperature_check'](self.terminal,self.findings,with_coverage=True)
                    self.assertEqual(result['outcome'],'partial' if stdout else 'failed')
                    self.assertEqual(run.call_args.kwargs['env']['LC_ALL'],'C')
                    self.assertEqual(self.findings.add_finding.call_count,1 if stdout else 0)
                    if stdout=='Core: +95.0°C':
                        self.assertEqual(self.findings.add_finding.call_args.args[2],'MEDIUM')
                    value=coverage()
                    value['outcomes'][4].update(result)
                    self.assertFalse(NS['assessment_complete'](value))
                    self.assertIn('Incomplete assessment',NS['assessment_verdict'](value,0))
                    display=SimpleNamespace(_ok_banner=Mock(),_assessment_coverage=value)
                    with patch.dict(NS,RISK=SimpleNamespace(findings=[]),html=html):
                        method('FindingsTable','show_all_ok_banner')(display)
                        report=NS['_build_exec_statement'](0,0,0,0,0,value)
                    display._ok_banner.setVisible.assert_called_with(False)
                    self.assertNotIn('Complete assessment — no findings',report)
                    self.findings.clear_findings.assert_not_called()

    def test_sensor_unrelated_warning_or_failed_word_is_not_a_read_failure(self):
        for message in ('', 'WARNING: using default limits',
                        'Warning: prior calibration failed; using device defaults',
                        'Info: read completed; previous calibration failed'):
            with self.subTest(message=message), \
                    patch.dict(NS,shutil=SimpleNamespace(which=lambda n:'fake'),SESSION=Mock(),T={'ACCENT':'blue'}), \
                    patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,'Core: +45.0°C',message)):
                result=NS['run_temperature_check'](self.terminal,self.findings,with_coverage=True)
            self.assertEqual(result['outcome'],'succeeded')

    def test_temperature_missing_failed_empty_partial_and_good(self):
        with patch.dict(NS,shutil=SimpleNamespace(which=lambda n:None),SESSION=Mock(),T={'ACCENT':'blue'}):
            result=NS['run_temperature_check'](self.terminal,self.findings,with_coverage=True)
        self.assertEqual(result['outcome'],'skipped')
        cases=[(1,'Core: +45.0°C','partial'),(0,'','unknown'),
               (0,'Core: +45.0°C\nbad °C','partial'),(0,'Core: +45.0°C','succeeded')]
        for code,text,state in cases:
            with self.subTest(state=state),patch.dict(NS,shutil=SimpleNamespace(which=lambda n:'fake'),SESSION=Mock(),T={'ACCENT':'blue','DANGER':'red','WARN':'yellow','TEXT_DIM':'grey'}),patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],code,text,'')):
                result=NS['run_temperature_check'](self.terminal,self.findings,with_coverage=True)
            self.assertEqual(result['outcome'],state)

    def test_update_and_network_garbage_cannot_be_clean(self):
        panel=SimpleNamespace(terminal=self.terminal,findings=self.findings)
        with patch.dict(NS,SESSION=Mock(),valid_pkg=lambda name:name=='example'):
            parse=method('CvePanel','_parse_upgrades')
            self.assertEqual(parse(panel,'Listing...\ngarbage'),'unknown')
            self.assertEqual(parse(panel,'Listing...'),'succeeded')
            self.assertEqual(parse(panel,'Listing...\nexample/stable 1.0 amd64'),'succeeded')
        self.findings.table.rowCount.return_value=0
        network=SimpleNamespace(terminal=self.terminal,findings=self.findings)
        with patch.dict(NS,SESSION=Mock(),L=lambda key:key):
            self.assertEqual(method('SideBar','_parse_network')(network,'garbage'),'unknown')


class CoverageIntegration(unittest.TestCase):
    def setUp(self):
        self.case=sequence.AssessmentSequence()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_successful_run_has_seven_explicit_success_states(self):
        run=self.case.finish_run()
        self.assertTrue(NS['assessment_complete'](run))
        self.assertEqual(len(run['outcomes']),7)

    def test_partial_cve_offline_missing_and_findings_are_preserved(self):
        run,cve=self.case.reach_cve()
        self.case.panel._cve_total=2
        self.case.finish_cve(cve)
        self.case.finish_command(ManualWorker.created[3])
        self.assertEqual(run['outcomes'][5]['outcome'],'partial')
        self.assertFalse(NS['assessment_complete'](run))
        self.case.sidebar.findings.clear_findings.assert_not_called()
        self.case.summary.assert_called_once_with()

    def test_service_probe_unknown_is_not_not_installed(self):
        done=Mock()
        with patch.dict(NS,probe_package=lambda name:(None,None)):
            self.case.sidebar._do_scan_services(on_terminal=done)
        self.assertEqual(done.call_args.args[0]['outcome'],'unknown')
        self.case.sidebar.findings.add_finding.assert_not_called()

    def test_offline_cve_is_skipped_and_successful_update_cannot_clear_it(self):
        with patch.dict(NS,has_internet=lambda:False):
            run=self.case.start()
            self.case.finish_command(ManualWorker.created[0])
            self.case.finish_command(ManualWorker.created[1])
            self.case.finish_command(ManualWorker.created[2])
        self.assertEqual(run['outcomes'][5]['outcome'],'skipped')
        self.assertEqual(run['outcomes'][6]['outcome'],'partial')
        self.assertFalse(NS['assessment_complete'](run))
        self.case.sidebar._post_scan_check.assert_not_called()

    def test_complete_run_with_cve_findings_is_not_a_clean_verdict(self):
        run,worker=self.case.reach_cve()
        panel=self.case.panel
        panel._handle_cve_result=MethodType(method('CvePanel','_handle_cve_result'),panel)
        panel.cve_table.rowCount.return_value=0
        with patch.dict(NS,QTableWidgetItem=Mock(),QColor=lambda color:color,
                        T={'DANGER':'red','WARN':'yellow','OK':'green','TEXT_DIM':'grey'}):
            worker.result_ready.emit('example',('1',{'cves':[{'cvss_severity':'medium'}]}))
        worker.outcome()
        worker.end()
        self.case.finish_command(ManualWorker.created[3])
        self.assertTrue(NS['assessment_complete'](run))
        self.assertIn('Complete assessment — findings need attention',NS['assessment_verdict'](run,0))

    def test_full_cve_response_page_is_partial_and_retains_findings(self):
        run,worker=self.case.reach_cve()
        panel=self.case.panel
        panel._handle_cve_result=MethodType(method('CvePanel','_handle_cve_result'),panel)
        panel.cve_table.rowCount.return_value=0
        cves=[{'cvss_severity':'medium'} for _ in range(5)]
        with patch.dict(NS,QTableWidgetItem=Mock(),QColor=lambda color:color,
                        T={'DANGER':'red','WARN':'yellow','OK':'green','TEXT_DIM':'grey'}):
            worker.result_ready.emit('example',('1',{'cves':cves}))
        worker.outcome()
        worker.end()
        self.case.finish_command(ManualWorker.created[3])
        self.assertEqual(run['outcomes'][5]['outcome'],'partial')
        self.assertEqual(run['outcomes'][5]['findings'],5)
        self.assertIn('findings need attention',NS['assessment_verdict'](run,0))
        panel.findings.clear_findings.assert_not_called()

    def test_malformed_cve_response_does_not_increment_success(self):
        panel=self.case.panel
        panel._cve_total=1
        panel._cve_ok=panel._cve_done=panel._cve_error=0
        actual=method('CvePanel','_handle_cve_result')
        actual(panel,'example',('1',{}),panel._cve_active_scan_id)
        self.assertEqual(panel._cve_ok,0)
        self.assertEqual(panel._cve_error,1)


if __name__=='__main__':
    unittest.main()
