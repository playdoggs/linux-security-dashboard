"""Pure production prerequisite logic; no host metadata, sudo or installation."""
import ast
import os
import re
import selectors
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest
from privileged_test_support import install_helpers

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'
TREE = ast.parse(SOURCE.read_text())
NAMES = {'PREREQUISITES','PREREQUISITE_INSTALL_RELEASES','PREREQUISITE_EFFECTS','APT_PREREQUISITE_OPTIONS',
         'detect_prerequisites','executable_trust','prerequisite_rows','prerequisite_os','prerequisite_read','prerequisite_candidate','prerequisite_apt_state',
         'prerequisite_apt_argv','parse_prerequisite_simulation','build_prerequisite_plan','prerequisite_redact',
         'prerequisite_gate','execute_prerequisite_plan','verify_prerequisite_plan'}


def namespace():
    ns = dict(os=os, re=re, stat=stat, subprocess=subprocess, time=time, Path=Path, selectors=selectors,
              shutil=SimpleNamespace(which=Mock(return_value='/trusted/executable')),
              coverage_result=lambda state, reason: dict(outcome=state, reason=reason))
    install_helpers(ns, transaction_stub=False)
    for node in TREE.body:
        name = node.name if isinstance(node, ast.FunctionDef) else None
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name): name=node.targets[0].id
        if name in NAMES:exec(compile(ast.Module(body=[node],type_ignores=[]),str(SOURCE),'exec'),ns)
    return ns


class PrerequisiteLogic(unittest.TestCase):
    def setUp(self):
        self.ns=namespace()
        self.ns['prerequisite_os']=Mock(return_value=('ubuntu','26.04'))
        self.ns['prerequisite_candidate']=Mock(return_value='1.2-3')

    def detect(self):return self.ns['detect_prerequisites']()

    def test_installed_presence_is_not_scan_success(self):
        rows=self.detect()
        self.assertTrue(all(r['status']=='Installed' for r in rows[:-1]))
        self.assertTrue(all(not r['installable'] for r in rows))
        self.assertEqual(rows[-1]['status'],'Not Required')
        self.ns['prerequisite_candidate'].assert_not_called()

    def test_discovered_executable_does_not_imply_trusted_path(self):
        self.ns['executable_trust']=Mock(return_value=(False,'path or parent is not root-controlled'))
        row=self.detect()[0]
        self.assertEqual(row['status'],'Installed')
        self.assertIn('Discovered: /trusted/executable',row['reason'])
        self.assertIn('not root-controlled',row['reason'])
        self.assertIn('Scan evidence',row['reason'])

    @patch.object(os, 'readlink', return_value='/protected/tool')
    def test_root_trust_checks_parent_and_resolved_path(self, readlink):
        states = {'/': (0, stat.S_IFDIR | 0o755),
                  '/synthetic': (0, stat.S_IFDIR | 0o755),
                  '/synthetic/bin': (0, stat.S_IFLNK | 0o777),
                  '/protected': (0, stat.S_IFDIR | 0o755),
                  '/protected/tool': (0, stat.S_IFREG | 0o755)}
        class FixturePath(type(Path())):
            def lstat(self):
                if str(self) not in states:
                    raise FileNotFoundError()
                uid, mode = states[str(self)]
                return SimpleNamespace(st_uid=uid, st_mode=mode)
            def readlink(self):
                return FixturePath('/protected/tool')
        self.ns['Path'] = FixturePath
        trust = self.ns['executable_trust']
        self.assertTrue(trust('/synthetic/bin')[0])
        for parent in ('/synthetic', '/protected'):
            states[parent] = (0, stat.S_IFDIR | 0o777)
            self.assertFalse(trust('/synthetic/bin')[0])
            states[parent] = (0, stat.S_IFDIR | 0o755)
        for uid, mode in ((1000, stat.S_IFREG | 0o755), (0, stat.S_IFREG | 0o644),
                          (0, stat.S_IFDIR | 0o755)):
            states['/protected/tool'] = (uid, mode)
            self.assertFalse(trust('/synthetic/bin')[0])
        del states['/protected/tool']
        self.assertFalse(trust('/synthetic/bin')[0])

    def test_untrusted_installer_path_rejected_before_simulation(self):
        self.ns['executable_trust']=Mock(return_value=(False,'unsafe parent'))
        self.ns['prerequisite_read']=Mock()
        with self.assertRaisesRegex(ValueError,'Untrusted'):
            self.ns['build_prerequisite_plan'](['lynis'])
        self.ns['prerequisite_read'].assert_not_called()

    def test_missing_candidate_is_eligible_and_deduplicated(self):
        self.ns['shutil'].which.side_effect=lambda name:'/trusted/'+name if name in ('sudo','apt-get','apt-cache','dpkg-query') else None
        rows=self.detect()
        eligible={r['package'] for r in rows if r['installable']}
        self.assertEqual(eligible, set(self.ns['PREREQUISITE_INSTALL_RELEASES']['26.04']))
        calls=[c.args[0] for c in self.ns['prerequisite_candidate'].call_args_list]
        self.assertEqual(len(calls),len(set(calls)))
        self.assertNotIn('systemd',eligible)
        self.assertNotIn('sudo',eligible)

    def test_no_candidate_disables_install(self):
        self.ns['shutil'].which.return_value=None
        self.ns['prerequisite_candidate'].return_value=None
        row=next(r for r in self.detect() if r['key']=='unused')
        self.assertEqual(row['status'],'Missing')
        self.assertFalse(row['installable'])
        self.assertIn('No candidate',row['reason'])

    def test_metadata_error_is_not_missing_or_installable(self):
        self.ns['shutil'].which.return_value=None
        self.ns['prerequisite_candidate'].side_effect=TimeoutError('offline metadata')
        row=next(r for r in self.detect() if r['key']=='unused')
        self.assertEqual(row['status'],'Could Not Verify')
        self.assertFalse(row['installable'])

    def test_non_ubuntu_and_unreviewed_release_fail_closed(self):
        self.ns['prerequisite_os'].return_value=('fedora','44')
        rows=self.detect()
        self.assertEqual(next(r for r in rows if r['key']=='cve')['status'],'Unsupported')
        self.assertFalse(any(r['installable'] for r in rows))
        self.ns['prerequisite_os'].return_value=('ubuntu','99.04')
        self.ns['shutil'].which.return_value=None
        self.assertFalse(any(r['installable'] for r in self.detect()))

    def test_existing_rpm_pacman_and_generic_probes_remain_available(self):
        self.ns['prerequisite_os'].return_value=('fedora','44')
        rows=self.detect()
        service=next(r for r in rows if r['key']=='services')
        self.assertEqual((service['executable'],service['status']),('rpm','Installed'))
        grep=next(r for r in rows if r['key']=='quick' and r['executable']=='grep')
        self.assertEqual(grep['status'],'Installed')
        self.ns['prerequisite_os'].return_value=('arch','rolling')
        inventory=next(r for r in self.detect() if r['key']=='inventory')
        self.assertEqual((inventory['executable'],inventory['status']),('pacman','Installed'))

    def test_subjects_and_optional_catalogue_not_install_allowlist(self):
        for release, packages in self.ns['PREREQUISITE_INSTALL_RELEASES'].items():
            self.assertFalse(set(packages)&{'ufw','fail2ban','openssh-server','auditd','nmap','timeshift','unattended-upgrades'})

    def test_missing_sudo_blocks_privileged_scan_and_prerequisite_installer(self):
        self.ns['shutil'].which.side_effect=lambda name: None if name in ('sudo','lynis') else '/trusted/'+name
        row=next(r for r in self.detect() if r['executable']=='lynis')
        self.assertFalse(row['installable'])
        panel=SimpleNamespace(_is_prerequisite_panel=True,notice=Mock())
        terminal=SimpleNamespace(_prerequisites=panel,append_warn=Mock())
        failed=Mock()
        self.assertFalse(self.ns['prerequisite_gate'](terminal,'lynis',on_failed=failed))
        failed.assert_called_once()

    def test_targeted_gate_skips_without_elevation(self):
        panel=SimpleNamespace(_is_prerequisite_panel=True,notice=Mock())
        terminal=SimpleNamespace(_prerequisites=panel,append_warn=Mock())
        done=Mock()
        self.ns['shutil'].which.return_value=None
        self.assertFalse(self.ns['prerequisite_gate'](terminal,'network',on_terminal=done))
        self.assertEqual(done.call_args.args[0]['outcome'],'skipped')
        self.assertEqual(self.ns['shutil'].which.call_args.args,('ss',))
        terminal.append_warn.assert_called_once()

    def test_simulation_collects_only_new_dependencies(self):
        text='Inst sensors-data (2.0 Ubuntu:26.04 [amd64])\nInst lm-sensors (1.2-3 Ubuntu:26.04 [amd64])\nConf sensors-data (2.0 Ubuntu:26.04 [amd64])\nConf lm-sensors (1.2-3 Ubuntu:26.04 [amd64])'
        self.assertEqual(self.ns['parse_prerequisite_simulation'](text),(('lm-sensors','1.2-3'),('sensors-data','2.0')))

    def test_unknown_simulation_actions_fail_closed(self):
        valid='Inst lynis (1.2-3 Ubuntu [amd64])\nConf lynis (1.2-3 Ubuntu [amd64])'
        for action in ('Unpk other (2 Ubuntu [amd64])','Reinst other (2 Ubuntu [amd64])',
                       'Unknown future action','  Remv ssh [1]','Conf malformed',
                       'Inst other [1] (2 Ubuntu [amd64])','E: broken metadata'):
            with self.subTest(action=action):
                with self.assertRaises(ValueError):self.ns['parse_prerequisite_simulation'](valid+'\n'+action)

    def test_known_simulation_headers_and_package_lists_are_accepted(self):
        text='''Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  dependency
Suggested packages:
  optional-tool
The following NEW packages will be installed:
  dependency lynis
0 upgraded, 2 newly installed, 0 to remove and 4 not upgraded.
Need to get 10.0 kB of archives.
After this operation, 20.0 kB of additional disk space will be used.
Inst dependency (2 Ubuntu [amd64])
Inst lynis (1.2-3 Ubuntu [amd64])
Conf dependency (2 Ubuntu [amd64])
Conf lynis (1.2-3 Ubuntu [amd64])'''
        self.assertEqual(self.ns['parse_prerequisite_simulation'](text),(('dependency','2'),('lynis','1.2-3')))

    def test_removals_upgrades_configuration_and_malformed_rejected(self):
        for text in ('Remv ssh [1]', 'Purg ssh [1]', 'Inst pkg [1] (2 Ubuntu [amd64])',
                     'Inst -x (2 Ubuntu [amd64])', 'Inst pkg (x;evil Ubuntu [amd64])',
                     'Inst pkg (2 Ubuntu [amd64])\nConf other (2 Ubuntu [amd64])',
                     'Inst pkg (2 Ubuntu [amd64])\nInst pkg (2 Ubuntu [amd64])', ''):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):self.ns['parse_prerequisite_simulation'](text)

    def test_argv_is_fixed_pinned_and_no_trust_bypass(self):
        argv=self.ns['prerequisite_apt_argv']([('lynis','3.1-1')])
        self.assertEqual(argv[0],'/usr/bin/apt-get')
        self.assertIn('--no-remove',argv)
        self.assertIn('Acquire::https::Verify-Peer=true',argv)
        self.assertEqual(argv[-2:],['--','lynis=3.1-1'])
        for package in ('--evil','/tmp/p.deb','foo-','foo+','x;id'):
            with self.assertRaises(ValueError):self.ns['prerequisite_apt_argv']([(package,'1')])

    def prepare_plan(self):
        self.ns['executable_trust']=Mock(return_value=(True,'synthetic root-controlled path'))
        self.ns['Path']=Mock(return_value=SimpleNamespace(stat=lambda:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o755)))
        self.ns['prerequisite_apt_state']=Mock(return_value='state')
        self.ns['prerequisite_read']=Mock(side_effect=['','Inst lynis (1.2-3 Ubuntu [amd64])\nConf lynis (1.2-3 Ubuntu [amd64])','Candidate: 1.2-3'])

    def test_plan_deduplicates_and_includes_sources(self):
        self.prepare_plan()
        plan=self.ns['build_prerequisite_plan'](['lynis','lynis'])
        self.assertEqual(plan['requested'],(('lynis','1.2-3'),))
        self.assertEqual(plan['resolved'],plan['requested'])
        self.assertIn('policy',plan)

    def test_plan_rejects_unreviewed_packages_and_changed_metadata(self):
        with self.assertRaises(ValueError):self.ns['build_prerequisite_plan'](['openssh-server'])
        self.prepare_plan()
        self.ns['prerequisite_apt_state'].side_effect=['before','after']
        with self.assertRaisesRegex(ValueError,'changed'):self.ns['build_prerequisite_plan'](['lynis'])

    def test_broken_package_database_not_automatically_repaired(self):
        self.prepare_plan()
        self.ns['prerequisite_read'].side_effect=['half-configured package']
        with self.assertRaisesRegex(ValueError,'manual repair'):self.ns['build_prerequisite_plan'](['lynis'])

    def test_changed_plan_rejected_before_sudo(self):
        self.ns['build_prerequisite_plan']=Mock(return_value={'requested':(('lynis','2'),)})
        with patch.object(subprocess,'Popen') as popen:
            with self.assertRaisesRegex(ValueError,'changed'):
                self.ns['execute_prerequisite_plan']({'requested':(('lynis','1'),)},b'fake',Mock())
            popen.assert_not_called()

    def test_package_worker_never_kills_on_collection_failure(self):
        plan={'requested':(('lynis','1'),),'command':('/usr/bin/apt-get','install','lynis=1')}
        self.ns['build_prerequisite_plan']=Mock(return_value=plan)
        process=Mock()
        process.poll.side_effect=[None,None,0]
        process.wait.return_value=0
        process.stdin.closed=process.stdout.closed=False
        with patch.object(subprocess,'Popen',return_value=process) as popen, \
             patch.object(selectors,'DefaultSelector',side_effect=OSError('fixture read failure')), \
             patch.object(os,'set_blocking'),patch.object(os,'read',return_value=b''), \
             patch.object(time,'sleep') as sleep:
            result=self.ns['execute_prerequisite_plan'](plan,b'fake',Mock())
        self.assertIn('OSError',result['error'])
        process.wait.assert_called_once()
        self.assertEqual(sleep.call_count,2)
        self.assertTrue(all(call.args==(.05,) for call in sleep.call_args_list))
        process.kill.assert_not_called();process.terminate.assert_not_called()
        self.assertNotIn('timeout',popen.call_args.kwargs)
        self.assertEqual(popen.call_args.args[0][0],'/usr/bin/sudo')
        self.assertNotIn('shell',popen.call_args.kwargs)

    def test_empty_exception_text_still_records_collection_failure(self):
        plan={'requested':(('lynis','1'),),'command':('/usr/bin/apt-get','install','lynis=1')}
        self.ns['build_prerequisite_plan']=Mock(return_value=plan)
        process=Mock();process.poll.return_value=0;process.wait.return_value=0
        process.stdin.closed=process.stdout.closed=False
        with patch.object(subprocess,'Popen',return_value=process), \
             patch.object(selectors,'DefaultSelector',side_effect=RuntimeError()):
            result=self.ns['execute_prerequisite_plan'](plan,b'fake',Mock())
        self.assertIn('RuntimeError',result['error'])
        process.wait.assert_called_once()
        process.kill.assert_not_called();process.terminate.assert_not_called()

    def test_missing_temperature_and_all_quick_prerequisites_are_skipped(self):
        self.ns['prerequisite_gate']=Mock(return_value=False)
        self.ns['T']={'ACCENT':'blue','OK':'green','WARN':'orange','DANGER':'red','TEXT_DIM':'grey'}
        self.ns['SESSION']=SimpleNamespace(log_scan=Mock())
        for node in TREE.body:
            if isinstance(node,ast.FunctionDef) and node.name in ('run_quick_checks','run_temperature_check'):
                exec(compile(ast.Module(body=[node],type_ignores=[]),str(SOURCE),'exec'),self.ns)
        terminal=Mock();findings=Mock()
        with patch.object(subprocess,'run') as run:
            temp=self.ns['run_temperature_check'](terminal,findings,with_coverage=True)
            quick=self.ns['run_quick_checks'](terminal,findings,with_coverage=True)
        self.assertEqual(temp['outcome'],'skipped')
        self.assertEqual(quick['outcome'],'skipped')
        run.assert_not_called();findings.add_finding.assert_not_called()

    def test_post_install_verification_checks_exact_versions_and_dependencies(self):
        rows=[dict(package='lynis',status='Installed',reason='',candidate=None,installable=False)]
        self.ns['detect_prerequisites']=Mock(return_value=rows)
        self.ns['prerequisite_read']=Mock(side_effect=['ii \t1\n','ii \twrong\n'])
        plan=dict(requested=(('lynis','1'),),resolved=(('lynis','1'),('dependency','2')))
        result=self.ns['verify_prerequisite_plan'](plan)
        self.assertTrue(result['packages']['lynis'])
        self.assertFalse(result['packages']['dependency'])
        self.assertEqual(result['rows'][0]['status'],'Could Not Verify')
        self.ns['prerequisite_read'].side_effect=['ii \t1\n','ii \t2\n']
        result=self.ns['verify_prerequisite_plan'](plan)
        self.assertTrue(all(result['packages'].values()))
        self.assertEqual(result['rows'][0]['status'],'Installed')

    def test_authentication_cancellation_never_creates_a_process(self):
        plan={'requested':(('lynis','1'),),'command':('/usr/bin/apt-get','install','lynis=1')}
        self.ns['build_prerequisite_plan']=Mock(return_value=plan)
        with patch.object(subprocess,'Popen') as popen:
            for password in (None,b'',b'x'*4097):
                with self.assertRaises(ValueError):self.ns['execute_prerequisite_plan'](plan,password,Mock())
            popen.assert_not_called()

    def test_readonly_metadata_does_not_inherit_apt_config(self):
        response=subprocess.CompletedProcess([],0,'Candidate: 1','')
        with patch.dict(os.environ,APT_CONFIG='/tmp/untrusted-config'), \
             patch.object(subprocess,'run',return_value=response) as run:
            self.ns['prerequisite_read'](['/usr/bin/apt-cache','policy','lynis'],time.monotonic()+3)
        self.assertNotIn('APT_CONFIG',run.call_args.kwargs['env'])
        self.assertNotIn('shell',run.call_args.kwargs)

    def test_package_worker_success_drains_and_reaps_without_termination(self):
        plan={'requested':(('lynis','1'),),'command':('/usr/bin/apt-get','install','lynis=1')}
        self.ns['build_prerequisite_plan']=Mock(return_value=plan)
        process=Mock();process.poll.return_value=0;process.wait.return_value=0
        process.stdin.closed=process.stdout.closed=False
        watches={}
        class Selector:
            def register(self,stream,event):watches[stream]=SimpleNamespace(fileobj=stream)
            def unregister(self,stream):del watches[stream]
            def get_map(self):return watches
            def select(self,timeout):return [(key,None) for key in list(watches.values())]
            def close(self):pass
        progress=Mock()
        with patch.object(subprocess,'Popen',return_value=process) as popen, \
             patch.object(selectors,'DefaultSelector',return_value=Selector()), \
             patch.object(os,'set_blocking'),patch.object(os,'write',side_effect=lambda fd,data:len(data)), \
             patch.object(os,'read',side_effect=[b'Safe fixture output\n',b'']):
            result=self.ns['execute_prerequisite_plan'](plan,b'fake',progress)
        self.assertEqual(result['code'],0);self.assertIsNone(result['error'])
        self.assertIn('Safe fixture output',result['output'])
        process.wait.assert_called_once();process.kill.assert_not_called();process.terminate.assert_not_called()
        self.assertIn('-i',popen.call_args.args[0]);self.assertNotIn('APT_CONFIG',popen.call_args.kwargs['env'])
        self.assertNotIn('timeout',popen.call_args.kwargs)

    def test_redaction_hides_stdin_password_and_url_credentials(self):
        text=self.ns['prerequisite_redact']('fake https://user:token@example.test/repo',b'fake')
        self.assertNotIn('fake',text);self.assertNotIn('user:token',text)


if __name__=='__main__':unittest.main()
