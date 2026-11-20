"""Production entry/worker/callback isolation, mocked widgets and commands only."""
from types import SimpleNamespace, MethodType
from pathlib import Path
import tempfile
import copy
import threading
import time
import unittest
from unittest.mock import Mock, patch
from PyQt6.QtCore import QCoreApplication, QThread, pyqtSignal

import test_assessment_sequence as sequence
from test_command_outcomes import NS, method

COMPLETE_LYNIS = 'Lynis security scan details:\nWarnings (0):\nSuggestions (0):\nHardening index : 80\nTests performed : 100\n'


class ScanIsolation(unittest.TestCase):
    def setUp(self):
        self.case = sequence.AssessmentSequence()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.owner = NS['ScanOwnership']()
        self.rows = []
        self.risk = SimpleNamespace(findings=[], clear=lambda: None)
        self.sidebar, self.panel = self.case.sidebar, self.case.panel
        self.sidebar._mark_section_action_done = Mock()
        self.terminal = self.sidebar.terminal
        self.terminal._scan_owner = self.owner
        self.display = SimpleNamespace(_scan_owner=self.owner, terminal=self.terminal,
                                       table=Mock(), _seen_findings=set(), score_changed=Mock(),
                                       _ok_banner=Mock(), add_finding=Mock(side_effect=lambda *args: self.rows.append(args)))
        self.display.table.setRowCount.side_effect=lambda n: self.rows.clear() if n==0 else None
        for name in ('clear_findings','hide_all_ok_banner','show_all_ok_banner','set_assessment_coverage'):
            setattr(self.display,name,MethodType(method('FindingsTable',name),self.display))
        self.sidebar.findings = self.panel.findings = self.display
        self.sidebar._scan_owner = self.panel._scan_owner = self.owner
        for name in ('_pre_scan','_post_scan_check','_scan_failed','_scan_network','_scan_unused',
                     '_scan_services','_quick_checks','_scan_temperature','_scan_drives',
                     '_scan_cve','_scan_upgrades','_run_lynis','_run_full_scan',
                     '_scan_installed','_scan_os_installed','_scan_user_installed'):
            setattr(self.sidebar,name,MethodType(method('SideBar',name),self.sidebar))
        self.sidebar._parse_network = Mock(side_effect=lambda text: self.rows.append(text) or 'succeeded')
        self.lynis = SimpleNamespace(_scan_owner=self.owner,terminal=self.terminal,findings=self.display,
                                     status=Mock(),output=Mock(),_lappend=Mock(),_workers=set(),_any_running=False,
                                     _get_sudo_password=Mock(return_value=b'fake'),
                                     _read_lynis_log=Mock(return_value='stale log must never be read'))
        for name in ('run_lynis','_parse_lynis_output','_parse_lynis_partial'):
            setattr(self.lynis,name,MethodType(method('LynisPanel',name),self.lynis))
        start=method('WorkerMixin','_start_worker')
        self.lynis._start_worker=lambda worker:start(self.lynis,worker)
        self.sidebar.lynis_panel=self.lynis
        self.patcher=patch.dict(NS,RISK=self.risk,T={'OK':'green','ACCENT':'blue','WARN':'yellow','DANGER':'red','TEXT_DIM':'grey'},
                               StreamingCommandWorker=sequence.ManualWorker)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def network(self):
        self.sidebar._scan_network()
        return sequence.ManualWorker.created[-1]

    def test_overlapping_individual_request_preserves_active_work(self):
        worker=self.network()
        worker.output_ready.emit('first result')
        token=self.owner.token
        self.sidebar._scan_unused()
        self.assertEqual(len(sequence.ManualWorker.created),1)
        self.assertEqual(self.rows,['first result'])
        self.assertEqual(self.owner.token,token)
        self.terminal.append_warn.assert_called()
        worker.outcome()
        self.assertEqual(self.owner.token,token)  # Logical success cannot release ownership.
        worker.end()
        self.assertIsNone(self.owner.token)

    def test_run_everything_and_individual_requests_are_mutually_exclusive(self):
        self.network()
        self.sidebar.run_everything(on_complete=self.case.summary)
        self.assertFalse(hasattr(self.sidebar,'_re_run'))
        sequence.ManualWorker.created[0].outcome();sequence.ManualWorker.created[0].end()
        self.sidebar.run_everything(on_complete=self.case.summary)
        token=self.owner.token
        self.sidebar._scan_network()
        self.assertEqual(len(sequence.ManualWorker.created),2)
        self.assertEqual(self.owner.token,token)
        self.case.summary.assert_not_called()

    def test_stale_worker_cannot_change_new_findings_status_or_banner(self):
        old=self.network()
        old.output_ready.emit('old')
        old.outcome();old.end()
        new=self.network()
        new.output_ready.emit('new')
        baseline=list(self.rows)
        self.sidebar._pending_section_action=('scan','current')
        self.display._ok_banner.reset_mock()
        old.output_ready.emit('stale')
        old.error_ready.emit('stale error')
        old.outcome();old.end()
        self.assertEqual(self.rows,baseline)
        self.assertEqual(self.sidebar._pending_section_action,('scan','current'))
        self.display._ok_banner.setVisible.assert_not_called()
        self.assertEqual(self.owner.workers,{new})

    def test_stale_cve_and_update_callbacks_cannot_replace_newer_data(self):
        self.sidebar._scan_cve()
        old=sequence.ManualWorker.created[-1]
        old.result_ready.emit('example',('1',{'cves':[]}))
        old.outcome();old.end()
        self.sidebar._scan_upgrades()
        current=sequence.ManualWorker.created[-1]
        self.panel._handle_cve_result.reset_mock()
        self.panel._parse_upgrades.reset_mock()
        self.panel.status.reset_mock()
        old.result_ready.emit('example',('old',{'cves':[]}))
        old.outcome();old.end()
        self.panel._handle_cve_result.assert_not_called()
        self.panel.status.setText.assert_not_called()
        current.output_ready.emit('recognized output')
        current.outcome();current.end()
        self.network()
        self.panel._parse_upgrades.reset_mock()
        self.panel.status.reset_mock()
        current.output_ready.emit('old updates');current.outcome();current.end()
        self.panel._parse_upgrades.assert_not_called()
        self.panel.status.setText.assert_not_called()

    def test_duplicate_completion_and_expired_continuation_cannot_reenter(self):
        worker=self.network()
        token=self.owner.token
        worker.output_ready.emit('recognized result')
        worker.outcome();worker.outcome()
        worker.end();worker.end()
        self.sidebar._mark_section_action_done.assert_called_once()
        self.sidebar._scan_network(_scan_token=token)
        self.assertEqual(len(sequence.ManualWorker.created),1)
        self.assertIsNone(self.owner.token)

    def test_fast_completion_is_registered_before_start(self):
        def immediate(worker):
            worker.running=True
            worker.output_ready.emit('fast result')
            worker.outcome();worker.end()
        with patch.object(sequence.ManualWorker,'start',immediate):
            self.network()
        self.assertEqual(self.rows,['fast result'])
        self.assertEqual(self.owner.workers,set())
        self.assertIsNone(self.owner.token)
        self.assertEqual(self.sidebar._workers,set())

    def test_pre_dispatch_exception_releases_owner_without_phantom_worker(self):
        with patch.object(sequence.ManualWorker,'start',side_effect=RuntimeError('start refused')):
            self.sidebar._scan_network()
        self.assertIsNone(self.owner.token)
        self.assertEqual(self.owner.workers,set())
        self.assertEqual(self.sidebar._workers,set())
        self.network()
        self.assertEqual(len(self.owner.workers),1)

    def test_post_dispatch_exception_retains_owner_and_rejects_new_requests(self):
        def start_then_raise(worker):
            worker.running=True
            raise RuntimeError('started before setup failed')
        with patch.object(sequence.ManualWorker,'start',start_then_raise):
            worker=self.network()
        token=self.owner.token
        self.assertTrue(worker.isRunning())
        self.assertEqual(self.owner.workers,{worker})
        self.sidebar._scan_unused()
        self.assertEqual(self.owner.token,token)
        self.assertEqual(len(sequence.ManualWorker.created),1)
        worker.output_ready.emit('partial result')
        worker.outcome();worker.end()
        self.assertEqual(self.rows,['partial result'])
        self.assertIsNone(self.owner.token)
        self.assertIsNone(self.sidebar._pending_section_action)
        self.display._ok_banner.setVisible.assert_called_with(False)

    def test_all_entry_points_reject_before_clearing_or_prompting(self):
        self.network()
        count=len(sequence.ManualWorker.created)
        for name in ('_scan_services','_quick_checks','_scan_temperature','_scan_drives',
                     '_scan_cve','_scan_upgrades','_run_lynis','_scan_installed',
                     '_scan_os_installed','_scan_user_installed','_run_full_scan'):
            getattr(self.sidebar,name)()
        self.panel.scan_cve();self.panel.scan_upgrades();self.lynis.run_lynis()
        self.assertEqual(len(sequence.ManualWorker.created),count)
        self.lynis._get_sudo_password.assert_not_called()
        self.assertEqual(self.display.table.setRowCount.call_count,1)

    def test_clear_and_manual_changes_are_rejected_during_scan(self):
        self.network()
        self.rows.append('preserve')
        self.display.clear_findings()
        self.assertEqual(self.rows,['preserve'])
        method('FindingsTable','_act')(self.display,'not executed','x','remove','HIGH')
        undo=SimpleNamespace(_scan_owner=self.owner,terminal=self.terminal)
        self.assertFalse(method('UndoPanel','_run_undo')(undo,{}))
        self.assertEqual(len(sequence.ManualWorker.created),1)

    def test_owned_seven_step_sequence_keeps_lease_and_snapshot(self):
        self.sidebar.run_everything(on_complete=self.case.summary)
        run=self.sidebar._re_run
        for index in (0,1):
            worker=sequence.ManualWorker.created[index]
            self.case.finish_command(worker)
        cve=sequence.ManualWorker.created[2]
        self.case.finish_cve(cve)
        update=sequence.ManualWorker.created[3]
        update.outcome()
        self.assertEqual(self.owner.token,update._scan_record['token'])
        self.case.summary.assert_not_called()
        update.end()
        self.case.summary.assert_called_once()
        snapshot=copy.deepcopy(self.display._assessment_coverage)
        cve.result_ready.emit('example',('old',{'cves':[]}));cve.end();update.end()
        self.assertEqual(self.display._assessment_coverage,snapshot)
        self.assertIsNone(self.owner.token)
        self.assertEqual(len(run['outcomes']),7)

    def test_lynis_missing_empty_and_stale_log_cannot_supply_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            stale=Path(folder)/'lynis.log'
            stale.write_text('hardening_index=100\n|WARNING|none\n')
            self.lynis._read_lynis_log.side_effect=lambda:stale.read_text()
            for text in ('','progress only','Warnings : 0\nSuggestions : 0\n'):
                result=self.lynis._parse_lynis_output(text)
                self.assertEqual(result['outcome'],'unknown')
            stale.unlink()  # Isolated fixture; real shared logs are never opened.
            self.assertEqual(self.lynis._parse_lynis_output('')['outcome'],'unknown')
        self.lynis._read_lynis_log.assert_not_called()

    def test_lynis_current_evidence_requires_success_and_thread_completion(self):
        self.sidebar._run_lynis()
        worker=sequence.ManualWorker.created[-1]
        worker.full_output=COMPLETE_LYNIS
        worker.outcome()
        self.assertIsNotNone(self.owner.token)
        self.terminal.append_ok.assert_not_called()
        worker.end()
        self.assertIsNone(self.owner.token)
        self.terminal.append_ok.assert_called_once_with('Lynis Full Audit complete.')
        self.network()
        self.lynis.status.reset_mock()
        worker.outcome();worker.end();worker.output_ready.emit('old Lynis')
        self.lynis.status.setText.assert_not_called()

    def test_lynis_empty_output_does_not_call_healthy_completion(self):
        self.sidebar._run_lynis()
        worker=sequence.ManualWorker.created[-1]
        worker.full_output=''
        worker.outcome();worker.end()
        self.terminal.append_ok.assert_not_called()
        self.assertIn('incomplete/unknown',self.lynis.status.setText.call_args.args[0])
        self.assertIsNone(self.sidebar._pending_section_action)
        self.display._ok_banner.setVisible.assert_called_with(False)

    def test_lynis_partial_output_preserves_warning_findings(self):
        result=self.lynis._parse_lynis_output('Warning: real issue\n')
        self.assertEqual(result['outcome'],'unknown')
        self.assertTrue(any(row[2]=='MEDIUM' for row in self.rows))

    def test_lynis_parse_exception_is_unknown_without_losing_ownership_cleanup(self):
        self.lynis._parse_lynis_output=Mock(side_effect=ValueError('bad counters'))
        self.sidebar._run_lynis()
        worker=sequence.ManualWorker.created[-1]
        worker.full_output=COMPLETE_LYNIS
        worker.outcome();worker.end()
        self.terminal.append_ok.assert_not_called()
        self.assertIn('incomplete/unknown',self.lynis.status.setText.call_args.args[0])
        self.assertIsNone(self.owner.token)
        self.assertIsNone(self.sidebar._pending_section_action)

    def test_lynis_failed_or_truncated_worker_never_parses_success_evidence(self):
        for truncated in (False,True):
            with self.subTest(truncated=truncated):
                self.terminal.append_ok.reset_mock()
                self.sidebar._run_lynis()
                worker=sequence.ManualWorker.created[-1]
                worker.full_output=COMPLETE_LYNIS
                worker.output_truncated=truncated
                worker.outcome(success=truncated)
                worker.end()
                self.terminal.append_ok.assert_not_called()
                self.assertIsNone(self.owner.token)

    def test_missing_lynis_never_installs_or_requests_audit_authorization(self):
        which=Mock(return_value=None)
        box=SimpleNamespace(question=Mock(return_value=1),StandardButton=SimpleNamespace(Yes=1,No=2))
        with patch.dict(NS,shutil=SimpleNamespace(which=which),QMessageBox=box):
            self.sidebar._run_lynis()
        self.assertEqual(sequence.ManualWorker.created, [])
        self.assertIsNone(self.owner.token)
        self.assertEqual(self.owner.workers, set())
        self.lynis._get_sudo_password.assert_not_called()
        box.question.assert_not_called()
        self.terminal.append_ok.assert_not_called()

    def test_duplicate_cve_response_is_consumed_once(self):
        self.sidebar._scan_cve()
        worker=sequence.ManualWorker.created[-1]
        worker.result_ready.emit('example',('1',{'cves':[]}))
        worker.result_ready.emit('example',('1',{'cves':[]}))
        self.assertEqual(self.panel._handle_cve_result.call_count,1)
        self.assertEqual(self.panel._cve_ok,1)
        worker.outcome();worker.end()
        self.assertIsNone(self.owner.token)

    def test_partial_results_remain_when_later_parser_callback_fails(self):
        self.sidebar._parse_network.side_effect=['succeeded',ValueError('parser failed')]
        worker=self.network()
        self.rows.append('valid finding from first chunk')
        worker.output_ready.emit('first chunk')
        worker.output_ready.emit('bad chunk')
        worker.outcome();worker.end()
        self.assertEqual(self.rows,['valid finding from first chunk'])
        self.display._ok_banner.setVisible.assert_called_with(False)
        self.assertIsNone(self.owner.token)

    def test_legacy_full_scan_keeps_three_checks_without_delayed_timers(self):
        self.sidebar._run_full_scan()
        self.case.finish_command(sequence.ManualWorker.created[0])
        self.case.finish_command(sequence.ManualWorker.created[1])
        self.assertEqual(len(sequence.ManualWorker.created),2)
        self.assertEqual([row['name'] for row in self.sidebar._re_run['outcomes']],
                         ['Unused software','Open network ports','Risky services'])
        self.case.quick.assert_not_called()
        self.case.temps.assert_not_called()
        self.assertIsNone(self.owner.token)
        self.display._ok_banner.setVisible.assert_called_with(False)

    def test_failed_lynis_keeps_partial_warning_without_success_parsing(self):
        full=Mock()
        self.lynis._parse_lynis_output=full
        self.sidebar._run_lynis()
        worker=sequence.ManualWorker.created[-1]
        worker.full_output='Warning: retained current-attempt issue\n'
        worker.outcome(success=False);worker.end()
        full.assert_not_called()
        self.assertTrue(any(row[2]=='MEDIUM' and 'retained current-attempt issue' in row[3] for row in self.rows))
        self.terminal.append_ok.assert_not_called()
        self.assertIsNone(self.owner.token)

    def test_admission_banner_exception_rolls_back_and_allows_retry(self):
        self.rows.append('keep finding')
        self.display._assessment_coverage={'id':'prior','active':False,'outcomes':[]}
        prior=copy.deepcopy(self.display._assessment_coverage)
        with patch.object(self.display,'hide_all_ok_banner',side_effect=RuntimeError('admission banner failed')):
            self.sidebar._scan_network()
        self.assertIsNone(self.owner.token)
        self.assertEqual(self.owner.depth,0)
        self.assertEqual(self.owner.workers,set())
        self.assertEqual(self.rows,['keep finding'])
        self.assertEqual(self.display._assessment_coverage,prior)
        self.network()
        self.assertEqual(len(self.owner.workers),1)

    def test_admission_coverage_initialization_exception_allows_retry(self):
        class BrokenCoverage:
            @property
            def _assessment_coverage(self):
                raise RuntimeError('coverage initialization failed')
        self.rows.append('keep finding')
        with patch.object(self.sidebar,'findings',BrokenCoverage()):
            self.sidebar._scan_network()
        self.assertIsNone(self.owner.token)
        self.assertEqual(self.owner.depth,0)
        self.assertEqual(self.rows,['keep finding'])
        self.network()
        self.assertEqual(len(self.owner.workers),1)

    def test_nested_admission_exception_preserves_parent_depth(self):
        token=self.owner.enter('parent')
        with patch.object(self.sidebar,'isEnabled',side_effect=RuntimeError('nested admission failed')):
            with self.assertRaisesRegex(RuntimeError,'nested admission failed'):
                self.sidebar._scan_network(_scan_token=token)
        self.assertEqual(self.owner.token,token)
        self.assertEqual(self.owner.depth,1)
        self.assertEqual(self.owner.workers,set())
        self.owner.leave(token)
        self.assertIsNone(self.owner.token)

    def test_admission_cleanup_exception_does_not_mask_original(self):
        token=self.owner.enter('parent')
        with patch.object(self.sidebar,'_do_scan_network',side_effect=RuntimeError('original failure')), \
                patch.object(self.sidebar,'setEnabled',side_effect=ValueError('cleanup failed')):
            with self.assertRaisesRegex(RuntimeError,'original failure'):
                self.sidebar._scan_network(_scan_token=token)
        self.assertEqual(self.owner.depth,1)
        self.owner.leave(token)
        self.assertIsNone(self.owner.token)

    def test_cleanup_signal_registration_failures_leave_no_phantom(self):
        for cleanup_number in (1,2,3):
            with self.subTest(cleanup_number=cleanup_number):
                created=[]
                def construct(*args,**kwargs):
                    worker=sequence.ManualWorker(*args,**kwargs)
                    created.append(worker)
                    connect=worker.finished.connect
                    calls=[0]
                    def connect_failure(slot):
                        calls[0]+=1
                        # Assessment acknowledgement is connected first.
                        if calls[0]==cleanup_number+1:
                            raise RuntimeError('cleanup signal registration failed')
                        return connect(slot)
                    worker.finished.connect=connect_failure
                    return worker
                with patch.dict(NS,CommandWorker=construct):
                    self.sidebar._scan_network()
                self.assertIsNone(self.owner.token)
                self.assertEqual(self.owner.depth,0)
                self.assertEqual(self.owner.workers,set())
                self.assertEqual(self.sidebar._workers,set())
                self.assertFalse(created[0].isRunning())
                self.assertEqual(len(created[0].finished.slots),1)  # Only caller's once-only acknowledgement remains.
                new=self.network()
                token=self.owner.token
                created[0].end();created[0].end()
                self.assertEqual(self.owner.token,token)
                self.assertEqual(self.owner.workers,{new})
                new.end()
                self.assertIsNone(self.owner.token)

    def test_reference_registration_failures_rollback_partial_add(self):
        class AddFailure(set):
            def add(self,worker):
                super().add(worker)
                raise RuntimeError('reference registration failed')
        for target in ('widget','owner'):
            with self.subTest(target=target):
                if target=='widget':self.sidebar._workers=AddFailure()
                else:self.owner.workers=AddFailure()
                self.sidebar._scan_network()
                self.assertEqual(self.sidebar._workers,set())
                self.assertEqual(self.owner.workers,set())
                self.assertIsNone(self.owner.token)
                self.sidebar._workers=set()
                self.owner.workers=set()
                new=self.network()
                self.assertTrue(new.isRunning())
                new.end()
                self.assertIsNone(self.owner.token)

    def test_run_setup_failure_restores_controls_and_allows_retry(self):
        with patch.object(self.display,'set_assessment_coverage',side_effect=RuntimeError('run setup failed')):
            self.sidebar.run_everything(on_complete=self.case.summary)
        self.assertIsNone(self.owner.token)
        self.assertFalse(self.sidebar._re_run['active'])
        self.assertIsNone(self.panel._assessment_owner)
        self.sidebar.setEnabled.assert_called_with(True)
        self.panel.setEnabled.assert_called_with(True)
        self.case.summary.assert_not_called()
        self.sidebar.run_everything(on_complete=self.case.summary)
        self.assertTrue(self.sidebar._re_run['active'])
        self.assertEqual(len(self.owner.workers),1)

    def test_pre_dispatch_cleanup_does_not_mask_start_exception(self):
        token=self.owner.enter('parent')
        worker=sequence.ManualWorker(['fake'])
        worker.start=Mock(side_effect=RuntimeError('original startup failure'))
        worker.deleteLater=Mock(side_effect=ValueError('secondary cleanup failure'))
        with self.assertRaisesRegex(RuntimeError,'original startup failure'):
            method('WorkerMixin','_start_worker')(self.sidebar,worker)
        self.assertEqual(self.owner.workers,set())
        self.assertEqual(self.sidebar._workers,set())
        self.assertEqual(self.owner.depth,1)
        worker.end();worker.end()
        worker.deleteLater.assert_called_once_with()
        self.owner.leave(token)
        self.assertIsNone(self.owner.token)

    def test_assessment_start_rollback_does_not_delete_twice(self):
        created=[]
        def construct(*args,**kwargs):
            worker=sequence.ManualWorker(*args,**kwargs)
            created.append(worker)
            worker.deleteLater=Mock()
            connect=worker.finished.connect
            count=[0]
            def fail_second(slot):
                count[0]+=1
                if count[0]==2:raise RuntimeError('cleanup connection failed')
                connect(slot)
            worker.finished.connect=fail_second
            return worker
        with patch.dict(NS,CommandWorker=construct):
            self.sidebar._scan_network()
        created[0].deleteLater.assert_called_once_with()
        self.assertIsNone(self.owner.token)

    def test_assessment_fallback_cleanup_retains_original_error(self):
        token=self.owner.enter('parent')
        worker=sequence.ManualWorker(['fake'])
        worker.deleteLater=Mock(side_effect=ValueError('cleanup error'))
        callback=Mock()
        with patch.object(self.sidebar,'_start_worker',side_effect=RuntimeError('original setup error')):
            self.sidebar._start_assessment_worker(worker,lambda:'succeeded',callback)
        callback.assert_called_once_with({'outcome':'failed','error':'original setup error'})
        self.owner.leave(token)
        self.assertIsNone(self.owner.token)

    def test_real_qt_result_handling_precedes_lease_release(self):
        app=QCoreApplication.instance() or QCoreApplication([])
        gate=threading.Event()
        class Thread(QThread):
            output_ready=pyqtSignal(str)
            error_ready=pyqtSignal(str)
            finished_ok=pyqtSignal()
            failed=pyqtSignal()
            def __init__(self,*args,**kwargs):super().__init__()
            def run(self):
                self.output_ready.emit('real queued result')
                self.finished_ok.emit()
                gate.wait(2)
        workers=[]
        original=self.sidebar._start_worker
        self.sidebar._start_worker=lambda worker:(workers.append(worker),original(worker))[-1]
        try:
            with patch.dict(NS,CommandWorker=Thread):
                self.sidebar._scan_network()
                deadline=time.monotonic()+2
                while 'real queued result' not in self.rows and time.monotonic()<deadline:
                    app.processEvents();time.sleep(.001)
                self.assertIn('real queued result',self.rows)
                self.assertIsNotNone(self.owner.token)
                gate.set()
                self.assertTrue(workers[0].wait(2000))
                app.processEvents()
                self.assertIsNone(self.owner.token)
                self.assertEqual(self.sidebar._workers,set())
        finally:
            gate.set()
            for worker in workers:
                try:worker.wait(2500)
                except RuntimeError:pass
