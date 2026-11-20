"""Real Qt prerequisite workflow with fake metadata/transactions only."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import uuid
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--screenshots',type=Path);args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='dashboard-4h-') as state:
        for key in ('HOME','XDG_CONFIG_HOME','XDG_STATE_HOME','XDG_DATA_HOME','XDG_CACHE_HOME'):
            path=Path(state,key);path.mkdir();os.environ[key]=str(path)
        os.environ['GSETTINGS_BACKEND']='memory'
        from PyQt6.QtCore import Qt,QTimer,QCoreApplication,QEvent
        from PyQt6.QtWidgets import QApplication,QDialog,QTextEdit,QMessageBox,QPushButton
        from PyQt6.QtTest import QTest
        original_run=subprocess.run
        original_popen=subprocess.Popen
        calls=[]
        def no_host(argv,*a,**kw):
            if argv in (['hostname'],['uname','-r']):return subprocess.CompletedProcess(argv,0,'fixture-endpoint\n','')
            calls.append(argv);raise AssertionError('Host execution forbidden in prerequisite fixture')
        subprocess.run=no_host
        subprocess.Popen=lambda *a,**kw: (_ for _ in ()).throw(AssertionError("Process creation forbidden in synthetic prerequisite fixture"))
        spec=importlib.util.spec_from_file_location('prereq_dashboard',ROOT/'linux-security-dashboard.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        m.pkg_installed=lambda n:False
        m.get_system_info=lambda:{k:'fixture-'+k for k in ('hostname','os','kernel','arch','cpu','ram','uptime')}
        m.check_update_age=lambda:(None,'')
        m.prerequisite_os=lambda:('ubuntu','26.04')
        installed=set();mode={'code':0,'stale':False};gate=threading.Event();gate.set();transactions=[]
        def rows():
            output=[]
            for r in m.PREREQUISITES:
                package=r[3];missing=package in ('deborphan','lynis','iproute2') and package not in installed
                eligible=missing and package!='deborphan'
                output.append(dict(key=r[0],section=r[1],executable=r[2],package=package,requirement=r[4],
                    status='Missing' if missing else 'Installed',reason='Synthetic no candidate' if package=='deborphan' else 'Synthetic metadata',
                    candidate='1' if eligible else None,installable=eligible))
            # A repeated package across sections must not duplicate the transaction.
            duplicate=dict(output[1]);duplicate['section']='Repeated dependency fixture';output.append(duplicate)
            output.append(dict(key='future',section='Unsupported fixture',executable='none',package='none',
                requirement='Not applicable',status='Unsupported',reason='Synthetic unsupported platform',candidate=None,installable=False))
            output.append(dict(key='unverified',section='Could Not Verify fixture',executable='none',package='none',
                requirement='Optional',status='Could Not Verify',reason='Synthetic query error',candidate=None,installable=False))
            output.append(dict(key='runtime',section='Runtime fixture',executable='—',package='—',
                requirement='Existing runtime',status='Not Required',reason='No additional package',candidate=None,installable=False))
            return output
        m.detect_prerequisites=rows
        m.verify_prerequisite_plan=lambda plan: dict(rows=rows(),packages={p:p in installed for p,v in plan["resolved"]})
        plans=[]
        def build(packages):
            names=tuple(sorted(set(packages)))
            assert set(names)<= {'lynis','iproute2'}
            plan=dict(requested=tuple((p,'1') for p in names),resolved=tuple((p,'1') for p in names),
                      command=tuple(m.prerequisite_apt_argv([(p,'1') for p in names])),policy='Synthetic trusted repository',state='fixture')
            plans.append(plan);return plan
        m.build_prerequisite_plan=build
        def transaction(plan,password,progress):
            transactions.append(plan)
            progress('Synthetic package progress')
            if not gate.wait(3):raise RuntimeError('Fixture gate timeout')
            if mode['stale']:raise ValueError('Installation plan changed; review again')
            if mode['code']==0:installed.update(p for p,v in plan['requested'])
            return dict(code=mode['code'],error=None,output='Synthetic result')
        m.execute_prerequisite_plan=transaction
        authorization=Mock(return_value=b'fixture-password');m.prompt_for_sudo_password=authorization
        app=QApplication([]);app.setStyle('Fusion');app._foundation_events=m.FoundationEvents(app);app.installEventFilter(app._foundation_events)
        wizard=type('Wizard',(),dict(mode='expert',online=True,profile='mixed'))()
        win=m.AuditDashboard(wizard_result=wizard);win.show()
        panel=win.prerequisites;owner=m.scan_owner(win);checks=[];captures=[]
        def expect(condition,message):
            if not condition:raise AssertionError(message)
        def until(condition):
            for i in range(400):
                if condition():return
                QTest.qWait(10)
            raise AssertionError('Fixture completion timeout: '+panel.phase)
        def idle():until(lambda:panel.phase=='idle' and not panel._workers and owner.token is None)
        def answer(accepted):
            def act():
                dialog=app.activeModalWidget()
                if isinstance(dialog,QDialog) and dialog.windowTitle()=='Approve prerequisite installation':
                    text=dialog.findChild(QTextEdit).toPlainText()
                    expect('Exact command:' in text and '/usr/bin/sudo' in text,'missing command preview')
                    expect('Removals: none. Upgrades: none.' in text,'missing effects preview')
                    expect('not automatically reversible' in text,'misleading reversal claim')
                    dialog.accept() if accepted else dialog.reject()
                else:QTimer.singleShot(5,act)
            QTimer.singleShot(5,act)
        def snapshot(label):
            if args.screenshots is None:return
            args.screenshots.mkdir(parents=True,exist_ok=True)
            path=args.screenshots/f'{time.strftime("%Y%m%d-%H%M%S")}-{label}-{uuid.uuid4().hex[:8]}.png'
            with path.open('xb'):pass
            expect(win.grab().save(str(path)),'screenshot save');captures.append(str(path))
        try:
            until(lambda:panel.generation > 0)
            idle();win._open_prerequisites();QTest.qWait(50)
            expect(panel.table.columnCount()==7,'table schema')
            expect(all(panel.table.item(i,0).checkState()==Qt.CheckState.Unchecked for i in range(len(panel.rows))),'automatic selection')
            expect(not panel.install_button.isEnabled(),'batch install without selection')
            expect(not win.sidebar.action_buttons['btn_unused'].isEnabled(),'missing no-candidate scan enabled')
            for i,row in enumerate(panel.rows):
                if row['package']=='iproute2':panel.table.item(i,0).setCheckState(Qt.CheckState.Checked)
                if row['package']=='deborphan':expect(not panel.table.cellWidget(i,6).isEnabled(),'candidate-less install enabled')
            expect(panel.selected_packages()==('iproute2',),'selection not deduplicated')
            panel.refresh();idle()
            expect(not panel.selected_packages(),'Refresh selected packages automatically')
            checks.append('startup detection, five table states, unchecked defaults, candidate gate and deduplication passed')
            snapshot('enterprise-prerequisites')
            win.theme_combo.setCurrentText('Hybrid Professional');win._open_prerequisites();QTest.qWait(20);snapshot('hybrid-prerequisites')
            answer(False);panel.install(('lynis',));idle()
            authorization.assert_not_called();expect(not transactions,'cancelled preview executed')
            answer(True);authorization.return_value=None;panel.install(('lynis',));idle()
            expect(not transactions,'cancelled authentication executed')
            authorization.return_value=b'fixture-password'
            checks.append('preview/credential cancellation never dispatches installation')
            mode['code']=1;answer(True);panel.install(('lynis',));idle()
            expect('failed/uncertain' in panel.notice.text(),'failed install reported success')
            expect(not win.sidebar.action_buttons['btn_lynis'].isEnabled(),'failed installation enabled audit')
            mode['code']=0;mode['stale']=True;answer(True);panel.install(('lynis',));idle()
            expect('changed' in panel.notice.text(),'stale plan accepted')
            mode['stale']=False
            checks.append('failed/stale transactions remain unavailable and require another review')
            # Retain actual native QThread ownership during an approved transaction.
            gate.clear();answer(True);panel.install(('lynis',));until(lambda:panel.phase=='installing' and len(panel._workers)>0)
            until(lambda:len(transactions)==3)
            expect(owner.token and owner.workers,'installation not owned')
            old_question=m.QMessageBox.question
            m.QMessageBox.question=Mock(return_value=QMessageBox.StandardButton.Yes)
            expect(not win.close(),'closed with installation active')
            expect(owner.shutdown_state=='waiting','shutdown not waiting')
            before=len(transactions);panel.install(('iproute2',));expect(len(transactions)==before,'shutdown admitted work')
            m.QMessageBox.question.return_value=QMessageBox.StandardButton.No
            win.close();expect(owner.shutdown_state=='running','shutdown cancellation failed')
            m.QMessageBox.question=old_question
            gate.set();idle()
            expect(win.sidebar.action_buttons['btn_lynis'].isEnabled(),'verified installation did not enable scan')
            expect('No scan was started' in panel.notice.text(),'automatic scan implication')
            checks.append('active package worker retained during shutdown; cancel-close and post-install validation passed')
            before=win.terminal.output.toPlainText();panel._receive_progress(panel.generation-1,'STALE_PROGRESS_FIXTURE')
            expect(win.terminal.output.toPlainText()==before,'stale progress contaminated Activity')
            # An older generation cannot consume a new operation's result; duplicates are harmless.
            original_start=panel._start_worker;held=[]
            panel._start_worker=lambda worker:held.append(worker)
            done=Mock();panel._launch(lambda:None,done,panel.generation)
            held[-1].value='fixture';held[-1].finished.emit();held[-1].finished.emit()
            expect(done.call_count==1,'duplicate terminal callback consumed twice')
            held[-1].deleteLater()
            done=Mock();panel._launch(lambda:None,done,panel.generation-1)
            held[-1].finished.emit();done.assert_not_called();held[-1].deleteLater()
            panel._start_worker=Mock(side_effect=RuntimeError('pre-dispatch fixture'))
            done=Mock();panel._launch(lambda:None,done,panel.generation)
            expect(done.call_count==1 and not panel._workers,'startup failure phantom worker')
            panel._start_worker=original_start
            checks.append('stale progress/results, duplicate completion and pre-dispatch rollback passed')
            # Fresh targeted gate, not cached table data, controls scan execution.
            original_which=m.shutil.which;m.shutil.which=lambda name:None
            done=Mock();win.sidebar._do_scan_network(on_terminal=done)
            expect(done.call_args.args[0]['outcome']=='skipped','missing prerequisite not skipped')
            win.tools_panel._schedule_card.findChild(QPushButton).click()
            expect(win.nav_buttons['Settings'].isChecked(),'legacy scheduler alias bypassed prerequisite navigation')
            m.shutil.which=original_which
            checks.append('targeted pre-scan revalidation skips without starting a scan or sudo')
            expect(not calls,'host command executed')
            expect(win.close(),'idle close failed')
            evidence=dict(checks=checks,screenshots=captures)
            if args.screenshots:
                path=args.screenshots/f'{time.strftime("%Y%m%d-%H%M%S")}-validation-{uuid.uuid4().hex[:8]}.json'
                with path.open('x') as output:json.dump(evidence,output,indent=2)
            print(json.dumps(evidence),flush=True)
        finally:
            gate.set()
            for i in range(400):
                app.processEvents()
                if not panel._workers:break
                QTest.qWait(10)
            win.close();win.deleteLater();QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete);app.processEvents()
            subprocess.run=original_run
            subprocess.Popen=original_popen


if __name__=='__main__':main()
