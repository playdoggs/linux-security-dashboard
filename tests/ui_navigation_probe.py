"""Real-widget fixture in an isolated process; no host scans or privileged commands.

Run through test_workspace_navigation.py, or pass --screenshots screenshots/stage3
on an authorized desktop. Preferences/history/logs always live in /tmp.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='dashboard-stage3-') as state:
        for name in ('home', 'config', 'data', 'cache', 'state'):
            Path(state, name).mkdir()
        os.environ.update({key: str(Path(state, directory)) for key, directory in
                           [('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'),
                            ('XDG_CACHE_HOME', 'cache'), ('XDG_STATE_HOME', 'state')]})
        os.environ['GSETTINGS_BACKEND'] = 'memory'
        from PyQt6 import sip
        from PyQt6.QtCore import Qt, QThread, pyqtSignal
        from PyQt6.QtTest import QTest
        from PyQt6.QtWidgets import QApplication, QPushButton, QLineEdit, QMessageBox
        real_run = subprocess.run
        unexpected = []
        def safe_run(argv, *a, **kw):
            if argv == ['gsettings', 'list-keys', 'org.gnome.settings-daemon.plugins.xsettings']:
                return real_run(argv, *a, **kw)
            if argv in (['hostname'], ['uname', '-r']):
                return subprocess.CompletedProcess(argv, 0, 'fixture-endpoint\n', '')
            unexpected.append(argv)
            raise AssertionError('Host execution prohibited in navigation fixture')
        subprocess.run = safe_run
        spec = importlib.util.spec_from_file_location('navigation_dashboard', SOURCE)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.pkg_installed = lambda name: False
        m.get_system_info = lambda: {key: 'fixture-' + key for key in
                                    ('hostname', 'os', 'kernel', 'arch', 'cpu', 'ram', 'uptime')}
        m.check_update_age = lambda: (None, 'Fixture: not checked')
        m.configure_qt_platform_theme()
        app = QApplication([])
        app.setStyle('Fusion')
        app._foundation_events = m.FoundationEvents(app)
        app.installEventFilter(app._foundation_events)
        wizard = type('FixtureWizard', (), {'mode': 'expert', 'online': True, 'profile': 'mixed'})()
        win = m.AuditDashboard(wizard_result=wizard)
        m.refresh_theme_widgets(app)
        win.show()
        QTest.qWait(50)
        results = []
        screenshots = []
        def check(condition, message):
            if not condition:
                raise AssertionError(message)
        def save(label, widget=win):
            if args.screenshots is None:
                return
            args.screenshots.mkdir(parents=True, exist_ok=True)
            path = args.screenshots / f'{time.strftime("%Y%m%d-%H%M%S")}-{label}-{uuid.uuid4().hex[:8]}.png'
            # Reserve each destination; never replace existing evidence.
            with path.open('xb'):
                pass
            check(widget.grab().save(str(path)), 'screenshot save')
            screenshots.append(str(path))
        def settle_until(condition):
            for _ in range(200):
                if condition():
                    return
                QTest.qWait(10)
            raise AssertionError('Qt fixture completion timeout')
        gate = threading.Event()
        workers = []
        finished = []
        class FixtureWorker(QThread):
            output_ready = pyqtSignal(str)
            error_ready = pyqtSignal(str)
            finished_ok = pyqtSignal()
            failed = pyqtSignal()
            def __init__(self, cmd, *a, **kw):
                super().__init__()
                self.cmd = cmd
                workers.append(self)
                self.finished.connect(lambda: finished.append(True))
            def run(self):
                self.output_ready.emit('Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
                                       'tcp LISTEN 0 128 127.0.0.1:45678 0.0.0.0:*\n')
                if gate.wait(3):
                    self.finished_ok.emit()
                else:
                    self.failed.emit()
        m.CommandWorker = FixtureWorker
        try:
            check(tuple(win.pages) == win.SECTIONS and win.stack.count() == 7, 'seven destinations')
            controllers = tuple(map(id, (win.sidebar, win.findings, win.cve_panel, win.lynis_panel,
                                         win.tools_panel, win.undo_panel)))
            owner = m.scan_owner(win)
            for index, name in enumerate(win.SECTIONS):
                win.nav_buttons[name].click()
                check(win.stack.currentIndex() == index, name)
                check(win.nav_buttons[name].isChecked(), 'selection')
                check(sum(b.isChecked() for b in win.nav_buttons.values()) == 1, 'exclusive selection')
                check(win.nav_buttons[name].accessibleName() == name, 'accessible label')
            check(not workers and owner.token is None and not owner.workers, 'navigation dispatched work')
            results.append('seven destinations: no execution, exclusive accessible selection')
            for index, expected in [(0, 'Findings'), (1, 'Assessments'), (2, 'Assessments'),
                                    (3, 'Remediation'), (4, 'Remediation')]:
                win.sidebar.stack.setCurrentIndex(index)
                check(win.nav_buttons[expected].isChecked(), 'legacy routing')
            check(controllers == tuple(map(id, (win.sidebar, win.findings, win.cve_panel, win.lynis_panel,
                                                win.tools_panel, win.undo_panel))), 'controllers replaced')
            results.append('legacy routing preserves controller identities')
            for key in ('btn_os_installed', 'btn_user_installed'):
                check(win.pages['Assets'].isAncestorOf(win.sidebar.action_buttons[key]), 'inventory placement')
            for key in ('btn_unused', 'btn_network', 'btn_services', 'btn_fullscan', 'btn_quick',
                        'btn_temperature', 'btn_drives', 'btn_lynis', 'btn_cve', 'btn_upgrades'):
                check(win.sidebar.isAncestorOf(win.sidebar.action_buttons[key]), 'assessment placement')
            check(win.pages['Remediation'].isAncestorOf(win.sidebar.action_buttons['btn_wizard']), 'guided fix placement')
            check(win.assessment_tabs.widget(1) is win.cve_panel and win.assessment_tabs.widget(2) is win.lynis_panel, 'assessment panels')
            check(win.remediation_tabs.widget(0) is win.tools_panel and win.remediation_tabs.widget(1) is win.undo_panel, 'remediation panels')
            check(win.pages['Settings'].isAncestorOf(win.theme_combo), 'settings placement')
            win.sidebar.setEnabled(False)
            check(all(not win.sidebar.action_buttons[key].isEnabled() for key in
                      ('btn_os_installed', 'btn_user_installed', 'btn_wizard')), 'linked control disable boundary')
            win.sidebar.setEnabled(True)
            check(all(win.sidebar.action_buttons[key].isEnabled() for key in
                      ('btn_os_installed', 'btn_user_installed', 'btn_wizard')), 'linked control restore boundary')
            win._navigate('Overview')
            QTest.keyClick(win.nav_buttons['Findings'], Qt.Key.Key_Space)
            check(win.nav_buttons['Findings'].isChecked(), 'Qt keyboard navigation activation')
            results.append('feature placement, linked control disable/restore and Qt keyboard activation passed')
            # Actual production scan entry, mocked command thread; no Linux command executes.
            win.sidebar._scan_network()
            check(len(workers) == 1 and owner.workers and owner.token, 'active worker not owned')
            token = owner.token
            settle_until(lambda: win.findings.table.rowCount() > 0)
            evidence = win.findings.table.rowCount()
            for name in win.SECTIONS:
                win._navigate(name)
                check(owner.token == token and owner.workers, 'navigation released active ownership')
                check(win.findings.table.rowCount() == evidence, 'navigation cleared evidence')
            win.sidebar._scan_unused()
            check(len(workers) == 1, 'conflicting scan dispatched')
            check('Cannot start' in win.terminal.output.toPlainText(), 'missing conflict feedback')
            win.activity_toggle.setChecked(False)
            check(win.terminal.isHidden(), 'activity collapse')
            check(owner.workers, 'activity collapse released worker')
            win.activity_toggle.setChecked(True)
            check(not win.terminal.isHidden(), 'activity expand')
            gate.set()
            settle_until(lambda: not owner.workers and owner.token is None)
            check(finished == [True], 'native Qt completion')
            check(win.findings.table.rowCount() == evidence, 'completion lost evidence')
            results.append('navigation/activity during real QThread execution preserves ownership and evidence')
            # Representative fixtures for visible screenshots and semantic preservation.
            win.findings.add_finding('Fixture service', 'SERVICE', 'HIGH', 'Synthetic finding; no command executes.')
            coverage = {'id': 'fixture-review', 'active': False, 'outcomes': [
                {'name': name, 'outcome': 'partial' if i == 5 else 'succeeded',
                 'reason': 'Synthetic partial evidence' if i == 5 else 'Synthetic evidence'}
                for i, name in enumerate(m.ASSESSMENT_STEPS)]}
            win.findings._assessment_coverage = coverage
            before = (win.findings.table.rowCount(), m.RISK.score(), copy.deepcopy(coverage))
            for theme in m.THEMES:
                win.theme_combo.setCurrentText(theme)
                m.refresh_theme_widgets(app)
                for name in win.SECTIONS:
                    win._navigate(name)
                    QTest.qWait(10)
                check(before == (win.findings.table.rowCount(), m.RISK.score(), coverage), 'theme/navigation altered evidence')
                check('Incomplete assessment' in win.overview_verdict.text(), 'overview false clean')
                if theme in ('Enterprise Workspace', 'Hybrid Professional'):
                    win.assessment_tabs.setCurrentIndex(0)
                    for name in win.SECTIONS:
                        win._navigate(name)
                        QTest.qWait(30)
                        save(theme.lower().replace(' ', '-') + '-' + name.lower())
            results.append('all seven themes preserve findings, score and incomplete coverage')
            win.theme_combo.setCurrentText('Enterprise Workspace')
            win._navigate('Findings')
            win.resize(1100, 700)
            QTest.qWait(20)
            check(win.stack.width() > 500, 'small-window content inaccessible')
            save('enterprise-small-window')
            win.terminal._adjust_font(4)
            QTest.qWait(30)
            for name, button in win.nav_buttons.items():
                check(button.width() >= button.fontMetrics().horizontalAdvance(name) + 16, 'clipped navigation')
            save('enterprise-larger-text')
            win.terminal._adjust_font(-4)
            win.resize(1440, 900)
            win._navigate('Findings')
            win.activateWindow()
            search = win.findings.findChild(QLineEdit)
            search.setFocus()
            QTest.qWait(50)
            if search.hasFocus():
                QTest.keyClick(search, Qt.Key.Key_Tab)
                check(app.focusWidget() is not search, 'Tab did not move focus')
                results.append('keyboard Tab traversal passed')
            else:
                results.append('desktop keyboard focus unavailable')
            # Offscreen tests still exercise nav activation through Qt button signals above.
            dialog = m.ExplainDialog('Fixture', 'SERVICE', 'HIGH', 'Synthetic explanation', win)
            dialog.show()
            QTest.qWait(20)
            save('enterprise-explanation-dialog', dialog)
            dialog.reject()
            check(not unexpected, f'unexpected commands: {unexpected}')
            check(not win._shutdown_busy(), 'unexpected active work')
            check(win.close(), 'normal close refused')
            check(owner.shutdown_state == 'safe_to_close', 'shutdown lifecycle bypassed')
            results.append('existing explanation dialog and normal shutdown passed')
            evidence = {'checks': results, 'screenshots': screenshots}
            if args.screenshots is not None:
                path = args.screenshots / f'{time.strftime("%Y%m%d-%H%M%S")}-visual-validation-{uuid.uuid4().hex[:8]}.json'
                with path.open('x') as output:
                    json.dump(evidence, output, indent=2)
            print(json.dumps(evidence))
        finally:
            gate.set()
            for worker in workers:
                if not sip.isdeleted(worker):
                    worker.wait(4000)
            win._workspace_timer.stop()
            win.close()
            app.processEvents()
            subprocess.run = real_run


if __name__ == '__main__':
    main()
