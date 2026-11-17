"""Isolated real-widget findings/dialog checks; synthetic data, no host operations."""
import argparse
import html
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', choices=('table', 'behaviour', 'short-dialog', 'long-dialog', 'performance', 'all'), default='all')
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='dashboard-4g-') as state:
        for key in ('HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME'):
            path = Path(state, key)
            path.mkdir()
            os.environ[key] = str(path)
        os.environ['GSETTINGS_BACKEND'] = 'memory'
        from PyQt6.QtCore import Qt, QEvent, QCoreApplication
        from PyQt6.QtGui import QHelpEvent, QFontMetrics
        from PyQt6.QtTest import QTest
        from PyQt6.QtWidgets import QApplication, QPushButton, QScrollArea, QDialogButtonBox, QToolTip, QLabel
        real_run = subprocess.run
        def no_host_commands(argv, *a, **kw):
            if argv == ['gsettings', 'list-keys', 'org.gnome.settings-daemon.plugins.xsettings']:
                return real_run(argv, *a, **kw)
            if argv in (['hostname'], ['uname', '-r']):
                return subprocess.CompletedProcess(argv, 0, 'fixture-endpoint\n', '')
            raise AssertionError(f'Host command prohibited: {argv}')
        subprocess.run = no_host_commands
        spec = importlib.util.spec_from_file_location('findings_dashboard', ROOT / 'linux-security-dashboard.py')
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.pkg_installed = lambda name: False
        m.get_system_info = lambda: {key: 'fixture-' + key for key in ('hostname', 'os', 'kernel', 'arch', 'cpu', 'ram', 'uptime')}
        m.check_update_age = lambda: (None, '')
        m.configure_qt_platform_theme()
        app = QApplication([])
        app.setStyle('Fusion')
        app._foundation_events = m.FoundationEvents(app)
        app.installEventFilter(app._foundation_events)
        wizard = type('FixtureWizard', (), {'mode': 'expert', 'online': True, 'profile': 'mixed'})()
        win = m.AuditDashboard(wizard_result=wizard)
        win.show()
        win._navigate('Findings')
        findings, table = win.findings, win.findings.table
        long_name = 'Fixture package with a descriptive long name'
        detail = 'Synthetic description <tag> & special characters. ' * 15
        findings.add_finding('Fixture low', 'HARDENING', 'LOW', 'Lower severity fixture')
        findings.add_finding(long_name, 'SERVICE', 'HIGH', detail, 'apt purge fixture-package', 'systemctl disable fixture.service')
        findings.add_finding('Fixture medium', 'NETWORK', 'MEDIUM', 'Medium severity fixture')
        m.refresh_theme_widgets(app)
        QTest.qWait(40)
        results, captures = [], []
        def check(condition, message):
            if not condition:
                raise AssertionError(message)
        def save(name, widget):
            if args.screenshots is None:
                return
            args.screenshots.mkdir(parents=True, exist_ok=True)
            path = args.screenshots / f'{time.strftime("%Y%m%d-%H%M%S")}-{name}-{uuid.uuid4().hex[:8]}.png'
            with path.open('xb'):
                pass
            check(widget.grab().save(str(path)), 'screenshot save')
            captures.append(str(path))
        def actions_visible():
            table.horizontalScrollBar().setValue(0)
            cell = table.cellWidget(0, 5)
            check(table.columnViewportPosition(5) + table.columnWidth(5) <= table.viewport().width(), 'actions outside viewport')
            check(table.columnViewportPosition(0) == 0, 'name not first')
            for button in cell.findChildren(QPushButton):
                check(cell.rect().contains(button.geometry()), 'action clipped by cell')
                check(button.width() >= button.fontMetrics().horizontalAdvance(button.text()) + 8, 'action text clipped')
                check(button.isVisible(), 'action hidden')
        try:
            if args.case in ('table', 'all'):
                logical_before = [[table.item(r, c).text() for c in range(5)] for r in range(table.rowCount())]
                check([table.horizontalHeader().logicalIndex(i) for i in range(6)] == [0, 2, 5, 1, 3, 4], 'priority order')
                for theme in ('Enterprise Workspace', 'Hybrid Professional'):
                    win.theme_combo.setCurrentText(theme)
                    for width, height in ((1440, 900), (1100, 700)):
                        win.resize(width, height)
                        QTest.qWait(200)
                        results.append(f"{theme}: requested {width}x{height}, actual {win.width()}x{win.height()}, viewport {table.viewport().width()}")
                        table.fit_columns()
                        QTest.qWait(20)
                        actions_visible()
                        check(table.horizontalScrollBar().maximum() == 0, 'unnecessary horizontal scroll')
                        risk_item = table.item(1, 2)
                        check(table.columnWidth(2) >= QFontMetrics(risk_item.font()).horizontalAdvance(risk_item.text()) + 32, 'risk width')
                        save(f'{theme.lower().replace(" ", "-")}-findings-actual-{win.width()}x{win.height()}', win)
                check(logical_before == [[table.item(r, c).text() for c in range(5)] for r in range(table.rowCount())], 'data altered by sizing')
                # Smaller embedded view: scrolling is permitted only below the minima.
                table.setFixedWidth(480)
                QTest.qWait(20)
                check(table.horizontalScrollBar().maximum() > 0, 'narrow view needs scroll')
                table.setMinimumWidth(0)
                table.setMaximumWidth(16777215)
                QTest.qWait(20)
                # Tooltip uses current logical item data after sorting, with HTML escaped.
                rect = table.visualItemRect(table.item(0, 4))
                point = rect.center()
                table.scrollToItem(table.item(0, 4))
                QTest.qWait(10)
                point = table.visualItemRect(table.item(0, 4)).center()
                event = QHelpEvent(QEvent.Type.ToolTip, point, table.viewport().mapToGlobal(point))
                QApplication.sendEvent(table.viewport(), event)
                check(html.escape(detail) in QToolTip.text(), 'complete escaped tooltip missing')
                QToolTip.hideText()
                results.append('normal/small geometry, priority columns, complete escaped tooltip and necessary-only scrolling passed')
            if args.case == 'performance':
                # Populate real Qt rows/cell layouts without invoking scanners or
                # the unrelated findings sort/population path 1,000 times.
                table.setRowCount(1000)
                for row in range(1000):
                    table.setItem(row, 0, m.QTableWidgetItem(f'Fixture {row}'))
                    table.setItem(row, 2, m.QTableWidgetItem('🟡 ▲ MEDIUM'))
                    table.setCellWidget(row, 5, findings._build_action_cell(
                        f'Fixture {row}', 'SERVICE', 'MEDIUM', 'Synthetic',
                        'apt purge fixture-package', 'systemctl disable fixture.service'))
                QTest.qWait(100)
                table.fit_columns()
                QTest.qWait(50)
                row_count = Mock(wraps=table.rowCount)
                item = Mock(wraps=table.item)
                cell_widget = Mock(wraps=table.cellWidget)
                set_width = Mock(wraps=table.setColumnWidth)
                table.rowCount, table.item, table.cellWidget = row_count, item, cell_widget
                table.setColumnWidth = set_width
                for width in (900, 780, 650, 820):
                    table.setFixedWidth(width)
                    QTest.qWait(30)
                    table.fit_columns()
                check(row_count.call_count == item.call_count == cell_widget.call_count == 0,
                      f'width-only resize traversed rows: rowCount={row_count.call_count}, item={item.call_count}, cellWidget={cell_widget.call_count}')
                set_width.reset_mock()
                table.fit_columns();table.fit_columns()
                check(set_width.call_count == 0, 'unchanged widths written repeatedly')
                # Data/widget/style invalidation is deliberately measured separately.
                table.rowCount, table.item, table.cellWidget = row_count._mock_wraps, item._mock_wraps, cell_widget._mock_wraps
                table.setColumnWidth = set_width._mock_wraps
                original_risk = table.columnWidth(2)
                table.item(999, 2).setText('A much longer explicit severity fixture label')
                QTest.qWait(50)
                check(table.columnWidth(2) > original_risk, 'risk data cache not invalidated')
                custom = m.QWidget()
                custom_layout = m.QHBoxLayout(custom)
                button = QPushButton('Fixture action')
                custom_layout.addWidget(button)
                table.setCellWidget(999, 5, custom)
                QTest.qWait(50)
                button.setMinimumWidth(620)
                QTest.qWait(50)
                check(table.columnWidth(5) >= 620, 'action layout cache not invalidated')
                table.removeCellWidget(999, 5)
                QTest.qWait(50)
                check(table.columnWidth(5) < 620, 'removed action cell remains cached')
                replacement = m.QWidget()
                replacement_layout = m.QHBoxLayout(replacement)
                replacement_button = QPushButton('Replacement fixture')
                replacement_button.setMinimumWidth(650)
                replacement_layout.addWidget(replacement_button)
                table.setCellWidget(999, 5, replacement)
                QTest.qWait(50)
                check(table.columnWidth(5) >= 650, 'replacement action cell not measured')
                table.setCellWidget(999, 5, None)
                QTest.qWait(50)
                check(table.columnWidth(5) < 620, 'cleared action cell remains cached')
                table.removeRow(999)
                QTest.qWait(50)
                check(table.columnWidth(5) < 620 and table.columnWidth(2) < original_risk + 100,
                      'removed widest row remains cached')
                large_font = table.item(0, 2).font()
                large_font.setPointSize(28)
                table.item(0, 2).setFont(large_font)
                QTest.qWait(50)
                check(table.columnWidth(2) >= QFontMetrics(large_font).horizontalAdvance(table.item(0, 2).text()) + 32,
                      'risk font cache not invalidated')
                win.theme_combo.setCurrentText('Hybrid Professional')
                QTest.qWait(100)
                actions_visible()
                results.append('1,000 findings: width-only resizing has zero row accesses; cache invalidation and unchanged-width suppression passed')
            if args.case in ('behaviour', 'all'):
                check(table.item(0, 0).text() == long_name, 'risk sorting changed')
                findings.search.setText('medium')
                check(table.isRowHidden(0) and not table.isRowHidden(1), 'search changed')
                findings.search.clear()
                actions = []
                findings._act = lambda *a: actions.append(a)
                ignored = []
                findings._ignore = ignored.append
                original_dialog = m.ExplainDialog
                explanations = []
                class ExplainSpy:
                    def __init__(self, *a): explanations.append(a)
                    def exec(self): return 0
                m.ExplainDialog = ExplainSpy
                try:
                    cell = table.cellWidget(0, 5)
                    for button in cell.findChildren(QPushButton): button.click()
                    check(actions == [('apt purge fixture-package', long_name, 'remove', 'HIGH'),
                                      ('systemctl disable fixture.service', long_name, 'disable', 'HIGH')], 'action routing changed')
                    check(ignored == [long_name], 'ignore routing changed')
                    table.cellDoubleClicked.emit(0, 0)
                    check(len(explanations) == 2 and all(e[:4] == (long_name, 'SERVICE', 'HIGH', detail) for e in explanations), 'explanation content/routing changed')
                finally:
                    m.ExplainDialog = original_dialog
                results.append('search, sorting, explanation/double-click and original action routing passed (actions intercepted)')
            for kind in ('short-dialog', 'long-dialog'):
                if args.case not in (kind, 'all'):
                    continue
                text = 'A short synthetic explanation.' if kind == 'short-dialog' else '\n'.join(f'Line {i}: long synthetic explanation.' for i in range(160))
                dialog = m.ExplainDialog('Fixture explanation', 'SERVICE', 'MEDIUM', text, win)
                dialog.show()
                QTest.qWait(30)
                scroll = dialog.findChild(QScrollArea, 'explanation_content')
                close = dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Close)
                check(dialog.width() <= 760 and dialog.height() <= 640, 'dialog exceeds cap')
                check(dialog.rect().contains(close.mapTo(dialog, close.rect().topLeft())) and
                      close.mapTo(dialog, close.rect().bottomRight()).y() < dialog.height(), 'Close outside dialog')
                labels = '\n'.join(label.text() for label in scroll.widget().findChildren(QLabel))
                check(text in labels, 'explanation text lost')
                if kind == 'short-dialog':
                    check(dialog.height() < 420, 'short explanation still oversized')
                else:
                    check(scroll.verticalScrollBar().maximum() > 0, 'long text not scrollable')
                    scroll.verticalScrollBar().setValue(scroll.verticalScrollBar().maximum())
                    check(close.isVisible(), 'Close scrolled away')
                save(kind, dialog)
                close.click()
                check(not dialog.isVisible(), 'Close failed')
                dialog.show()
                QTest.qWait(10)
                QTest.keyClick(dialog, Qt.Key.Key_Escape)
                check(not dialog.isVisible(), 'Escape failed')
                results.append(f'{kind}: text preserved, dimensions bounded, scrolling/Close/Escape passed')
            if args.case in ('long-dialog', 'all'):
                m.EXPLANATIONS['Fixture glossaryword'] = {
                    'what': 'What fixture section', 'why': 'Why fixture section',
                    'ignore': 'Ignore fixture section', 'fix': 'Fix fixture section'}
                m.GLOSSARY['glossaryword'] = 'Fixture glossary definition'
                dialog = m.ExplainDialog('Fixture glossaryword', 'SERVICE', 'HIGH', 'glossaryword', win)
                dialog.show()
                QTest.qWait(10)
                labels = '\n'.join(label.text() for label in dialog.findChildren(QLabel))
                for text in ('What fixture section', 'Why fixture section', 'Ignore fixture section',
                             'Fix fixture section', 'Fixture glossary definition'):
                    check(text in labels, 'named explanation/glossary content lost')
                dialog.close()
                results.append('named explanation sections and glossary preserved')
            check(not win._shutdown_busy(), 'unexpected worker')
            check(win.close(), 'normal close failed')
            evidence = {'checks': results, 'screenshots': captures}
            if args.screenshots is not None:
                path = args.screenshots / f'{time.strftime("%Y%m%d-%H%M%S")}-visual-validation-{uuid.uuid4().hex[:8]}.json'
                with path.open('x') as output:json.dump(evidence, output, indent=2)
            print(json.dumps(evidence), flush=True)
        finally:
            win.close()
            app.processEvents()
            # Dispose the isolated widget tree while QApplication/event dispatch
            # still exists, rather than relying on Python frame destruction order.
            win.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            app.processEvents()
            subprocess.run = real_run


if __name__ == '__main__':
    main()
