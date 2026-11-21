"""Production Qt dialogs/keyboard policy, without application import or host I/O."""
import argparse
import ast
import json
from pathlib import Path
import time
import uuid

from PyQt6 import QtWidgets as W
from PyQt6.QtCore import Qt,QTimer
from PyQt6.QtGui import QColor,QPalette
from PyQt6.QtTest import QTest

ROOT=Path(__file__).resolve().parents[1]


def production():
    ns={name:getattr(W,name) for name in dir(W) if name.startswith('Q')}
    ns.update(Qt=Qt,QColor=QColor,QPalette=QPalette,
              timeshift_is_configured=lambda:True,make_undo_cmd=lambda cmd:None)
    names={'BASE_FS','UI_METRICS','UI_TYPOGRAPHY','THEMES','T','PROFILES','fs',
           'apply_theme','build_palette','make_style','ThemeColor','theme_value',
           'set_theme_style','safe_confirmation_buttons','privileged_question',
           'PreActionDialog','ProfileDialog'}
    for node in ast.parse((ROOT/'linux-security-dashboard.py').read_text()).body:
        name=node.name if isinstance(node,(ast.FunctionDef,ast.ClassDef)) else None
        if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name):name=node.targets[0].id
        if name in names:exec(compile(ast.Module(body=[node],type_ignores=[]),'<production>','exec'),ns)
    return ns


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--case',choices=('preaction','message','profile'),required=True)
    parser.add_argument('--theme',default='Enterprise Workspace')
    parser.add_argument('--screenshots',type=Path)
    args=parser.parse_args()
    ns=production();app=W.QApplication([]);app.setStyle('Fusion')
    ns['apply_theme'](args.theme);app.setPalette(ns['build_palette']());app.setStyleSheet(ns['make_style']())
    checks=[];observations=[];captures=[]

    def expect(condition,message):
        if not condition:raise AssertionError(message)

    def capture(label,dialog):
        if not args.screenshots:return
        args.screenshots.mkdir(parents=True,exist_ok=True)
        p=args.screenshots/f'{time.strftime("%Y%m%d-%H%M%S")}-{args.theme.lower().replace(" ","-")}-{label}-{uuid.uuid4().hex[:8]}.png'
        with p.open('xb'):pass
        expect(dialog.grab().save(str(p)),'capture failed');captures.append(str(p))

    def dialog_test(scenario):
        message=args.case=='message'
        dialog=None if message else ns['PreActionDialog']('remove','fixture','apt remove fixture')
        errors=[];observed=[]
        def interact():
            box=app.activeModalWidget()
            try:
                expect(isinstance(box,W.QDialog),'missing active dialog')
                if message:
                    positive=box.button(W.QMessageBox.StandardButton.Yes)
                    negative=box.button(W.QMessageBox.StandardButton.No)
                else:
                    buttons=box.findChild(W.QDialogButtonBox)
                    positive=buttons.button(W.QDialogButtonBox.StandardButton.Ok)
                    negative=buttons.button(W.QDialogButtonBox.StandardButton.Cancel)
                expect(box.focusWidget() is negative,'initial focus is affirmative/content')
                app.setActiveWindow(box);QTest.qWait(1)
                expect(negative.hasFocus(),'decline lacks actual Qt focus')
                def state(stage):
                    expect(negative.isDefault() and not positive.isDefault(),'affirmative became default')
                    expect(not positive.autoDefault() and not negative.autoDefault(),'autoDefault enabled')
                    observations.append(dict(case=args.case,scenario=scenario,stage=stage,
                                             default=negative.text(),focus=box.focusWidget().text() if isinstance(box.focusWidget(),W.QPushButton) else type(box.focusWidget()).__name__))
                state('initial')
                if scenario in ('positive-return','positive-space','positive-escape'):
                    positive.setFocus(Qt.FocusReason.TabFocusReason);app.processEvents()
                    expect(positive.hasFocus(),'affirmative focus unavailable');state('positive focused')
                if scenario=='tab-space':
                    seen=[]
                    for _ in range(8):
                        QTest.keyClick(app.focusWidget(),Qt.Key.Key_Tab)
                        seen.append(app.focusWidget());state('tab')
                        expect(box.isVisible(),'Tab submitted the dialog')
                        if app.focusWidget() is negative:break
                    expect(positive in seen and negative in seen,'Tab failed to traverse buttons')
                    QTest.keyClick(negative,Qt.Key.Key_Tab,Qt.KeyboardModifier.ShiftModifier)
                    expect(positive.hasFocus(),'Shift+Tab failed');state('reverse tab')
                capture(args.case+'-'+scenario,box)
                if scenario=='content-return':
                    text=box.findChild(W.QTextEdit)
                    text.setFocus(Qt.FocusReason.TabFocusReason);app.processEvents()
                    expect(text.hasFocus(),'details focus unavailable');state('content focused')
                    QTest.keyClick(text,Qt.Key.Key_Return)
                    expect(not observed or observed[-1]!=int(W.QDialog.DialogCode.Accepted),'details Enter approved')
                    if box.isVisible():QTest.keyClick(text,Qt.Key.Key_Escape)
                elif scenario=='checkbox-space':
                    checkbox=box.snapshot_cb;old=checkbox.isChecked()
                    checkbox.setFocus(Qt.FocusReason.TabFocusReason);app.processEvents()
                    QTest.keyClick(checkbox,Qt.Key.Key_Space)
                    expect(checkbox.isChecked()!=old and box.isVisible(),'Space on checkbox submitted dialog')
                    state('checkbox focused');QTest.keyClick(checkbox,Qt.Key.Key_Escape)
                else:
                    key=(Qt.Key.Key_Space if scenario in ('positive-space','negative-space','tab-space')
                         else Qt.Key.Key_Escape if scenario=='positive-escape'
                         else Qt.Key.Key_Enter if scenario=='keypad-enter' else Qt.Key.Key_Return)
                    QTest.keyClick(app.focusWidget(),key)
            except Exception as exc:
                errors.append(str(exc))
                if isinstance(box,W.QDialog):box.reject()
        watchdog=QTimer();watchdog.setSingleShot(True)
        def expire():
            errors.append('modal watchdog expired')
            if app.activeModalWidget():app.activeModalWidget().reject()
        watchdog.timeout.connect(expire);watchdog.start(2500)
        QTimer.singleShot(0,interact)
        if message:
            result=ns['privileged_question'](None,'Synthetic privileged confirmation','Fixture only; no command runs.')
            expected=W.QMessageBox.StandardButton.Yes if scenario in ('positive-space','tab-space') else W.QMessageBox.StandardButton.No
        else:
            dialog.finished.connect(observed.append)
            result=dialog.exec()
            expected=W.QDialog.DialogCode.Accepted if scenario in ('positive-space','tab-space') else W.QDialog.DialogCode.Rejected
            dialog.deleteLater()
        watchdog.stop()
        expect(not errors,'; '.join(errors));expect(result==expected,f'{scenario}: unexpected result {result}')
        checks.append(args.case+' '+scenario+' passed')

    if args.case=='profile':
        profile=ns['ProfileDialog']('mixed',75);profile.show();app.setActiveWindow(profile);QTest.qWait(5)
        selected=profile.btn_group.checkedButton()
        selected.setFocus(Qt.FocusReason.TabFocusReason);app.processEvents()
        expect(selected.hasFocus(),'profile radio focus unavailable')
        buttons=profile.findChild(W.QDialogButtonBox)
        ok=buttons.button(W.QDialogButtonBox.StandardButton.Ok)
        cancel=buttons.button(W.QDialogButtonBox.StandardButton.Cancel)
        for label,widget in [('selected-radio',selected),('remember',profile.remember),('apply',ok),('cancel',cancel)]:
            expect(widget.hasFocus(),'profile Tab order: '+label)
            option=W.QStyleOptionButton();option.initFrom(widget)
            expect(bool(option.state & W.QStyle.StateFlag.State_HasFocus),'native focus state absent')
            capture('profile-focus-'+label,profile)
            observations.append(dict(case='profile',focus=label,qt_focus=True))
            QTest.keyClick(widget,Qt.Key.Key_Tab)
        expect(selected.hasFocus(),'profile focus did not wrap')
        QTest.keyClick(selected,Qt.Key.Key_Tab,Qt.KeyboardModifier.ShiftModifier)
        expect(cancel.hasFocus(),'profile reverse traversal failed')
        profile.remember.setFocus();old=profile.remember.isChecked()
        QTest.keyClick(profile.remember,Qt.Key.Key_Space)
        expect(profile.remember.isChecked()!=old and profile.isVisible(),'profile Space failed')
        selected.setFocus();QTest.keyClick(selected,Qt.Key.Key_Up)
        expect(profile.btn_group.checkedButton() is not selected,'radio arrow navigation failed')
        QTest.keyClick(profile,Qt.Key.Key_Escape)
        expect(not profile.isVisible() and profile.result()==W.QDialog.DialogCode.Rejected,'profile Escape failed')
        profile.deleteLater();checks.append('profile Tab/Shift+Tab, wrap, Space, arrows, Escape and visible-focus state passed')
    else:
        cases=['initial-enter','keypad-enter','positive-return','positive-escape','negative-space','positive-space','tab-space']
        if args.case=='preaction':cases+=['content-return','checkbox-space']
        for scenario in cases:dialog_test(scenario)
    print(json.dumps(dict(checks=checks,observations=observations,screenshots=captures)),flush=True)


if __name__=='__main__':main()
