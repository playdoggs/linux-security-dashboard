"""Capture/check current UI semantics without importing or launching the app.

python3 -B tests/capture_ui_baseline.py --output tests/fixtures/ui_baseline
python3 -B tests/capture_ui_baseline.py --check tests/fixtures/ui_baseline

Exit 1 means a production report smoke failure (even if captures match).
Exit 2 means capture mismatch. Never substitute a missing production renderer.
"""
import argparse
import ast
import datetime
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import sys
from types import MethodType, SimpleNamespace
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'
TEXT = SOURCE.read_text()
TREE = ast.parse(TEXT)
CLASSES = {n.name: n for n in TREE.body if isinstance(n, ast.ClassDef)}


class Color:
    def __init__(self, value): self.value = value
    def color(self): return self
    def name(self): return self.value


class Font:
    Weight = SimpleNamespace(Bold=1)
    def __init__(self, *args):
        self.is_bold = (args[0].is_bold if args and isinstance(args[0], Font)
                        else len(args)>2 and args[2] == self.Weight.Bold)
    def bold(self): return self.is_bold


class Item:
    def __init__(self, text):
        self.value, self.metadata = text, {}
        self.fg, self.ft = Color('#000000'), Font()
    def text(self): return self.value
    def setForeground(self, value): self.fg = value
    def foreground(self): return self.fg
    def setFont(self, value): self.ft = value
    def font(self): return self.ft
    def setData(self, role, value): self.metadata[role] = value
    def data(self, role): return self.metadata.get(role)


class Table:
    def __init__(self): self.rows, self.hidden = [], {}
    def rowCount(self): return len(self.rows)
    def insertRow(self, row): self.rows.insert(row, [None] * 6)
    def setItem(self, row, col, item): self.rows[row][col] = item
    def item(self, row, col): return self.rows[row][col]
    def setCellWidget(self, *args): pass
    def removeCellWidget(self, *args): pass
    def setRowHeight(self, *args): pass
    def setRowHidden(self, row, hidden): self.hidden[row] = hidden


class Banner:
    visible = False
    def setVisible(self, value): self.visible = value


class FixtureDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None): return cls(2026, 1, 1, 12, 0, 0, tzinfo=tz)


def load(node, namespace):
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    return namespace[node.name]


def method(name, namespace):
    return load(next(n for n in CLASSES['FindingsTable'].body
                     if isinstance(n, ast.FunctionDef) and n.name == name), namespace)


def namespace():
    ns = dict(re=re, html=html, datetime=SimpleNamespace(datetime=FixtureDateTime),
              Qt=SimpleNamespace(ItemDataRole=SimpleNamespace(UserRole=0)),
              QTableWidgetItem=Item, QColor=Color, QFont=Font,
              IGNORE_LIST=set(), UNDO_LOG=[], PKG_MGR='apt')
    constants = {'UI_TYPOGRAPHY','THEMES','PROFILES','LANGS','ASSESSMENT_STEPS','COVERAGE_STATES'}
    functions = {'assessment_complete','assessment_verdict','assessment_details',
                 '_collect_findings_by_section','_render_finding_rows','_build_exec_statement','generate_report'}
    for node in TREE.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants:
            ns[node.targets[0].id] = ast.literal_eval(node.value)
        elif isinstance(node, ast.ClassDef) and node.name == 'RiskTracker': load(node,ns)
        elif isinstance(node, ast.FunctionDef) and node.name in functions: load(node,ns)
    ns.update(T=dict(ns['THEMES']['Light']), RISK=ns['RiskTracker'](),
              fs=lambda delta=0:max(9,13+delta), L=lambda key:ns['LANGS']['EN'].get(key,key),
              TOOLS_DATA=[dict(name='fixture-tool',cat='Fixture',desc='Synthetic tool status')],
              pkg_installed=lambda name:False,
              get_system_info=lambda:{k:'fixture-'+k for k in ('hostname','os','kernel','arch','cpu','ram','uptime')})
    return ns


FINDINGS = [
    ('fixture-service <demo>','SERVICE','HIGH','Synthetic package observation; not a live host finding.'),
    ('fixture:631','NETWORK','MEDIUM','Synthetic listener observation.'),
    ('fixture-hardening','HARDENING','LOW','Synthetic hardening evidence.'),
    ('fixture-inventory','LEFTOVER','INFO','Synthetic inventory entry.'),
    ('fixture-update','OUTDATED','MEDIUM','Synthetic available update; excluded from risk score.'),
    ('fixture-cve','CVE','HIGH','Synthetic CVE observation; applicability is not asserted.'),
]


def capture(name, expert=True, populated=True, state=None, entire=False, legacy=False, switch_to=None, filter_text=None):
    ns=namespace()
    display=SimpleNamespace(table=Table(),expert_mode=expert,profile_key='mixed',
                            _bulk_depth=0,_seen_findings=set(),_ok_banner=Banner(),
                            score_changed=SimpleNamespace(emit=lambda:None),
                            _build_action_cell=lambda *args:None)
    priority = next(n.value for n in CLASSES['FindingsTable'].body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'RISK_SORT')
    display.RISK_SORT = ast.literal_eval(priority)
    for function in ('_sort_by_risk','_risk_display','_risk_colour','_get_tag','_is_duplicate',
                     'hide_all_ok_banner','show_all_ok_banner','set_assessment_coverage','add_finding','_filter_rows'):
        setattr(display,function,MethodType(method(function,ns),display))
    if populated:
        for row in FINDINGS: display.add_finding(*row)
        display.add_finding(*FINDINGS[0])  # Repeated identity must not add score/row.
    if switch_to is not None:
        ns['save_config'] = Mock()  # Record preference intent; never write user state.
        toggle = next(n for n in CLASSES['AuditDashboard'].body if isinstance(n, ast.FunctionDef) and n.name == '_toggle_mode')
        window = SimpleNamespace(findings=display, terminal=Mock())
        load(toggle,ns)(window,ns['L']('mode_expert' if switch_to else 'mode_simple'))
    if filter_text is not None:display._filter_rows(filter_text)
    outcomes=[dict(name=step,outcome='succeeded',reason='Synthetic evidence') for step in ns['ASSESSMENT_STEPS']]
    if state:
        for index in (range(7) if entire else (3,)):outcomes[index].update(outcome=state)
    if legacy:outcomes=outcomes[:3]
    coverage=dict(id='fixture-run',active=False,outcomes=outcomes)
    if name=='unknown-coverage':coverage=None
    if coverage is None:
        display._assessment_coverage=None;display.show_all_ok_banner()
    else:display.set_assessment_coverage(coverage)
    sections=ns['_collect_findings_by_section'](display)
    risk=ns['RISK']
    count=sum(x in ('HIGH','MEDIUM','LOW') for x in risk.findings)
    result=dict(initial_mode='expert' if expert else 'simple',mode='expert' if display.expert_mode else 'simple',
                visible_rows=sum(not display.table.hidden.get(i,False) for i in range(display.table.rowCount())),
                score=risk.score(),score_inputs=risk.findings,
                findings=sections,row_order=[display.table.item(i,0).text() for i in range(display.table.rowCount())],
                coverage=display._assessment_coverage,
                complete=ns['assessment_complete'](coverage),banner=display._ok_banner.visible,
                verdict=ns['assessment_verdict'](coverage,count),reports={})
    outputs={}
    for report_mode in ('executive','technical'):
        outputs[f'{name}-{report_mode}-coverage-fragment.html']=ns['_build_exec_statement'](
            risk.score(),risk.findings.count('HIGH'),risk.findings.count('MEDIUM'),risk.findings.count('LOW'),0,coverage)
        try:
            report=ns['generate_report'](display,'mixed',report_mode)
            result['reports'][report_mode]=dict(status='generated',sha256=hashlib.sha256(report.encode()).hexdigest())
            outputs[f'{name}-{report_mode}.html']=report
        except Exception as exc:
            result['reports'][report_mode]=dict(status='failed',exception=type(exc).__name__,message=str(exc))
    return result,outputs


def orchestration():
    import test_assessment_sequence as sequence
    from test_command_outcomes import method as production_method
    results={}
    for legacy in (False,True):
        case=sequence.AssessmentSequence();case.setUp()
        try:
            if legacy:
                production_method('SideBar','_run_full_scan')(case.sidebar)
                case.finish_command(sequence.ManualWorker.created[0])
                case.finish_command(sequence.ManualWorker.created[1])
                run=case.sidebar._re_run
            else:run=case.finish_run()
            results['three-step' if legacy else 'seven-step']=dict(
                outcomes=run['outcomes'],active=run['active'],finalized=run['finalized'],
                summary_calls=case.summary.call_count,
                dispatched=[worker.args[0] for worker in sequence.ManualWorker.created])
        finally:case.doCleanups()
    return results


def build():
    cases={};files={}
    options=[('expert-complete',{}),('simple-complete',dict(expert=False)),
             ('simple-then-expert',dict(expert=False,switch_to=True)),
             ('expert-then-simple',dict(switch_to=False)),
             ('expert-filtered',dict(filter_text='fixture-service')),
             ('complete-no-findings',dict(populated=False)),
             ('unknown-coverage',dict(populated=False)),
             ('all-failed',dict(populated=False,state='failed',entire=True)),
             ('legacy-three',dict(legacy=True))]
    options += [('one-'+state,dict(state=state)) for state in ('partial','failed','skipped','cancelled','unknown')]
    for name,kwargs in options:
        result,outputs=capture(name,**kwargs);cases[name]=result
        if name in ('expert-complete','simple-complete','one-skipped'):files.update(outputs)
    dump=lambda x:json.dumps(x,indent=2,ensure_ascii=False,sort_keys=True)+'\n'
    files['behaviour.json']=dump(dict(cases=cases,sequences=orchestration()))
    manifest=dict(source_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),
                  python=sys.version.split()[0],fixture_timestamp='2026-01-01T12:00:00',
                  note='Synthetic fixture data. Full-report exceptions are product failures, not successful HTML captures.')
    files['manifest.json']=dump(manifest)
    failures=sorted({(v['exception'],v['message']) for case in cases.values()
                     for v in case['reports'].values() if v['status']=='failed'})
    return files,failures


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output',type=Path);group.add_argument('--check',type=Path)
    args=parser.parse_args()
    # A fixture mistake must not launch a real host probe or subprocess.
    with (patch.object(subprocess,'run',side_effect=AssertionError('Host probes prohibited')),
          patch.object(subprocess,'Popen',side_effect=AssertionError('Subprocess execution prohibited'))):
        files,failures=build()
    if args.output:
        args.output.mkdir(parents=True,exist_ok=True)
        for name,body in files.items():(args.output/name).write_text(body,encoding='utf-8')
        print(f'Captured {len(files)} files in {args.output}')
    else:
        # Provenance changes are expected after a redesign; compare behaviour separately.
        mismatches=[name for name,body in files.items() if name!='manifest.json'
                    and (not (args.check/name).is_file() or (args.check/name).read_text(encoding='utf-8')!=body)]
        print('Capture comparison: '+('MISMATCH '+', '.join(mismatches) if mismatches else 'MATCH'))
        if mismatches:return 2
    for kind,message in failures:print(f'Production HTML report smoke: FAIL ({kind}: {message})')
    return 1 if failures else 0


if __name__=='__main__':raise SystemExit(main())
