"""Real report generation and finding rendering; no host probes or GUI startup."""
import html
import unittest
from unittest.mock import patch

import capture_ui_baseline as baseline


class HtmlReports(unittest.TestCase):
    def test_real_reports_preserve_simple_expert_selection_scores_and_coverage(self):
        with patch.object(baseline.subprocess,'run',side_effect=AssertionError('Host probe prohibited')):
            for expert in (True, False):
                for state in (None, 'skipped', 'partial', 'failed', 'cancelled', 'unknown'):
                    with self.subTest(expert=expert,state=state):
                        name='report-fixture'
                        data,outputs=baseline.capture(name,expert=expert,state=state)
                        self.assertEqual(data['score'],51 if expert else 48)
                        self.assertEqual(sum(map(len,data['findings'].values())),6 if expert else 4)
                        for mode in ('executive','technical'):
                            self.assertEqual(data['reports'][mode]['status'],'generated')
                            report=outputs[f'{name}-{mode}.html']
                            self.assertTrue(report.startswith('<!DOCTYPE html>'))
                            self.assertTrue(report.rstrip().endswith('</body></html>'))
                            self.assertIn('Overall Assessment',report)
                            self.assertIn('Undo / Rollback Log',report)
                            self.assertIn('fixture-service &lt;demo&gt;',report)
                            self.assertNotIn('fixture-service <demo>',report)
                            self.assertIn('fixture-cve',report)
                            self.assertEqual('fixture-hardening' in report, expert)
                            self.assertEqual('fixture-inventory' in report, expert)
                            self.assertIn('fixture-update',report)
                            self.assertIn(f'{51 if expert else 48} / 100',report)
                            self.assertIn('Complete assessment' if state is None else 'Incomplete assessment',report)
                            self.assertNotIn('this is not an all-clear' if state is None else 'Complete assessment —',report)

    def test_real_renderer_escapes_every_field_and_preserves_severity(self):
        ns=baseline.namespace()
        original=list(baseline.FINDINGS)
        payload='<script>alert("fixture")</script> & \'quoted\''
        records=[('name '+payload,ftype,'HIGH','detail '+payload)
                 for ftype in ('SERVICE','HARDENING','CVE')]
        with patch.object(baseline,'FINDINGS',records):
            data,outputs=baseline.capture('escaped',state='skipped')
        for mode in ('executive','technical'):
            report=outputs[f'escaped-{mode}.html']
            self.assertIn(html.escape(payload),report)
            self.assertNotIn('<script>',report)
            self.assertNotIn('onclick=',report)
        row={key:payload for key in ('name','ftype','risk','tag','detail')}
        fragment=ns['_render_finding_rows']([row])
        self.assertEqual(fragment.count(html.escape(payload)),5)
        self.assertNotIn('<script>',fragment)
        self.assertEqual(ns['_render_finding_rows']([]),'')
        for severity,color in [('HIGH','#ff4444'),('MEDIUM','#f0a500'),('LOW','#3fb950'),('INFO','#00d9ff')]:
            row=dict(name='fixture',ftype='SERVICE',risk='symbol '+severity,tag='SERVICE',detail='fixture')
            self.assertIn(color,ns['_render_finding_rows']([row]))
        self.assertEqual(baseline.FINDINGS,original)

    def test_filtering_keeps_report_rows_and_mode_switch_does_not_backfill(self):
        data,reports=baseline.capture('filtered',filter_text='fixture-service')
        self.assertEqual(data['visible_rows'],1)
        self.assertEqual(data['score'],51)
        for mode in ('executive','technical'):
            self.assertIn('fixture-cve',reports[f'filtered-{mode}.html'])
            self.assertIn('fixture-hardening',reports[f'filtered-{mode}.html'])
        data,reports=baseline.capture('switched',expert=False,switch_to=True)
        self.assertEqual(data['score'],48)
        for mode in ('executive','technical'):
            self.assertNotIn('fixture-hardening',reports[f'switched-{mode}.html'])

    def test_empty_and_unknown_coverage_reports_generate_without_false_clean(self):
        data,reports=baseline.capture('unknown-coverage',populated=False)
        for mode in ('executive','technical'):
            report=reports[f'unknown-coverage-{mode}.html']
            self.assertIn('coverage is unknown',report)
            self.assertNotIn('Complete assessment —',report)
            self.assertIn('0 / 100',report)
