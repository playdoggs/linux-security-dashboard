"""Pure presentation policy tests; no app import, host probes or GUI creation."""
import ast
import configparser
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'linux-security-dashboard.py'
TREE=ast.parse(SOURCE.read_text())


def contrast(a,b):
    def luminance(value):
        channels=[int(value[i:i+2],16)/255 for i in (1,3,5)]
        channels=[x/12.92 if x<=.04045 else ((x+.055)/1.055)**2.4 for x in channels]
        return sum(x*w for x,w in zip(channels,(.2126,.7152,.0722)))
    x,y=sorted((luminance(a),luminance(b)))
    return (y+.05)/(x+.05)


class UiFoundation(unittest.TestCase):
    def setUp(self):
        self.ns={}
        names={'BASE_FS','UI_METRICS','UI_TYPOGRAPHY','THEMES','T','fs','apply_theme',
               'config_bool','get_startup_theme','make_style','ThemeColor','theme_value','set_theme_style'}
        for node in TREE.body:
            name=node.name if isinstance(node,(ast.FunctionDef,ast.ClassDef)) else None
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name):name=node.targets[0].id
            if name in names:exec(compile(ast.Module(body=[node],type_ignores=[]),str(SOURCE),'exec'),self.ns)
        self.ns['apply_theme']('Enterprise Workspace')

    def test_default_and_locked_appearance_preferences(self):
        cfg=configparser.ConfigParser()
        self.assertEqual(self.ns['get_startup_theme'](cfg),'Enterprise Workspace')
        for theme in self.ns['THEMES']:
            cfg['prefs']={'theme_locked':'true','locked_theme':theme}
            self.assertEqual(self.ns['get_startup_theme'](cfg),theme)
        cfg['prefs']={'theme_locked':'true','locked_theme':'invalid'}
        self.assertEqual(self.ns['get_startup_theme'](cfg),'Enterprise Workspace')
        cfg['prefs']={'theme_locked':'false','locked_theme':'Dark'}
        self.assertEqual(self.ns['get_startup_theme'](cfg),'Enterprise Workspace')

    def test_all_seven_appearances_share_components(self):
        self.assertEqual(set(self.ns['THEMES']),{'Enterprise Workspace','Hybrid Professional','Dark','Hacker','Solarized','Light','Pink'})
        for name in self.ns['THEMES']:
            self.ns['apply_theme'](name)
            css=self.ns['make_style']()
            self.assertIn('QPushButton:focus',css)
            self.assertIn('QTableWidget::item:selected',css)
            self.assertIn("Sans Serif",css)
            self.assertNotIn('Courier New',css)
            for key in ('NAV_TEXT','NAV_DIM','NAV_ACCENT','CONTROL_BORDER','SELECTED'):
                self.assertIn(key,self.ns['T'])

    def test_hybrid_changes_navigation_not_content_palette(self):
        enterprise=dict(self.ns['T'])
        self.ns['apply_theme']('Hybrid Professional');hybrid=self.ns['T']
        for key in ('BG_DARK','BG_MID','BG_CARD','TEXT_MAIN','TEXT_DIM','ACCENT','OK','WARN','DANGER'):
            self.assertEqual(enterprise[key],hybrid[key])
        self.assertNotEqual(enterprise['SIDEBAR'],hybrid['SIDEBAR'])
        self.assertNotEqual(enterprise['NAV_TEXT'],hybrid['NAV_TEXT'])

    def test_bound_inline_styles_follow_tokens_and_keep_loop_values(self):
        widgets=[]
        for key in ('OK','DANGER'):
            widget=SimpleNamespace(setStyleSheet=lambda text:None)
            value=self.ns['theme_value'](self.ns['T'][key])
            self.ns['set_theme_style'](widget,lambda value=value:f'color:{value};')
            widgets.append(widget)
        self.ns['apply_theme']('Dark')
        self.assertEqual(widgets[0]._ui_theme_style(),f"color:{self.ns['T']['OK']};")
        self.assertEqual(widgets[1]._ui_theme_style(),f"color:{self.ns['T']['DANGER']};")
        self.assertNotEqual(widgets[0]._ui_theme_style(),widgets[1]._ui_theme_style())

    def test_professional_text_status_navigation_and_control_contrast(self):
        for name in ('Enterprise Workspace','Hybrid Professional'):
            self.ns['apply_theme'](name);p=self.ns['T']
            for key in ('TEXT_MAIN','TEXT_DIM','ACCENT','WARN','DANGER','OK'):
                self.assertGreaterEqual(contrast(p[key],p['BG_MID']),4.5,(name,key))
            for key in ('NAV_TEXT','NAV_DIM'):
                self.assertGreaterEqual(contrast(p[key],p['SIDEBAR']),4.5,(name,key))
            self.assertGreaterEqual(contrast(p['CONTROL_BORDER'],p['BG_MID']),3)

    def test_font_scale_and_geometry_tokens(self):
        self.assertEqual(self.ns['fs'](),13)
        self.ns['BASE_FS']=22
        self.assertEqual(self.ns['fs'](),22)
        self.ns['BASE_FS']=1
        self.assertEqual(self.ns['fs'](),9)
        self.assertGreaterEqual(self.ns['UI_METRICS']['row_min'],44)
        self.assertGreaterEqual(self.ns['UI_METRICS']['risk_width'],148)
        self.assertGreaterEqual(self.ns['UI_METRICS']['control_min'],32)
