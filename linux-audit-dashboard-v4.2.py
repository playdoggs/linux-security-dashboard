#!/usr/bin/env python3
"""
Linux Audit Dashboard v4.2
A security health check tool for Linux — plain English, no jargon.
Built by playdoggy 2026 — my first vibe app 🎮
https://github.com/playdoggs/linux-audit-dashboard

This app scans your Linux system for security issues, explains them
in plain English, and lets you fix them safely with full confirmation
before anything is changed on your system.
"""

# ── Standard library imports ──────────────────────────────────────────────────
import sys          # System exit and app startup
import os           # Environment variables and file path checks
import re           # Regular expressions for parsing command output
import json         # Reading/writing the undo log file
import subprocess   # Running shell commands safely
import urllib.request, urllib.parse  # Fetching CVE data from the internet
import datetime     # Timestamps for the undo log and session summary
import time         # Small retry backoff delays for network calls
import socket       # Detect timeout/network errors from urllib layers
import base64       # Decoding the embedded face images
import html         # Safely escaping text in the HTML report
import logging      # Writing errors to a log file without crashing the app
import configparser # Reading and writing the user's saved preferences
import shutil       # Checking if external tools (like pkexec) are installed
from pathlib import Path  # Clean cross-platform file path handling

# ── PyQt6 GUI imports ─────────────────────────────────────────────────────────
# PyQt6 is the Python wrapper around Qt6 — a professional cross-platform
# GUI toolkit. Install with: pip install PyQt6 --break-system-packages
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QLabel,
    QSplitter, QTabWidget, QHeaderView, QMessageBox, QFrame, QProgressBar,
    QDialog, QDialogButtonBox, QScrollArea, QComboBox, QStatusBar,
    QFileDialog, QListWidget, QListWidgetItem, QStackedWidget,
    QRadioButton, QButtonGroup, QLineEdit, QCheckBox, QGroupBox,
    QSizePolicy, QScrollBar, QInputDialog, QSplitterHandle
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
# QShortcut is in QtGui in PyQt6 (moved from QtWidgets in Qt5)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QTextCursor, QPixmap,
    QKeySequence, QShortcut, QPainter
)

# ── File paths for persistent data ────────────────────────────────────────────
# All stored in the user's home directory so no root access is needed
LOG_FILE      = Path.home() / ".audit-dashboard-errors.log"
CONFIG_FILE   = Path.home() / ".audit-dashboard.conf"
UNDO_LOG_FILE = Path.home() / ".audit-dashboard-undo.log"

def init_logging():
    """
    Configure error logging with safe fallbacks.
    Prefer the home-directory log, then /tmp, then stderr-only logging.
    """
    fmt = "%(asctime)s %(levelname)s %(message)s"
    candidates = [LOG_FILE, Path("/tmp/.audit-dashboard-errors.log")]
    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            logging.basicConfig(filename=str(candidate), level=logging.ERROR, format=fmt, force=True)
            return candidate
        except OSError:
            continue
    logging.basicConfig(level=logging.ERROR, format=fmt, force=True)
    return None

# Set up error logging — errors go to a file when possible and never crash startup
ACTIVE_LOG_FILE = init_logging()

# ── Config file helpers ───────────────────────────────────────────────────────
def load_config():
    """Load the user's saved preferences from disk."""
    c = configparser.ConfigParser()
    c.read(str(CONFIG_FILE))
    return c

def save_config(section, key, value):
    """Save a single preference to disk. Uses a temp file to avoid corruption."""
    c = load_config()
    if section not in c:
        c[section] = {}
    c[section][key] = str(value)
    # Write to a temp file first, then rename — this is atomic and safe
    tmp = CONFIG_FILE.with_suffix(".tmp")
    with open(str(tmp), "w") as f:
        c.write(f)
    tmp.replace(CONFIG_FILE)  # Atomic rename — no partial writes

def config_bool(value, default=False):
    """Parse config string/bool into True/False safely."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}

def get_startup_theme(cfg):
    """
    Startup rule:
    - Default to Light every launch
    - Unless the user locked a theme, in which case use the locked theme
    """
    locked = config_bool(cfg.get("prefs", "theme_locked", fallback="false"))
    if locked:
        locked_theme = cfg.get("prefs", "locked_theme", fallback="Light")
        if locked_theme in THEMES:
            return locked_theme
    return "Light"

# ── Input validation ──────────────────────────────────────────────────────────
# Only allow valid Linux package names — prevents command injection attacks
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9.+\-]{0,99}$")
def valid_pkg(name):
    """Return True only if the name looks like a real package name."""
    return bool(PKG_RE.match(name.strip()))

# Strip ANSI colour codes from terminal output before displaying in the GUI
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[[\d;]+m")
def strip_ansi(t):
    """Remove terminal colour escape codes from a string."""
    return ANSI_RE.sub("", t)

# ── Global font size (accessibility) ─────────────────────────────────────────
# Users can increase/decrease the font with A+/A- buttons.
# This rebuilds the entire stylesheet so every widget updates at once.
BASE_FS = 13  # Default font size in pixels
def fs(delta=0):
    """Return the current font size, optionally offset by delta pixels."""
    return max(9, BASE_FS + delta)  # Never go below 9px — unreadable

# ── Themes ────────────────────────────────────────────────────────────────────
# Each theme is a dictionary of colour codes. T is the active theme.
# apply_theme() updates T and make_style() rebuilds the stylesheet.
THEMES = {
    "Dark": {
        "BG_DARK":"#0d1117","BG_MID":"#161b22","BG_CARD":"#21262d",
        "ACCENT":"#00d9ff","WARN":"#f0a500","DANGER":"#ff4444","OK":"#3fb950",
        "TEXT_MAIN":"#e6edf3","TEXT_DIM":"#8b949e","BORDER":"#30363d","SIDEBAR":"#0d1117"
    },
    "Hacker": {
        "BG_DARK":"#000000","BG_MID":"#0a0a0a","BG_CARD":"#111111",
        "ACCENT":"#00ff41","WARN":"#ffff00","DANGER":"#ff0000","OK":"#00ff41",
        "TEXT_MAIN":"#00ff41","TEXT_DIM":"#005f1a","BORDER":"#003b10","SIDEBAR":"#000000"
    },
    "Solarized": {
        "BG_DARK":"#002b36","BG_MID":"#073642","BG_CARD":"#073642",
        "ACCENT":"#268bd2","WARN":"#cb4b16","DANGER":"#dc322f","OK":"#859900",
        "TEXT_MAIN":"#839496","TEXT_DIM":"#586e75","BORDER":"#073642","SIDEBAR":"#002b36"
    },
    "Light": {
        "BG_DARK":"#ffffff","BG_MID":"#f6f8fa","BG_CARD":"#eaeef2",
        "ACCENT":"#0969da","WARN":"#9a6700","DANGER":"#cf222e","OK":"#1a7f37",
        "TEXT_MAIN":"#24292f","TEXT_DIM":"#57606a","BORDER":"#d0d7de","SIDEBAR":"#f6f8fa"
    },
    "Pink": {
        "BG_DARK":"#1a0a1a","BG_MID":"#2a0a2a","BG_CARD":"#3a1a3a",
        "ACCENT":"#ff69b4","WARN":"#ff9f40","DANGER":"#ff2255","OK":"#aa44ff",
        "TEXT_MAIN":"#ffe0f0","TEXT_DIM":"#cc88aa","BORDER":"#5a2a5a","SIDEBAR":"#1a0a1a"
    },
}
T = dict(THEMES["Dark"])  # Start with Dark theme

def apply_theme(name):
    """Switch the active theme. Call make_style() after to update the UI."""
    global T
    T.update(THEMES.get(name, THEMES["Dark"]))

def build_palette():
    """Build a QPalette from the current theme T.
    Sets ALL the roles Fusion uses to draw frames and bevels — not just the
    basic ones.  Without Mid/Dark/Shadow/Midlight the Fusion renderer derives
    them from Window, producing dark borders on a white Light-mode background.
    Call this whenever apply_theme() is called."""
    p = QPalette()
    for role, col in [
        (QPalette.ColorRole.Window,           T["BG_DARK"]),
        (QPalette.ColorRole.WindowText,       T["TEXT_MAIN"]),
        (QPalette.ColorRole.Base,             T["BG_MID"]),
        (QPalette.ColorRole.AlternateBase,    T["BG_CARD"]),
        (QPalette.ColorRole.Text,             T["TEXT_MAIN"]),
        (QPalette.ColorRole.BrightText,       T["TEXT_MAIN"]),
        (QPalette.ColorRole.Button,           T["BG_CARD"]),
        (QPalette.ColorRole.ButtonText,       T["TEXT_MAIN"]),
        (QPalette.ColorRole.Highlight,        T["ACCENT"]),
        (QPalette.ColorRole.HighlightedText,  T["BG_DARK"]),
        (QPalette.ColorRole.Link,             T["ACCENT"]),
        (QPalette.ColorRole.ToolTipBase,      T["BG_CARD"]),
        (QPalette.ColorRole.ToolTipText,      T["TEXT_MAIN"]),
        (QPalette.ColorRole.PlaceholderText,  T["TEXT_DIM"]),
        # Frame/bevel roles — Fusion uses these for widget borders, scrollbar
        # troughs, and button shadows.  Map them to our border/dim colors so
        # they look right in both dark and light themes.
        (QPalette.ColorRole.Light,            T["BG_DARK"]),
        (QPalette.ColorRole.Midlight,         T["BG_CARD"]),
        (QPalette.ColorRole.Mid,              T["BORDER"]),
        (QPalette.ColorRole.Dark,             T["BORDER"]),
        (QPalette.ColorRole.Shadow,           T["TEXT_DIM"]),
    ]:
        p.setColor(role, QColor(col))
    return p

def make_style():
    """Build and return the complete Qt stylesheet string for the current theme.
    Called whenever the theme changes or font size changes."""
    f = BASE_FS
    return f"""
/* ── Base widget styles ── */
QMainWindow, QWidget {{
    background: {T['BG_DARK']};
    color: {T['TEXT_MAIN']};
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: {f}px;
}}
/* ── Tab bar ── */
QTabWidget::pane {{
    border: 1px solid {T['BORDER']};
    background: {T['BG_MID']};
    border-radius: 0 6px 6px 6px;
}}
QTabBar::tab {{
    background: {T['BG_CARD']};
    color: {T['TEXT_DIM']};
    padding: 8px 14px;
    border: 1px solid {T['BORDER']};
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    margin-right: 2px;
    font-size: {f-1}px;
    min-width: 80px;
}}
QTabBar::tab:selected {{
    background: {T['BG_MID']};
    color: {T['ACCENT']};
    border-bottom: 2px solid {T['ACCENT']};
    font-weight: bold;
}}
QTabBar::tab:hover {{ color: {T['ACCENT']}; }}
/* ── Buttons — default style ── */
QPushButton {{
    background: {T['BG_CARD']};
    color: {T['ACCENT']};
    border: 1px solid {T['ACCENT']};
    border-radius: 4px;
    padding: 6px 14px;
    font-size: {f-1}px;
}}
QPushButton:hover {{ background: {T['ACCENT']}; color: {T['BG_DARK']}; }}
QPushButton:disabled {{ color: {T['TEXT_DIM']}; border-color: {T['BORDER']}; }}
/* ── Button colour variants ── */
QPushButton#danger {{ color: {T['DANGER']}; border-color: {T['DANGER']}; }}
QPushButton#danger:hover {{ background: {T['DANGER']}; color: #ffffff; }}
QPushButton#warn {{ color: {T['WARN']}; border-color: {T['WARN']}; }}
QPushButton#warn:hover {{ background: {T['WARN']}; color: {T['BG_DARK']}; }}
QPushButton#ok {{ color: {T['OK']}; border-color: {T['OK']}; }}
QPushButton#ok:hover {{ background: {T['OK']}; color: {T['BG_DARK']}; }}
QPushButton#neutral {{ color: {T['TEXT_DIM']}; border-color: {T['BORDER']}; }}
QPushButton#neutral:hover {{ background: {T['BG_CARD']}; color: {T['TEXT_MAIN']}; }}
/* ── Sidebar section buttons — left accent border instead of full border ── */
QPushButton#section_btn {{
    background: {T['BG_MID']};
    color: {T['TEXT_MAIN']};
    border: none;
    border-left: 3px solid {T['ACCENT']};
    border-top: 1px solid {T['BORDER']};
    border-radius: 0;
    padding: 8px 10px;
    font-size: {f-1}px;
    font-weight: bold;
    text-align: left;
}}
QPushButton#section_btn:hover {{
    background: {T['BG_CARD']};
    border-left: 3px solid {T['WARN']};
}}
/* ── Text areas and lists ── */
QTextEdit, QListWidget {{
    background: {T['BG_DARK']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: {f-1}px;
    padding: 6px;
}}
QLineEdit {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: {f-1}px;
}}
QInputDialog QLineEdit {{
    background: #ffffff;
    color: #1a1a1a;
    border: 2px solid {T['ACCENT']};
    border-radius: 4px;
    padding: 6px 8px;
    font-size: {f}px;
}}
/* ── Tables ── */
QTableWidget {{
    background: {T['BG_MID']};
    gridline-color: {T['BORDER']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    font-size: {f-1}px;
}}
QTableWidget::item {{ padding: 6px 8px; border-bottom: 1px solid {T['BORDER']}; }}
QTableWidget QTableView {{ alternate-background-color: {T['BG_DARK']}; }}
QTableWidget::item:selected {{ background: {T['ACCENT']}; color: {T['BG_DARK']}; }}
QHeaderView::section {{
    background: {T['BG_CARD']};
    color: {T['TEXT_DIM']};
    border: none;
    border-right: 1px solid {T['BORDER']};
    border-bottom: 1px solid {T['BORDER']};
    padding: 6px 8px;
    font-size: {f-2}px;
    letter-spacing: 1px;
}}
/* ── Scroll bars ── */
QScrollBar:vertical {{ background: {T['BG_MID']}; width: 10px; border-radius: 5px; }}
QScrollBar::handle:vertical {{ background: {T['BORDER']}; border-radius: 5px; min-height: 20px; }}
QScrollBar:horizontal {{ background: {T['BG_MID']}; height: 10px; }}
QScrollBar::handle:horizontal {{ background: {T['BORDER']}; border-radius: 5px; }}
/* ── Splitter handles — the draggable dividers between panels ── */
QSplitter::handle:vertical {{ background: {T['ACCENT']}; height: 10px; border-radius: 4px; }}
QSplitter::handle:vertical:hover {{ background: {T['WARN']}; }}
QSplitter::handle:horizontal {{ background: {T['BORDER']}; width: 10px; border-radius: 4px; }}
QSplitter::handle:horizontal:hover {{ background: {T['ACCENT']}; }}
/* ── Toolbar and risk bar — objectName-targeted so theme changes update them ── */
QWidget#toolbar_bar {{
    background: {T['BG_MID']};
    border-bottom: 1px solid {T['BORDER']};
}}
QWidget#risk_panel_bar {{
    background: {T['BG_MID']};
    border-bottom: 2px solid {T['BORDER']};
}}
QWidget#sidebar_info_box {{
    background: {T['BG_CARD']};
    border-top: 1px solid {T['BORDER']};
}}
QWidget#sidebar_widget {{
    background: {T['SIDEBAR']};
}}
QWidget#terminal_hdr {{
    background: {T['BG_CARD']};
    border-top: 2px solid {T['BORDER']};
}}
QWidget#findings_hdr {{
    background: {T['BG_CARD']};
    border-bottom: 1px solid {T['BORDER']};
}}
QFrame#tool_card {{
    background: {T['BG_CARD']};
    border: 1px solid {T['BORDER']};
    border-radius: 6px;
    margin: 2px;
}}
/* ── Label styles ── */
QLabel#heading {{ color: {T['ACCENT']}; font-size: {f+1}px; letter-spacing: 2px; padding: 4px 0; font-weight: bold; }}
QLabel#app_title {{ color: {T['ACCENT']}; font-size: {f}px; letter-spacing: 1px; font-weight: bold; }}
QLabel#section_title {{ color: {T['TEXT_MAIN']}; font-size: {f-1}px; letter-spacing: 1px; padding: 2px 4px; font-weight: bold; background: {T['BG_MID']}; border-left: 3px solid {T['ACCENT']}; }}
QLabel#section_sub {{ color: {T['TEXT_DIM']}; font-size: {f-3}px; padding: 0 8px 4px 14px; background: {T['BG_MID']}; border-left: 3px solid {T['ACCENT']}; }}
QLabel#status {{ color: {T['TEXT_DIM']}; font-size: {f-1}px; padding: 2px 6px; }}
/* ── Progress bar (the risk score bar) ── */
QProgressBar {{
    border: 1px solid {T['BORDER']};
    border-radius: 6px;
    background: {T['BG_CARD']};
    height: 24px;
    text-align: center;
    font-size: {f}px;
    font-weight: bold;
    color: {T['TEXT_MAIN']};
}}
QProgressBar::chunk {{ border-radius: 5px; }}
/* ── Dropdowns ── */
QComboBox {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: {f-1}px;
}}
QComboBox::drop-down {{ border: none; }}
QComboBox QAbstractItemView {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    selection-background-color: {T['ACCENT']};
    selection-color: {T['BG_DARK']};
}}
/* ── Tooltips ── */
QToolTip {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['ACCENT']};
    padding: 6px;
    font-size: {f-1}px;
    border-radius: 4px;
}}
/* ── Dialogs ── */
QDialog {{ background: {T['BG_MID']}; color: {T['TEXT_MAIN']}; }}
/* ── Status bar at the bottom of the app ── */
QStatusBar {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    font-size: {f}px;
    border-top: 2px solid {T['BORDER']};
    min-height: 30px;
    padding: 4px 8px;
}}
/* ── Group boxes (bordered sections in dialogs) ── */
QGroupBox {{
    border: 1px solid {T['BORDER']};
    border-radius: 6px;
    margin-top: 12px;
    font-size: {f-1}px;
    color: {T['TEXT_DIM']};
    padding: 8px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {T['ACCENT']};
    font-size: {f-1}px;
}}
"""

# ── Languages (12 supported) ──────────────────────────────────────────────────
# Each language is a dict of UI string keys to translated values.
# Add more by copying one block and translating the values.
LANGS = {
    "EN": {
        "title":"LINUX AUDIT DASHBOARD v4.2",
        "findings_hdr":"FINDINGS — double-click any row for a plain English explanation",
        "terminal_hdr":"TERMINAL OUTPUT",
        "risk_label":"SYSTEM HEALTH",
        "mode_simple":"Simple Mode",
        "mode_expert":"Expert Mode",
        "update_ok":"System is up to date 👍",
        "update_week":"Getting a bit dusty...",
        "update_two_weeks":"Your system feels neglected 😬",
        "update_month":"Mate. Come on. 😅",
        "update_ancient":"Abandoned like a gym membership in February 💀",
        "built_by":"Built by playdoggy 2026 — my first vibe app 🎮",
        "sec_scan":"SCAN YOUR SYSTEM",
        "sec_scan_sub":"What software is installed?",
        "sec_checks":"SECURITY CHECKS",
        "sec_checks_sub":"How is your OS configured?",
        "sec_cve":"CVE VULNERABILITY CHECK",
        "sec_cve_sub":"Known vulnerabilities in your software",
        "sec_tools":"RECOMMENDED TOOLS",
        "sec_tools_sub":"Extra security tools worth having",
        "sec_undo":"UNDO / ROLLBACK",
        "sec_undo_sub":"Review and reverse app actions",
        "btn_unused":"🔍  Scan for Unused Software",
        "btn_network":"📡  Check Open Ports",
        "btn_services":"⚠   Check Risky Services",
        "btn_installed":"📦  List All Installed",
        "btn_os_installed":"📦  OS Pre-installed Software",
        "btn_user_installed":"📦  User Installed Software",
        "btn_fullscan":"🔒  RUN FULL SCAN",
        "btn_quick":"⚡  Quick Security Checks",
        "btn_lynis":"🛡  Run Lynis Full Audit",
        "btn_wizard":"🔧  Step-by-Step Fix Wizard",
        "btn_cve":"🎯  Check for Known Vulnerabilities",
        "btn_upgrades":"📋  Check for Available Updates",
        "btn_tools":"🧰  View Recommended Tools",
        "btn_undo":"↩  View Undo / Rollback Log",
        "tab_findings":"⚠  FINDINGS",
        "tab_cve":"🛡  CVE CHECK",
        "tab_lynis":"🔒  LYNIS",
        "tab_tools":"🧰  TOOLS",
        "tab_undo":"↩  UNDO LOG",
    },
    "DE": {
        "title":"LINUX AUDIT DASHBOARD v4.2",
        "findings_hdr":"BEFUNDE — Doppelklick für Erklärung",
        "terminal_hdr":"TERMINAL AUSGABE","risk_label":"SYSTEMGESUNDHEIT",
        "mode_simple":"Einfacher Modus","mode_expert":"Experten Modus",
        "update_ok":"System ist aktuell 👍","update_week":"Wird etwas staubig...",
        "update_two_weeks":"Dein System fühlt sich vernachlässigt 😬",
        "update_month":"Alter. Bitte. 😅","update_ancient":"Vergessen wie ein Fitnessstudio-Abo 💀",
        "built_by":"Gebaut von playdoggy 2026 🎮",
        "sec_scan":"SYSTEM SCANNEN","sec_scan_sub":"Prüft OS-Basis — vorinstallierte Komponenten",
        "sec_checks":"SICHERHEITSPRÜFUNGEN","sec_checks_sub":"Prüft OS-Konfiguration — Einstellungen, Berechtigungen",
        "sec_cve":"CVE SCHWACHSTELLENPRÜFUNG","sec_cve_sub":"Prüft Software gegen bekannte Sicherheitslücken",
        "sec_tools":"EMPFOHLENE WERKZEUGE","sec_tools_sub":"Zusätzliche Sicherheits- und Überwachungswerkzeuge",
        "sec_undo":"RÜCKGÄNGIG / ROLLBACK","sec_undo_sub":"Aktionen dieser App überprüfen und rückgängig machen",
        "btn_unused":"🔍  Ungenutzte Software suchen","btn_network":"📡  Offene Ports prüfen",
        "btn_services":"⚠   Riskante Dienste prüfen","btn_installed":"📦  Alle installierten auflisten",
        "btn_fullscan":"🔒  VOLLSTÄNDIGEN SCAN STARTEN","btn_quick":"⚡  Schnelle Sicherheitsprüfungen",
        "btn_lynis":"🛡  Lynis vollständig ausführen","btn_wizard":"🔧  Schritt-für-Schritt Reparatur",
        "btn_cve":"🎯  Bekannte Schwachstellen prüfen","btn_upgrades":"📋  Updates prüfen",
        "btn_tools":"🧰  Empfohlene Werkzeuge anzeigen","btn_undo":"↩  Rückgängig-Protokoll anzeigen",
        "tab_findings":"⚠  BEFUNDE","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS",
        "tab_tools":"🧰  WERKZEUGE","tab_undo":"↩  RÜCKGÄNGIG",
    },
    "ES": {
        "title":"PANEL DE AUDITORÍA LINUX v4.2",
        "findings_hdr":"HALLAZGOS — doble clic para explicación",
        "terminal_hdr":"SALIDA DE TERMINAL","risk_label":"SALUD DEL SISTEMA",
        "mode_simple":"Modo Simple","mode_expert":"Modo Experto",
        "update_ok":"Sistema actualizado 👍","update_week":"Se está poniendo algo polvoriento...",
        "update_two_weeks":"Tu sistema se siente abandonado 😬",
        "update_month":"Colega. Por favor. 😅","update_ancient":"Abandonado como membresía de gimnasio 💀",
        "built_by":"Construido por playdoggy 2026 🎮",
        "sec_scan":"ESCANEAR SISTEMA","sec_scan_sub":"Verifica la base del SO — componentes preinstalados",
        "sec_checks":"VERIFICACIONES DE SEGURIDAD","sec_checks_sub":"Verifica configuración del SO — ajustes, permisos",
        "sec_cve":"VERIFICACIÓN CVE","sec_cve_sub":"Verifica software contra vulnerabilidades conocidas",
        "sec_tools":"HERRAMIENTAS RECOMENDADAS","sec_tools_sub":"Herramientas adicionales de seguridad y monitoreo",
        "sec_undo":"DESHACER / ROLLBACK","sec_undo_sub":"Revisar y revertir acciones tomadas por esta app",
        "btn_unused":"🔍  Buscar software no usado","btn_network":"📡  Verificar puertos abiertos",
        "btn_services":"⚠   Verificar servicios riesgosos","btn_installed":"📦  Listar todos instalados",
        "btn_fullscan":"🔒  EJECUTAR ANÁLISIS COMPLETO","btn_quick":"⚡  Verificaciones rápidas",
        "btn_lynis":"🛡  Ejecutar auditoría Lynis","btn_wizard":"🔧  Asistente de corrección",
        "btn_cve":"🎯  Verificar vulnerabilidades","btn_upgrades":"📋  Verificar actualizaciones",
        "btn_tools":"🧰  Ver herramientas recomendadas","btn_undo":"↩  Ver registro de deshacer",
        "tab_findings":"⚠  HALLAZGOS","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS",
        "tab_tools":"🧰  HERRAMIENTAS","tab_undo":"↩  DESHACER",
    },
    "FR": {
        "title":"TABLEAU DE BORD v4.2",
        "findings_hdr":"RÉSULTATS — double-clic pour explication",
        "terminal_hdr":"SORTIE DU TERMINAL","risk_label":"SANTÉ DU SYSTÈME",
        "mode_simple":"Mode Simple","mode_expert":"Mode Expert",
        "update_ok":"Système à jour 👍","update_week":"Ça commence à prendre la poussière...",
        "update_two_weeks":"Votre système se sent négligé 😬",
        "update_month":"Allez. Vraiment. 😅","update_ancient":"Abandonné comme abonnement de gym 💀",
        "built_by":"Construit par playdoggy 2026 🎮",
        "sec_scan":"ANALYSER LE SYSTÈME","sec_scan_sub":"Vérifie la base du système — composants préinstallés",
        "sec_checks":"VÉRIFICATIONS DE SÉCURITÉ","sec_checks_sub":"Vérifie la configuration — paramètres, permissions",
        "sec_cve":"VÉRIFICATION CVE","sec_cve_sub":"Vérifie les logiciels contre les vulnérabilités connues",
        "sec_tools":"OUTILS RECOMMANDÉS","sec_tools_sub":"Outils supplémentaires de sécurité et surveillance",
        "sec_undo":"ANNULER / ROLLBACK","sec_undo_sub":"Examiner et inverser les actions de cette app",
        "btn_unused":"🔍  Chercher logiciels inutilisés","btn_network":"📡  Vérifier ports ouverts",
        "btn_services":"⚠   Vérifier services risqués","btn_installed":"📦  Lister tous installés",
        "btn_fullscan":"🔒  LANCER ANALYSE COMPLÈTE","btn_quick":"⚡  Vérifications rapides",
        "btn_lynis":"🛡  Exécuter audit Lynis","btn_wizard":"🔧  Assistant de correction",
        "btn_cve":"🎯  Vérifier vulnérabilités","btn_upgrades":"📋  Vérifier mises à jour",
        "btn_tools":"🧰  Voir outils recommandés","btn_undo":"↩  Voir journal d'annulation",
        "tab_findings":"⚠  RÉSULTATS","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS",
        "tab_tools":"🧰  OUTILS","tab_undo":"↩  ANNULER",
    },
    "PT": {"title":"PAINEL DE AUDITORIA LINUX v4.2","findings_hdr":"RESULTADOS — clique duplo para explicação","terminal_hdr":"SAÍDA DO TERMINAL","risk_label":"SAÚDE DO SISTEMA","mode_simple":"Modo Simples","mode_expert":"Modo Expert","update_ok":"Sistema atualizado 👍","update_week":"Ficando um pouco empoeirado...","update_two_weeks":"Seu sistema se sente negligenciado 😬","update_month":"Cara. Vamos lá. 😅","update_ancient":"Abandonado como plano de academia 💀","built_by":"Criado por playdoggy 2026 🎮","sec_scan":"ESCANEAR SISTEMA","sec_scan_sub":"Verifica a base do SO — componentes pré-instalados","sec_checks":"VERIFICAÇÕES DE SEGURANÇA","sec_checks_sub":"Verifica configuração do SO — configurações, permissões","sec_cve":"VERIFICAÇÃO CVE","sec_cve_sub":"Verifica software contra vulnerabilidades conhecidas","sec_tools":"FERRAMENTAS RECOMENDADAS","sec_tools_sub":"Ferramentas adicionais de segurança e monitoramento","sec_undo":"DESFAZER / ROLLBACK","sec_undo_sub":"Revisar e reverter ações desta app","btn_unused":"🔍  Buscar software não utilizado","btn_network":"📡  Verificar portas abertas","btn_services":"⚠   Verificar serviços arriscados","btn_installed":"📦  Listar todos instalados","btn_fullscan":"🔒  EXECUTAR ANÁLISE COMPLETA","btn_quick":"⚡  Verificações rápidas","btn_lynis":"🛡  Executar auditoria Lynis","btn_wizard":"🔧  Assistente de correção","btn_cve":"🎯  Verificar vulnerabilidades","btn_upgrades":"📋  Verificar atualizações","btn_tools":"🧰  Ver ferramentas recomendadas","btn_undo":"↩  Ver registro de desfazer","tab_findings":"⚠  RESULTADOS","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  FERRAMENTAS","tab_undo":"↩  DESFAZER"},
    "IT": {"title":"CRUSCOTTO AUDIT LINUX v4.2","findings_hdr":"RISULTATI — doppio clic per spiegazione","terminal_hdr":"OUTPUT TERMINALE","risk_label":"SALUTE DEL SISTEMA","mode_simple":"Modalità Semplice","mode_expert":"Modalità Esperto","update_ok":"Sistema aggiornato 👍","update_week":"Si sta un po' impolverando...","update_two_weeks":"Il tuo sistema si sente trascurato 😬","update_month":"Dai. Andiamo. 😅","update_ancient":"Abbandonato come iscrizione in palestra 💀","built_by":"Creato da playdoggy 2026 🎮","sec_scan":"SCANSIONA SISTEMA","sec_scan_sub":"Verifica la base del SO — componenti preinstallati","sec_checks":"CONTROLLI DI SICUREZZA","sec_checks_sub":"Verifica configurazione SO — impostazioni, permessi","sec_cve":"CONTROLLO CVE","sec_cve_sub":"Verifica il software rispetto alle vulnerabilità note","sec_tools":"STRUMENTI CONSIGLIATI","sec_tools_sub":"Strumenti aggiuntivi di sicurezza e monitoraggio","sec_undo":"ANNULLA / ROLLBACK","sec_undo_sub":"Esaminare e invertire le azioni di questa app","btn_unused":"🔍  Cercare software non usato","btn_network":"📡  Controllare porte aperte","btn_services":"⚠   Controllare servizi rischiosi","btn_installed":"📦  Elencare tutti i installati","btn_fullscan":"🔒  ESEGUIRE SCANSIONE COMPLETA","btn_quick":"⚡  Controlli rapidi","btn_lynis":"🛡  Eseguire audit Lynis","btn_wizard":"🔧  Procedura guidata","btn_cve":"🎯  Controllare vulnerabilità","btn_upgrades":"📋  Controllare aggiornamenti","btn_tools":"🧰  Vedere strumenti consigliati","btn_undo":"↩  Vedere registro annullamento","tab_findings":"⚠  RISULTATI","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  STRUMENTI","tab_undo":"↩  ANNULLA"},
    "NL": {"title":"LINUX AUDIT DASHBOARD v4.2","findings_hdr":"BEVINDINGEN — dubbelklik voor uitleg","terminal_hdr":"TERMINAL UITVOER","risk_label":"SYSTEEMGEZONDHEID","mode_simple":"Eenvoudige Modus","mode_expert":"Expert Modus","update_ok":"Systeem is up-to-date 👍","update_week":"Het wordt een beetje stoffig...","update_two_weeks":"Je systeem voelt zich verwaarloosd 😬","update_month":"Kom op nou. 😅","update_ancient":"Verlaten als een sportschoolabonnement 💀","built_by":"Gemaakt door playdoggy 2026 🎮","sec_scan":"SYSTEEM SCANNEN","sec_scan_sub":"Controleert OS-basis — voorgeïnstalleerde componenten","sec_checks":"BEVEILIGINGSCONTROLES","sec_checks_sub":"Controleert OS-configuratie — instellingen, rechten","sec_cve":"CVE KWETSBAARHEIDSCHECK","sec_cve_sub":"Controleert software tegen bekende kwetsbaarheden","sec_tools":"AANBEVOLEN HULPMIDDELEN","sec_tools_sub":"Extra beveiligings- en monitoringtools","sec_undo":"ONGEDAAN / ROLLBACK","sec_undo_sub":"Acties van deze app bekijken en terugdraaien","btn_unused":"🔍  Ongebruikte software zoeken","btn_network":"📡  Open poorten controleren","btn_services":"⚠   Risicovolle services","btn_installed":"📦  Alle geïnstalleerd","btn_fullscan":"🔒  VOLLEDIGE SCAN UITVOEREN","btn_quick":"⚡  Snelle controles","btn_lynis":"🛡  Lynis audit uitvoeren","btn_wizard":"🔧  Stap-voor-stap wizard","btn_cve":"🎯  Kwetsbaarheden controleren","btn_upgrades":"📋  Updates controleren","btn_tools":"🧰  Aanbevolen tools bekijken","btn_undo":"↩  Ongedaan-log bekijken","tab_findings":"⚠  BEVINDINGEN","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  TOOLS","tab_undo":"↩  ONGEDAAN"},
    "PL": {"title":"PULPIT AUDYTU LINUX v4.2","findings_hdr":"WYNIKI — podwójne kliknięcie dla wyjaśnienia","terminal_hdr":"WYJŚCIE TERMINALA","risk_label":"ZDROWIE SYSTEMU","mode_simple":"Tryb Prosty","mode_expert":"Tryb Eksperta","update_ok":"System jest aktualny 👍","update_week":"Zaczyna się trochę kurzyć...","update_two_weeks":"Twój system czuje się zaniedbany 😬","update_month":"No dalej. Serio. 😅","update_ancient":"Porzucony jak karnet na siłownię 💀","built_by":"Zbudowany przez playdoggy 2026 🎮","sec_scan":"SKANUJ SYSTEM","sec_scan_sub":"Sprawdza bazę OS — preinstalowane komponenty","sec_checks":"KONTROLE BEZPIECZEŃSTWA","sec_checks_sub":"Sprawdza konfigurację OS — ustawienia, uprawnienia","sec_cve":"SPRAWDZANIE CVE","sec_cve_sub":"Sprawdza oprogramowanie pod kątem znanych podatności","sec_tools":"ZALECANE NARZĘDZIA","sec_tools_sub":"Dodatkowe narzędzia bezpieczeństwa i monitoringu","sec_undo":"COFNIJ / ROLLBACK","sec_undo_sub":"Przejrzyj i cofnij działania tej aplikacji","btn_unused":"🔍  Szukaj nieużywanego oprogramowania","btn_network":"📡  Sprawdź otwarte porty","btn_services":"⚠   Ryzykowne usługi","btn_installed":"📦  Lista zainstalowanych","btn_fullscan":"🔒  URUCHOM PEŁNY SKAN","btn_quick":"⚡  Szybkie kontrole","btn_lynis":"🛡  Uruchom audyt Lynis","btn_wizard":"🔧  Kreator naprawy","btn_cve":"🎯  Sprawdź podatności","btn_upgrades":"📋  Sprawdź aktualizacje","btn_tools":"🧰  Zalecane narzędzia","btn_undo":"↩  Dziennik cofania","tab_findings":"⚠  WYNIKI","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  NARZĘDZIA","tab_undo":"↩  COFNIJ"},
    "RU": {"title":"ПАНЕЛЬ АУДИТА LINUX v4.2","findings_hdr":"РЕЗУЛЬТАТЫ — двойной клик для объяснения","terminal_hdr":"ВЫВОД ТЕРМИНАЛА","risk_label":"СОСТОЯНИЕ СИСТЕМЫ","mode_simple":"Простой Режим","mode_expert":"Режим Эксперта","update_ok":"Система обновлена 👍","update_week":"Становится немного пыльно...","update_two_weeks":"Ваша система чувствует себя заброшенной 😬","update_month":"Ну давай же. 😅","update_ancient":"Заброшено как абонемент в спортзал 💀","built_by":"Создано playdoggy 2026 🎮","sec_scan":"СКАНИРОВАТЬ СИСТЕМУ","sec_scan_sub":"Проверяет базу ОС — предустановленные компоненты","sec_checks":"ПРОВЕРКИ БЕЗОПАСНОСТИ","sec_checks_sub":"Проверяет конфигурацию ОС — настройки, разрешения","sec_cve":"ПРОВЕРКА CVE","sec_cve_sub":"Проверяет ПО на известные уязвимости","sec_tools":"РЕКОМЕНДУЕМЫЕ ИНСТРУМЕНТЫ","sec_tools_sub":"Дополнительные инструменты безопасности","sec_undo":"ОТМЕНА / ROLLBACK","sec_undo_sub":"Просмотр и отмена действий этого приложения","btn_unused":"🔍  Поиск неиспользуемого ПО","btn_network":"📡  Открытые порты","btn_services":"⚠   Рискованные службы","btn_installed":"📦  Список установленных","btn_fullscan":"🔒  ПОЛНОЕ СКАНИРОВАНИЕ","btn_quick":"⚡  Быстрые проверки","btn_lynis":"🛡  Запустить аудит Lynis","btn_wizard":"🔧  Мастер исправления","btn_cve":"🎯  Проверить уязвимости","btn_upgrades":"📋  Проверить обновления","btn_tools":"🧰  Рекомендуемые инструменты","btn_undo":"↩  Журнал отмены","tab_findings":"⚠  РЕЗУЛЬТАТЫ","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  ИНСТРУМЕНТЫ","tab_undo":"↩  ОТМЕНА"},
    "SV": {"title":"LINUX AUDIT DASHBOARD v4.2","findings_hdr":"FYND — dubbelklicka för förklaring","terminal_hdr":"TERMINALUTDATA","risk_label":"SYSTEMHÄLSA","mode_simple":"Enkelt Läge","mode_expert":"Expertläge","update_ok":"Systemet är uppdaterat 👍","update_week":"Börjar bli lite dammigt...","update_two_weeks":"Ditt system känner sig försummat 😬","update_month":"Kom igen nu. 😅","update_ancient":"Övergett som ett gymkort 💀","built_by":"Byggt av playdoggy 2026 🎮","sec_scan":"SKANNA SYSTEM","sec_scan_sub":"Kontrollerar OS-basen — förinstallerade komponenter","sec_checks":"SÄKERHETSKONTROLLER","sec_checks_sub":"Kontrollerar OS-konfiguration — inställningar, behörigheter","sec_cve":"CVE SÅRBARHETSKONTROLL","sec_cve_sub":"Kontrollerar programvara mot kända sårbarheter","sec_tools":"REKOMMENDERADE VERKTYG","sec_tools_sub":"Extra säkerhets- och övervakningsverktyg","sec_undo":"ÅNGRA / ROLLBACK","sec_undo_sub":"Granska och återställ åtgärder av denna app","btn_unused":"🔍  Sök oanvänd programvara","btn_network":"📡  Kontrollera öppna portar","btn_services":"⚠   Riskfyllda tjänster","btn_installed":"📦  Lista alla installerade","btn_fullscan":"🔒  KÖR FULLSTÄNDIG SKANNING","btn_quick":"⚡  Snabba kontroller","btn_lynis":"🛡  Kör Lynis-audit","btn_wizard":"🔧  Steg-för-steg guide","btn_cve":"🎯  Kontrollera sårbarheter","btn_upgrades":"📋  Kontrollera uppdateringar","btn_tools":"🧰  Rekommenderade verktyg","btn_undo":"↩  Ångralogg","tab_findings":"⚠  FYND","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  VERKTYG","tab_undo":"↩  ÅNGRA"},
    "TR": {"title":"LINUX DENETİM PANELİ v4.2","findings_hdr":"BULGULAR — açıklama için çift tıklayın","terminal_hdr":"TERMINAL ÇIKTI","risk_label":"SİSTEM SAĞLIĞI","mode_simple":"Basit Mod","mode_expert":"Uzman Mod","update_ok":"Sistem güncel 👍","update_week":"Biraz tozlanmaya başladı...","update_two_weeks":"Sisteminiz kendini ihmal edilmiş hissediyor 😬","update_month":"Hadi ama. Gerçekten. 😅","update_ancient":"Spor salonu üyeliği gibi terk edildi 💀","built_by":"playdoggy 2026 tarafından yapıldı 🎮","sec_scan":"SİSTEMİ TARA","sec_scan_sub":"OS tabanını kontrol eder — önceden yüklenmiş bileşenler","sec_checks":"GÜVENLİK KONTROLLERİ","sec_checks_sub":"OS yapılandırmasını kontrol eder — ayarlar, izinler","sec_cve":"CVE GÜVENLİK AÇIĞI","sec_cve_sub":"Yüklü yazılımı bilinen güvenlik açıklarına karşı kontrol eder","sec_tools":"ÖNERİLEN ARAÇLAR","sec_tools_sub":"Ek güvenlik ve izleme araçları","sec_undo":"GERİ AL / ROLLBACK","sec_undo_sub":"Bu uygulamanın eylemlerini inceleyin ve geri alın","btn_unused":"🔍  Kullanılmayan yazılım ara","btn_network":"📡  Açık portları kontrol et","btn_services":"⚠   Riskli servisleri kontrol et","btn_installed":"📦  Tüm yüklüleri listele","btn_fullscan":"🔒  TAM TARAMA ÇALIŞTIR","btn_quick":"⚡  Hızlı güvenlik kontrolleri","btn_lynis":"🛡  Lynis denetimi çalıştır","btn_wizard":"🔧  Adım adım düzeltme","btn_cve":"🎯  Güvenlik açıklarını kontrol et","btn_upgrades":"📋  Güncellemeleri kontrol et","btn_tools":"🧰  Önerilen araçlar","btn_undo":"↩  Geri alma günlüğü","tab_findings":"⚠  BULGULAR","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  ARAÇLAR","tab_undo":"↩  GERİ AL"},
    "ZH": {"title":"Linux 安全审计面板 v4.2","findings_hdr":"发现 — 双击任意行查看解释","terminal_hdr":"终端输出","risk_label":"系统健康状态","mode_simple":"简单模式","mode_expert":"专家模式","update_ok":"系统已是最新 👍","update_week":"开始有点落后了...","update_two_weeks":"您的系统感觉被忽视了 😬","update_month":"快来更新吧。 😅","update_ancient":"就像健身房会员卡一样被遗忘了 💀","built_by":"由 playdoggy 2026 构建 🎮","sec_scan":"扫描系统","sec_scan_sub":"检查操作系统基础 — 预装和捆绑的组件","sec_checks":"安全检查","sec_checks_sub":"检查操作系统配置 — 设置、权限、策略","sec_cve":"CVE 漏洞检查","sec_cve_sub":"对照已知安全漏洞检查已安装的软件","sec_tools":"推荐工具","sec_tools_sub":"值得拥有的额外安全和监控工具","sec_undo":"撤销 / 回滚","sec_undo_sub":"查看和撤销此应用程序的操作","btn_unused":"🔍  扫描未使用的软件","btn_network":"📡  检查开放端口","btn_services":"⚠   检查危险服务","btn_installed":"📦  列出所有已安装","btn_fullscan":"🔒  运行完整扫描","btn_quick":"⚡  快速安全检查","btn_lynis":"🛡  运行 Lynis 审计","btn_wizard":"🔧  分步修复向导","btn_cve":"🎯  检查已知漏洞","btn_upgrades":"📋  检查更新","btn_tools":"🧰  查看推荐工具","btn_undo":"↩  查看撤销日志","tab_findings":"⚠  发现","tab_cve":"🛡  CVE","tab_lynis":"🔒  LYNIS","tab_tools":"🧰  工具","tab_undo":"↩  撤销"},
}
LANG = "EN"
def L(k):
    """Look up a UI string in the current language.
    Falls back to English if the key is missing from the active language dict.
    This lets us add new keys to EN without updating every translation at once."""
    return LANGS.get(LANG, LANGS["EN"]).get(k, LANGS["EN"].get(k, k))

# ── Distro and package manager detection ──────────────────────────────────────
def detect_distro():
    """Detect which Linux distro we're running on and return the package manager.
    Supports apt (Ubuntu/Debian), dnf (Fedora/RHEL), pacman (Arch)."""
    try:
        data = {
            l.split("=", 1)[0]: l.split("=", 1)[1].strip().strip('"')
            for l in open("/etc/os-release") if "=" in l
        }
        name = data.get("ID", "ubuntu").lower()
        like = data.get("ID_LIKE", "").lower()
        if name in ("ubuntu","mint","pop","zorin","elementary") or "ubuntu" in like: return "apt"
        if "debian" in name or "debian" in like: return "apt"
        if name in ("fedora","rhel","centos","rocky","alma"): return "dnf"
        if name in ("arch","manjaro","endeavouros"): return "pacman"
    except Exception as e:
        logging.error(f"Distro detection failed: {e}")
    return "apt"  # Safe default

PKG_MGR = detect_distro()

def pkg_install(pkg):
    """Return the correct install command list for the detected package manager."""
    return {
        "apt":    ["apt", "install", "-y", pkg],
        "dnf":    ["dnf", "install", "-y", pkg],
        "pacman": ["pacman", "-S", "--noconfirm", pkg],
    }.get(PKG_MGR, ["apt", "install", "-y", pkg])

def pkg_remove(pkg):
    """Return the correct removal command list for the detected package manager.
    Uses purge for apt to also remove config files."""
    return {
        "apt":    ["apt", "purge", "-y", pkg],
        "dnf":    ["dnf", "remove", "-y", pkg],
        "pacman": ["pacman", "-R", "--noconfirm", pkg],
    }.get(PKG_MGR, ["apt", "purge", "-y", pkg])

def pkg_installed(pkg):
    """Check if a package is installed. Returns True/False.
    Runs quickly — safe to call from the main thread for checking."""
    try:
        if PKG_MGR == "apt":
            return "ii" in subprocess.run(
                ["dpkg", "-l", pkg], capture_output=True, text=True, timeout=5
            ).stdout
        if PKG_MGR == "dnf":
            return subprocess.run(
                ["rpm", "-q", pkg], capture_output=True, timeout=5
            ).returncode == 0
        if PKG_MGR == "pacman":
            return subprocess.run(
                ["pacman", "-Q", pkg], capture_output=True, timeout=5
            ).returncode == 0
    except Exception as e:
        logging.error(f"pkg_installed({pkg}): {e}")
    return False

def check_update_age():
    """Check how many days since the system's package list was last updated.
    Returns (days, message) or (None, '') if we can't tell."""
    try:
        stamp_path = None
        for candidate in (
            Path("/var/lib/apt/periodic/update-success-stamp"),
            Path("/var/cache/apt/pkgcache.bin"),
            Path("/var/lib/apt/lists/partial"),
        ):
            if candidate.exists():
                stamp_path = candidate
                break
        if stamp_path is None:
            return None, ""
        stamp = stamp_path.stat().st_mtime
        days  = (datetime.datetime.now().timestamp() - stamp) / 86400
        if days < 3:  return days, L("update_ok")
        if days < 7:  return days, L("update_week")
        if days < 14: return days, L("update_two_weeks")
        if days < 30: return days, L("update_month")
        return days, L("update_ancient")
    except Exception:
        return None, ""

def check_sudo_cached():
    """Check if sudo credentials are already cached (so commands won't hang).
    Returns True if sudo will work without a password prompt right now."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False

# ── Rollback risk database ────────────────────────────────────────────────────
# For each action type, explains what rollback does, the risk that returns,
# and in plain English how an attacker could exploit that risk.
ROLLBACK_RISK = {
    "ftp": {
        "does":    "Reinstalls the FTP package on your machine",
        "risk":    "FTP transmits your username and password in plain text over the network",
        "exploit": "Anyone on the same network can capture your login credentials in seconds using free tools like Wireshark. No hacking skill required.",
        "level":   "HIGH"
    },
    "telnet": {
        "does":    "Reinstalls Telnet — an unencrypted remote shell",
        "risk":    "Every command you type and every password you enter is visible on the network",
        "exploit": "An attacker on your network sees every command you type in real time. SSH replaced Telnet in the 1990s for exactly this reason. There is no good reason to run Telnet in 2026.",
        "level":   "HIGH"
    },
    "xrdp": {
        "does":    "Re-enables the Remote Desktop server on port 3389",
        "risk":    "Port 3389 is one of the most actively attacked ports on the internet",
        "exploit": "Ransomware groups specifically scan for exposed RDP. Multiple critical vulnerabilities have allowed attackers to take full control of machines with no credentials. Only use this behind a VPN.",
        "level":   "HIGH"
    },
    "cups": {
        "does":    "Re-enables and starts the CUPS print server on port 631",
        "risk":    "CUPS has had multiple critical remote code execution vulnerabilities including CVE-2024-47176 in 2024",
        "exploit": "An unauthenticated attacker on your network can execute arbitrary code just by sending a crafted packet to port 631. If you do not print from this machine this risk is completely unnecessary.",
        "level":   "HIGH"
    },
    "avahi-daemon": {
        "does":    "Allows avahi-daemon to restart — it broadcasts your machine name and services to the local network",
        "risk":    "Your machine announces itself and what it is running to every device on your network",
        "exploit": "Attackers use mDNS responses to map networks without active scanning. Your machine effectively introduces itself. Low risk at home, unnecessary noise on any shared network.",
        "level":   "MEDIUM"
    },
    "fail2ban": {
        "does":    "Removes fail2ban — nothing will monitor or block repeated failed login attempts",
        "risk":    "SSH brute force attacks against your machine become completely unchecked",
        "exploit": "Automated bots scan the internet for SSH ports and try thousands of passwords per minute. Without fail2ban there is nothing stopping them. A weak password is only a matter of time.",
        "level":   "HIGH"
    },
    "rsh-server": {
        "does":    "Reinstalls the legacy RSH remote shell server",
        "risk":    "RSH has no encryption and no modern authentication at all",
        "exploit": "RSH was deprecated in the 1990s because it is trivially exploitable. Any attacker on your network can hijack sessions. There is zero reason to run this on a modern system.",
        "level":   "HIGH"
    },
    "ufw": {
        "does":    "Disables your UFW firewall entirely",
        "risk":    "Every port on your machine is now reachable from your network with no filtering",
        "exploit": "Any service running on your machine — including ones you forgot about — becomes directly accessible. Attackers scan home networks constantly. A vulnerable service can be found and exploited within minutes.",
        "level":   "HIGH"
    },
}

def get_rollback_info(cmd, name):
    """Look up the rollback risk explanation for a given action.
    Falls back to a generic explanation if we don't have a specific one."""
    # Check our database for a known match by package/service name
    for key, info in ROLLBACK_RISK.items():
        if key in name.lower() or key in cmd.lower():
            return info
    # Generic fallback for unknown actions
    action = "remove" if ("purge" in cmd or "remove" in cmd) else "disable"
    return {
        "does":    f"Reverses the {action} action on {name}",
        "risk":    "Review whether this service or package should be active on your system",
        "exploit": "Depends on what is being restored — check the original finding for details.",
        "level":   "LOW"
    }

# ── Recommended tools database ────────────────────────────────────────────────
# Each tool has a plain English description, reason why you want it,
# how to set it up, how to verify it works, and the command to run it.
TOOLS_DATA = [
    {
        "name": "htop", "cat": "Monitoring",
        "desc": "Visual, interactive process monitor — like Task Manager for Linux",
        "why": "Shows CPU, memory, and all running processes in real time with colour coding. Much easier than the basic 'top' command.",
        "setup": "Just install it and type 'htop' in any terminal.",
        "verify": "Run 'htop' — you should see a colourful list of processes.",
        "run": "htop", "safe_run": False,  # False = no sudo needed
    },
    {
        "name": "btop", "cat": "Monitoring",
        "desc": "Next-generation system monitor — CPU, memory, disk and network all in one screen",
        "why": "One screen gives you the complete picture of your system health. Supports mouse, has themes, and is very readable at a glance.",
        "setup": "Just install it and type 'btop' in any terminal.",
        "verify": "Run 'btop' — shows all resources at once with graphs.",
        "run": "btop", "safe_run": False,
    },
    {
        "name": "smartmontools", "cat": "Health",
        "desc": "Reads your hard drive's built-in health sensors (SMART data)",
        "why": "Hard drives warn about failure before it happens. This reads those warnings so you can replace a drive before it dies and takes your data with it.",
        "setup": "After install run: sudo smartctl -a /dev/sda (replace sda with your drive — check with 'lsblk')",
        "verify": "Run: sudo smartctl -H /dev/sda — look for 'PASSED'",
        "run": "smartctl -H /dev/sda", "safe_run": True,
    },
    {
        "name": "lm-sensors", "cat": "Health",
        "desc": "Reads CPU and motherboard temperature sensors",
        "why": "Overheating causes crashes and shortens hardware life. Know when your machine is running hot before it becomes a problem.",
        "setup": "After install run: sudo sensors-detect (say yes to the defaults), then just type 'sensors'",
        "verify": "Run 'sensors' — shows temperatures in Celsius for each sensor.",
        "run": "sensors", "safe_run": False,
    },
    {
        "name": "rkhunter", "cat": "Security",
        "desc": "Rootkit Hunter — scans for known malware and system backdoors",
        "why": "Checks if anything malicious is hiding on your system. Uses a database of known rootkit signatures.",
        "setup": "After install run: sudo rkhunter --update — then: sudo rkhunter --check",
        "verify": "Run: sudo rkhunter --check — look for any red 'Warning' lines.",
        "run": "rkhunter --check", "safe_run": True,
    },
    {
        "name": "chkrootkit", "cat": "Security",
        "desc": "Another rootkit scanner — run alongside rkhunter for better coverage",
        "why": "Two scanners catch more than one. They use different databases so together they give broader coverage of known threats.",
        "setup": "Just install and run: sudo chkrootkit",
        "verify": "Run: sudo chkrootkit — look for INFECTED (false positives are common — Google any results first).",
        "run": "chkrootkit", "safe_run": True,
    },
    {
        "name": "clamav", "cat": "Security",
        "desc": "Free open source antivirus scanner for Linux",
        "why": "Scans files for known viruses and malware. Useful for scanning downloaded files or checking a mounted Windows drive.",
        "setup": "After install run: sudo freshclam (downloads latest virus definitions) then: clamscan -r /home",
        "verify": "Run: clamscan --version — should show the ClamAV version number.",
        "run": "clamscan -r /home", "safe_run": False,
    },
    {
        "name": "fail2ban", "cat": "Security",
        "desc": "Automatically bans IP addresses that repeatedly fail login attempts",
        "why": "Stops brute-force attacks on SSH and other services. Without it bots can try thousands of passwords per minute with zero consequence.",
        "setup": "Install it and it works automatically with sensible defaults.",
        "verify": "Run: sudo fail2ban-client status sshd — shows how many IPs are currently banned.",
        "run": "fail2ban-client status", "safe_run": True,
    },
    {
        "name": "nmap", "cat": "Network",
        "desc": "Network scanner — see what devices and open ports are on your network",
        "why": "Know what is exposed on your machine and your local network. Used by security professionals worldwide to map attack surfaces.",
        "setup": "Install then run: nmap localhost (scans your own machine first to understand it)",
        "verify": "Run: nmap localhost — shows all open ports on your own machine.",
        "run": "nmap localhost", "safe_run": False,
    },
    {
        "name": "nethogs", "cat": "Network",
        "desc": "Shows which programs are using your network bandwidth right now",
        "why": "Find out instantly if something is secretly uploading data in the background. Shows bandwidth per process in real time.",
        "setup": "Just install and run: sudo nethogs",
        "verify": "Run: sudo nethogs — shows each process and how much bandwidth it is using.",
        "run": "nethogs", "safe_run": True,
    },
    {
        "name": "ncdu", "cat": "Storage",
        "desc": "Visual disk usage analyser — find what is eating your storage space",
        "why": "Instantly find and navigate to large files and folders. Much faster than digging through folders manually.",
        "setup": "Just install and run: ncdu /",
        "verify": "Run: ncdu / — shows a visual tree of disk usage sorted by size.",
        "run": "ncdu /", "safe_run": False,
    },
    {
        "name": "timeshift", "cat": "Backup",
        "desc": "System snapshot tool — like System Restore for Linux",
        "why": "If something breaks after an update or system change you can restore to a working state. Essential safety net before making any major changes.",
        "setup": "Install then open Timeshift from the applications menu and set up an automatic schedule.",
        "verify": "Run: sudo timeshift --list — shows available snapshots.",
        "run": "timeshift --list", "safe_run": True,
    },
    {
        "name": "borgbackup", "cat": "Backup",
        "desc": "Encrypted, compressed, deduplicated backup tool",
        "why": "Secure backups that only you can read. Deduplication means it is storage-efficient. Better than just copying files.",
        "setup": "After install: borg init --encryption=repokey /path/to/your/backup/drive",
        "verify": "Run: borg --version — shows version number.",
        "run": "borg list", "safe_run": False,
    },
    {
        "name": "logwatch", "cat": "Monitoring",
        "desc": "Analyses your system logs and produces a plain English daily summary",
        "why": "Get a daily report of what happened on your system — catch unusual activity, failed logins, and errors before they become problems.",
        "setup": "After install: sudo logwatch --output stdout --detail low",
        "verify": "Run: sudo logwatch --output stdout --range today --detail low",
        "run": "logwatch --output stdout --detail low", "safe_run": True,
    },
    {
        "name": "auditd", "cat": "Security",
        "desc": "Kernel-level audit daemon — records security-relevant system events in detail",
        "why": "Logs who did what on your system at the lowest level. Essential for detecting intrusions and investigating what happened after a security incident.",
        "setup": "After install: sudo systemctl enable --now auditd",
        "verify": "Run: sudo ausearch -m login --start today — shows today's login events.",
        "run": "auditctl -l", "safe_run": True,
    },
]

# ── Face images (base64-encoded PNGs embedded directly in the file) ─────────
# Six states: clean / low / moderate / high / critical / destroyed
FACE_IMAGES = {
    "clean": "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",
    "low": "iVBORw0KGgoAAAANSUhEUgAAAHgAAAB4CAIAAAC2BqGFAAABCGlDQ1BJQ0MgUHJvZmlsZQAAeJxjYGA8wQAELAYMDLl5JUVB7k4KEZFRCuwPGBiBEAwSk4sLGHADoKpv1yBqL+viUYcLcKakFicD6Q9ArFIEtBxopAiQLZIOYWuA2EkQtg2IXV5SUAJkB4DYRSFBzkB2CpCtkY7ETkJiJxcUgdT3ANk2uTmlyQh3M/Ck5oUGA2kOIJZhKGYIYnBncAL5H6IkfxEDg8VXBgbmCQixpJkMDNtbGRgkbiHEVBYwMPC3MDBsO48QQ4RJQWJRIliIBYiZ0tIYGD4tZ2DgjWRgEL7AwMAVDQsIHG5TALvNnSEfCNMZchhSgSKeDHkMyQx6QJYRgwGDIYMZAKbWPz9HbOBQAABIlElEQVR4nNW9d6AlRbE/XlXdM3PizXs35wgL7LILSFQQRKKKEcQceAr4jA9zfvqe4fnMiKBiQBDJKAqSMyg5LbA5p5tOnpnuqu8fPXPuuWl3kfe+39+vucA5Z1JPdXWFT1VXo4jAPjQRQcSXeuifbs1etd7Z/fg//qx97Mw+PnciauC+Ezq54OU973+7/b8ajL228Qn9UsnavOr/DtfvmZp7Pfr/ZBjo//4jX2bb6xTcAx33cfr+b7Q9iY49D/64R/9/IUb/p574kqbUXmT0PzfRXs70/P+skIWWvrV2ch87PCw6JG2th/+5F345kxcR913fvqSjzbdrPTT2lfdw+ah+7ksnm9cOc/QoNhzLlWOf3TqkL/XZe+gTTGzVuV5NxETNPrd2fl+m11gOHdvGdmncQxO1l2beTTQSo46+fM0uIu6mIiwAKCCAAC3kSM5z/woCAiIiIBICAgBgy632jRb72O19f7vWgdcv56b/g6ZSIrZYBAERiQRRIcBLt4tYQNiCCGPaYGIen4hF/md4peU+Izjavazr3J6n8J7v3rx8z+c3tQIiEo0gaL3eGOjv272rv29H/0D/YH/f4NBQqVIq16q1er0eW6s9nc1k8vlcW3tbZ2d7R0/HpEndk6dM6uru7OruAhxxN2usABANS/+9apGxFBgrWvedGjBWdLzMkZyol6POsZYBQGvV/LFUKr344ppnnnzuhWdfeP65Fzes3zKwa7BartbrIYNlsAICgADJHSX5LwsIAiCgr/xcNtfeWZg8tWfegjmLli5esnTxfvstmjtntvZ99xQGNsYqJCIEBHyJ0+XlWETYVLv/FywqZmYRrRL6lkuVp5586qGHHv7HfY899eSz27ZsrzdCBtSgPQx8X2lN5CnSqIiIFCjHGy0qyzIIMDMbFpY4tsaYRhRGECKIBupoL8yYO+OAFQcdcfhhhx6+cuGSBb7nA4BltsyaqDmTWhnun/M5J2qJkGgl9P8exa1lRHBv1dfff+9d9/7lxlsevP+RdavXV23Vg6CAuSDrB5lAZz0d+IpQa0RNqBQSYsu0b52AKE5rsmVhBhERYzjmODK2EcehiSNTDWtVqSmAjkJx4eIFxxx31CmnH3/4kYdrHQCAMYZayD0RpV4mfUaYd6MPjLHtRqj7Ya2+p/sDiLWChIQEAI898vjVf7ju6iuv3bxhuwUJwMtkMn4u8ALfy6gg63m+Jk1ICMAgJIICAkAgrgPNbjSZWlxXCNiZ4EKIgCho2ZrY2JijRmwiY+pR1AgbtSgCk/H1QSuXvuWsN572+pNnzJoJANbasXpi1Js0G+6zgG49YbQyhHToJjSim/pkb7dmZgAhUiLy1xtvvviiX919+0OVRq1AmXwu62V9L+8FOd/zPeV5iQxjEeDEjAPtHtJyz5SygGnPOTlh2BsgdzECJxYHATJxLCYKw1oUNUyjFlYr1ZijqVMnn/6mk9/7wXcuPWgpABgbEWpH7tGq72UQelh07IFeYy2hsYQe1ySy1iqlAOCvf/rbD7770/vvehCACrliJu97OZ0tBH4mg0QCVphT4qEIADKAICIIIarhe4oISPqxaTywwAizWYTSPnLTpIFE8yEBiuUwNGGp0aiE1Uq9HJW6im2ve9MpH/238xbvv7i156PJsjdCj2toNT2svRB6z88b90IRYWal1OrVa77y2X+/6erbSDBfzOmsV+jMZQtZUCgAwoACCMLJ7dj1FJ1rAgCgEAha2XnMrHIkFwDB9CVlJBuKEJA4NgBAAUBAUohooqheqdVLYWOwUQ1LHR1tH/zX933sgvPz+UJsYk/rUa+4L4QeKwxGEPqliN29yGhmRkIEvOSiS7/xxe/07xpsL7bn8n6xK6/zARCxZZDhi5tkQWDHg8P3Qp2I3eG+jrlKAAEFRJCbv6RtL/oNCZCEDYTlsNpXqZZrpai8csVB3/nhv7/iqMNDYzShonFYu3mH5IkTOzit5/xPEpqZiaher3/83At+e+lVRb8tX/QLk3LZtjwSsnEkHnkdOnUHIAwj5xaSgpGSDSV5K4Ym/6a9aiF04qrv3UYWESsAqJQYKfdXaoONgcFypoDf+t7X3vfBdxkTOsuk9QKYGIfYw2P+JwnNIoRYGSqf9db33HLLvT357kyb7pnWpTw0RhAo1WwjEZkRhE6fkPhSNEIFtWq84T6kVAVx6rGlVxO/TfMIuwuFUTSpsBENbR+KSnGtUfn0Vz96wZf+LTbG08Moxcsl9L5fs4fnsbCNzVlnvOvPf7m9u9Cb7wy6prYjIDMjJCQb1xcdeWcA4GQwiCYiVtP8x1bNLCNVd4t4GfV2zUMkzTFjEEBNwmZoa6kxaHZUd/3Hd778sU+d63TjqD7vI3A44hJm3sP1+9JExFjjae9T53/m+z+5cEphar4z0zG1g9miUGotDYM7E3Wx+QMAp+J374hE8l92ll/L2I8k9Ihrm2bKsHJlcURH0aR2be2vD8TVRunyay8+6bSTRtF6XFOt2Zk9Efpl4lWxiT3tXXfVDWe95b3FTEe+MzNpRjdbS+A58BLS9xq3iQM53WeRYWNyfEKn9GiBTEeyczpBh0VNeg6MI+ITO8fd2Yl1FADauWl7pa/a1lu8/f4/z5o5U1KsraWfI/hmr4do7DQc68K4D5Lifq2NmRXRUP/AFz/zFZ+8TE73TO1mIwgqfUHcE5URAFHQEWrYGQEgBEQZwY8ogsJObbpDyQnc2mdp2nsImADbqeXdfIuWpzvj3Dk2KOgsGNPd25nLZjdv2fLVz34TEUXsWGNuFNFGkWgUDWnUT6OoORGBmmNl2RKpX/78t8+vWZ3P5Tt6OwkImh7GyKEa+6Dmk5qzeI8SvOVmI/oxwbUyfKz1EaPfouUBACAgbIU8yk/KdWU6r/njDffee59SXlPGjsuIe20jYobjniEj3i+ZsMnsYNFKDQ4OXXrxZXlqz7XlcgXfab+0/0nXHWOJsAM2AVsiIYSIiESAKOCQz5EGddPxTsji+HCi3qLjYRARYCd+kNK/5F4oAu6fkXduGoZk2eY7Ctn2XBTHP/zehftIzYma7DXCAi0yvvUy94GZlVY333TrhrWbc23tbT3tiIJEko6FCDMLIJBCSt4MHbBp2QqLCLvZCwjawQwaAYStBVGINCzyWJpen+A4vRruHbPD/MQKx4YNuD4ggQPqSBlEQkIUEieJ2IoA4rAOJfSJMNOW7a723nPbg889//x+ixdba/cAPE3cJQCAvRB6Ig3bPAwAV/3+WgQvX/SzuZw1MRI6wepAJU2KrQ3rjahhTBizMZbBGmQDlhmSGU2I4PvkeaQDL9OWzRZ9EWAr0Gp3YwsDOsU3avgFUIFSulFpVMo104g4srEBdjYFglJKK/K0UlprXysfySMv8JTnIVpmi6hbTEZua89Fg7Z/1+B1f7hxvy8tbn3cHvhvfFLtWRaPqyGTX5hJqfXr1h+38rSoApPmFfNdBWsYAAVF2CKijaNKf7lWiRr1KA45ZGMgIgAfKNA64ynf06SUCFjDYSNuGEbI5HK5XBsWeoteNmCT8hpAS4A26VsiyhLnXZRScSSlbX2mEpfCKLKNQOtcoJRCRALG2HAcc2TiGECANJCv0c8oPxvkirlsR0GRCACiEIIIKU1D28pb1u846LBFt933ZyJFhHt2BSYaBj2RSThKlY1pwpZJqXvveqB/YKCnvTeTz7JN7CQBVh7FlWjn5lK9GpWj/pyHs6a2z5sxY+70rumTu6Z0t3V35jsK+VxGK0XCEIZxX6m6bnP/HQ+/cOdDawa2Z6OaBN2Ztq4MKmRmEEZQkkrStIdJPJeIEFR1qFzePlSuQ2zqKw+ceeIRiw6cM2lyVyHwPeWRsViph6VaY1dfeev2/o1bd7+wrW/9loHtu8u2Um8rSb5c7ZkxiTwUFhYNAJatn9F5P/PcUy8+v+r5pQccwGwR9x4AG0s3PS75pSV9YoKGzuK99/b7BdgrKOUrY60zXxWhRNi/ZchUpSPLH3rLq0484oAF0wpd+YynNIqAMLfG+0ARkdJT4TD84OsP/8tDz3/zkluef3F3FOVNtZZt87OFLHoKHNacyHoAACBQSomReqVWGaiGlahaDbs69Gffc/LZJx2a80WsicXhdkiAiIIoBCBIwtKIzLZy/YVNu268/dkb71kTlvzdG/t75/YSIbOICBsmn3RO7Rys/P3vjy094AC2ojSMItq4hnPzkPugJ2Lbvc4OpSkK6089+owHWmVQmn4AIhEO9pUaVelpb1z49fcctXx+VBqMwkat1hARBBIkBiQUAiefraB7exE0px469xX7feC7v7/9Nzf8Y/tO7KjYWib2876X1dr3SCERORM+jiLTMGElrNfiWiOMuXb8IfM//77XHrKgt1Id6K8Jkk/IiAoAGQUEhBP7B0AUyrS8N3/Z3JOPPviE25745H/cEFV0eaDU1lNo+gmowct4COrxR56C90KK2IwTMBn7tfW00cpwFC+P6ys6qa4Ubdq4deOGLdrX2ke2zIBEAEjW2rBqqmH102e95qjl8/q3bwOlEbVoDcDAgAAKnS51bh2CSIK8gTdQqmW0+ua5rzv9uOUXX3nn3x5avbk/1v1eRvvaU8ojj4AtG2MacRwajoBzSAct6vngG059w6uXBVwvVRukA+2wblSu0yTIiKgAhRlIEBgkAoyi2OzY9cYTDnz4sfU/uebhYMjmOgK2lBghCtHXAeg1q9YBAKm9GQgjydj8MJrQw+jBxA0RmS0ArV29vlQZzBfyqJWjMwiiAhOaej2e1OYd94ol1aESel7qriXQHLIktklzliEAuCiWgKJIJB4aOmpB91FfetfTm/pvf/SZ+x5ds2rN7sFSvRHGIQOCeIra2zIzp+QOXjj1+EP3P2rl7E7fr1RKISJ6WoSB0FlvTodqxsQnQUREQWAUcSCh5rg0+KrD5v7s2nujhrKRVZ5KOkYY5DyfvA0bN1QqpUKhuBfrYiT236Tn3u3osaPVtLPWvLAugrjNJ1LU/BURgCEKzdwZhekdObECSA4ncn4Cud6MumkC9CCmhgShGahb4mjJpMwBZxzx4dOO2DVY3lWq9JfrYWw9RdnA68hnejtzHXkfra3XokoUE/kMAGKd9E/EEQAOD/LwOzj3H0UArTHQ253LZXUcczLwAqgQQLSnPV/37R7YuWt3odAmwk52jU+df86OHkUIAABmTEHkrZu2WADteYgCgkiICWrBwKy1IoUgVjnLAEAAhYZtMgdOY4I1J+gOYmKtCTitheUolEZdIbZndXexWyly48TWGmvj2JTKDRQgVEjATgihQod8IgoQiBAmYK2kQCImoTERAGEAAk95iGAAkcRBqM6UI0WBrwfK5R3bd82bO28P1HRt2GZrEk1Ajytx9iCGWtG4zZu2AKDW2o2wNF8EEJFDI6FlHy23eLoooIiaTnmzJ0gjFbcTNSKIQICgFAAYK7GNxNnVzv4AdLqXQSwIAKjROLnrMgokkV1MvrqBbcIshEpV6pE1GHgKFSURMkBgIAKtqWEa23dsB+cPjxe9HfXUEURrBZVGq9EJpTQ26TI0VFKgtfZcipWbl8KAiJ5HfYOVwcGSImr17BBAmGUE6iiQBF5b/C6XNEPkZkkq6YAQFZEiUu5/lNxiGMwY8S4jSI4ASoBS4rYqfATyfL+/VDURBL4mpVIQAQGQCEkpBh4aHBp12+YdxiHTyF9pfLsCE901EhFGABBEQXJGe70aEZDyVJrQIgJg2Qqi9tTOocqWrQMKka2FYYoOo3rpcAolqCiQAz0BJA15izCKKBCNQMLJn2VwBtrYro98RxFgkRSjYguWgVmYhRlYwAAyoiCLUrRlR8mKKM9TyQR1vWBAtAoRsDRQTm7aMn7QMnFa6Z5AAinSS60DO06fR8yCEZ6+sA3DhgKdzKMmNMoMClVGNTh6at0uVCQ8kiCj4ilNhCjF8hOkXEAJtoxhy+sRAgByKt/HdLr1UW5GQBoTcBR3MHZyUyREa1Gt2tAvAEFGA6GwNBsiKKUAcHBwEEaO7lg51fqhtf0TVkfiAVtjwjAipFS8Jn1gZiIknwDgiRe3MiSJEKPsnhZSJCkDOBxiSoIrTXRnxGsAsAggkgtATdTHBCFx9g0LAAu6NChkUUiAaJBJwLmytdiuWr9bo6czqklASQLFiRCJwgjGCo59a4lnOAwxD2s0bP2AIzkbESwLG6GWNC13MiGBiPaVBu/59TvLtUgTMqQGxggKu/8TJy5ySkgAAGBgHiW1BZ3X7gRuK+OMEHBOkzdHioSEbMyEcd7zlKeFwBpTDyOwhAoYrafU9v7S+k195At6lOK3LTdGEMA4tknPZU/0Hka7EJoI1OhYevPUiT44ydWM8o0YoZZp5Ht+oLwdu4f6ytH0dj+07Bh/dJ9GgnAwKpEjZavWX1ITMH3ZMSelI59MFRHxgdq6s0NlfGjd9k27diPgrN6e/Wf1dhZUZahswNM5f+O2gb6Bkpf1lVKOyokWlub0SgOVsCcqwwgZ4rqTOix79gNHXbzn3xP9AUKKtNbVhi1Vo5ldWWA7/n1b8x1gJFGHv6UDySDNPJDE+pbRl6QGRiL9AZVSfQ259Nd33nTHk7VY2vO+IJRqUSGDx79iyTmvO7Inyyhme1+lbiOfAiQaTi1J7VCAEUHkZgf26os3yaJb5WZr+knKZTjqgubJhIAKXLwURAgSs9hBZGysNVIsBsUATQuVW4VSK30VkiRRVknfwb0vNv2KVGWmn9LEFBTg1Axvqk5UICgiGOQKF1/2p61Dta999M1LZ3d3FDLMplRpPLVu600PPXfud674xJmvOubAWUozAjCLZdHKYXzNwRNmEGBfUzruAElkYyJt3LQvk6N6InZO1cF4h1xEXinP0wLCwpCG/cXZ80T1Ur1uwyMXzpje2xk1qqj9cZ/SxB4EJAE6MPUjhgd7dMdk+OpmdGuYtRJpJkkaUqNc/dhZx3d2FMGEcWystcimQ+Pxi2eeuHLRo+u2DPU3wtgeunDq9Elt2wfieiVs78lzPOrBgoB+4Lc+al8kQbO9tEUcya0RRERp7fsBA4vlhJOJEJEURfWwVgoJ4jNPXJbTLC1PwQTMGC1weJQFtw89aUrqpu+euBiJEYRsWKwNFHa2ZeMo6i+bdbsbq7cNbdhZ2R3ZhuKwVFrSHRy1/7RyFM2e0nb2KcvYhGF/ZEIRFE6bA1cFJJPJwmjxtq9thHk3NqmnlRatU55FSKlMIbAgYjiBuUhQBJFqA/VKPTpsv5mvPWpxuVpVFMjwzAdAYAAghFS1Oz52fh2OtEal1cJq/T35wu5uksBZyC4B3XKgMNueM6Je2Np/763P3vfY+tXr+/oG6mHYILK5dm/pnElvevWKk49YLBJryDYa9j1vOOra257buL2Ou7BzSgcDU6IWWIwgULGtHYa1b1OKjhYUaaJIklgyDqH30FqnCaJLwYK2tjYGdrlOiATCilRYjhtVq1R07tkntAdQihRSa0a+swgQOFFZThA5UL5pNe2Bu5uio1X7J+iJAFgJAsx3tG3vq1xz33M33vncI8/s6B8qCZL2lKeAENhQaVe8ZcvmW+/bftwRz/37v546u8erl+MpXZlz3vSKj//gzzRgM8Ugk/XcQlLH1wjQ0dm+j+Qa2/4Zh0XEmZmqo7MjUcuY2kCI9XJYq9VfeciC045cVK6V0MsiGBRKeTNBcyAlFraYisAMwxhI8qyxNvJYdY8AHLPnQb6YWbs7vOyqu6+/5Ym1mwcZdS5D+WJAQERiwBiLIBB42stmtPLveHDT2Rt+86vvnLVoUrY0VHr9q/a75Np7Vm2uVEu1XLYdGFCBsFhrPKCurs7WnkxEnmHzpKWTI2S0YIJytBB0hF/fnM5uOcTkSV0AbAwJKwRBwjgy9VLNsHnXqYf6HlhQgCJI7CgqLGyFjYgFYAcGA7DDN0BchCaxEZ2cwvStmoJruBstYsRayee9XTXz5V/f9trzLvzqL2/ZuKNaLGY7CpQljaKiuh0aCitDEUa23VdFT8X1el9/f973tuwon//VPwxVG8i2N595/asPjDhuVBrGirgsH0FjkJRq72yHMUIMAAEopSQnVJTRsnw8jsbU4p8AlIJUTvVOmYSQLPYDAlKqNhhWq9HiWT1HrVxYqVUV0fiGi+sUs6Ns076RZEmKuPdoHeMRrlNTW5Bygd5cxr/tibWf+vaf1+8u5wKals8JWBFkxmqjLqzmzuw8avmcQw6YvXBWd2dnBhH6B6qPPLv5hpuffOSF8MEXtv34Dw9+6f0n1Kp9pxy79OdXPdZosGlYvz3LbJnZWuMHqlgstJJlz1bHKMu4xTOEprM1uo2wtSV1uwB6p/RqUGKsMIMmYY6qcWjNMStm97b7/YMRqQSQxOGHJM+QFmo2V8UOUxlEAGlk1ujoN0FkBAASMX7Ou+aWpzfsbkzt7IhDA4AR23K9FCg69pCFbz95+dGHLJjcWQAQE0URMwnOm1Q8/IBp7zj1sEuvv/d7v7rzkuuePPuUQ2f15Peb5h+2dPrdD2/lhmAnEXBsbBg1OnpynZ0d4xJnoh620k2LWEzDly1u16hXcrdrxRYEALp7Oz3UcWTZGOVl2EgUGkJZvt8sscaVHGAnFtCtNFHCJNaisLMv0C2JIBQQjeSS4pr4Ao+SbM0PmLqFgM4NFfEOOWju725dFUbZhq01wlLgyanHLjnn9COO2H9qxqNGLRroGwAkASIFKNCAmCviKfzoO449aP85F3zv6k07B+fOnOOBOvTAeXc8tNUYw8IgYGIb2qije0ZnV6fze1OCJMQZ2TtHYcaRymaflGGLbdckPQJA75RJmawfhlGjEeUyvolNo1HP+jB/xqQoiglTTDbtCFsOPJ0tZBQKu4iIGBABy5G1xlhr2CCQW29ElCaPELOjp8IR7h+gi+UCVKultx6/7M5H1t7x0IvTOtqPOGT5205aecx+U9DaoVqj3gClCAgRGEFQFAAggFJkBfr7Bl61dMrtF54fc1irRe2FzLxZkzRw2IhsbBSRjWMDprunK5MJmO2+e96tTY+UOONfn56DzZF0vlz3pO62zvzOLYNhI86wDaMojBpdedXT5htjkMnhxoJkrMllPD+XX7tt4LG/r3tx467dA2VrbeBRb2dx1uSuuTN6ZnYVe4qe9im2lo2xLCxMgEqTHwREVK7UktzZRNUgOmhVmC1pFf38i2es21HtKmand7fFUa1SrrMo1BrAzaBUWolJ2U0hApIqVSNSVouOBdny5J6859moEUdhlAl8E8UMZubM6QC41zjWSIq1EBpGipJRbcJDCNbGnZ2dXVN6t2zZYSMrIja2cRwX8plCxpM4RAoEFKC1BrraC89vGfzx5X/924Mv7hyIxKaLt8ECsFKUyfuT24KFM7oOmD/twAXT5k/rmtLTls1lSWEptM88u2HNhm1vPnZ/RYn7AjC8VtllDMSWdN0smtxubDzYN0BEoHwCw+BQWhBiZ/4DkiSGJQCAAmAFVsihNlEMXXnfz6jBRp1tkQFNbBFk1uyZkAzyPrWRpNtb2u5YKieWLKCxNvAzs2ZPf/SRx4wxIM7qs+3FXDbwhWPimElZlq724LoHVl3w7Rv6+6N8odhRyKDEmPClEbYxQmTM1h2NDZu33PzgBo3SUcj3tGUKuYxhM1Cpb9lZ7m3PnHb0fgUfmMGlzqa2ZzrdgC1SvV5HJFLuDOsMQyLAZDWzW6zYjLm4+3AqFwWE49gWsjqb0burIVsLImLRB3/+gjkAsO+gxSjSjc692ytO4k5mZmutNXb+/LkC4vSGiFjgtnzW1xA2BBVKWO/oaPv9bc9+/D+vQurIZb16pcEQuVWzhKQ8FWhfK9TKR7ScsShZEBLD23ZFxjYEBD0UnZk9o7uQ9cTG2JIc3cw3RBEASoC95tp8RGFhFGEHLrok9URmCGK6nEVcjAEBUETY5jJeeyGzcVcNEYGZDWQpN3vODGMsW24tsLLnluIOKaFbKNjUW80bJUhgcx5Yy6RIKZXLegBw2OErEMjG1kaCli1g3veVAzlZ8ll195Przv3aZRGotmBw1vRJy5bMmT65E0kNlKqbtvWv29S/dedQqRxZ0L7yA9/XipBYEJUyBACCpLE0FB24aFoh6w+VI6V0CygPLnorw9YpgYNdBAClmMvorA+KEk8MAUQgjKJGVI8MoQAJCyZRTRECEYZsRhcKWRdZNQZMaDu625YtP0hrBVoBgLUhokfUBMhGyZOmcIM07jZeplLrOIy6vrkg/bHHnnz26Wd97UX1uCvXZePYRtYtmsgXskQoAMSsvNydDz29YMHk1x62+DWHzFu2YEZneyH1OCRkKlUrG3cMPrN612Ortjy9asvazX19Q6EBJlSBRlQUI9fLcYdvzjrh4KhRcyyMSImMRkEmK0IucUNc8BGNtdms8oLsMxuH/v7k2jXrt/YN1gWgmPWnTGpfvGDasoXTZk8KTK1er1rwU7cKUQQYQftBR7GgQCGQjdha6epov/+eh4dKg0rrZSsOWrxoEaTL8/eAyjR9AgBEZrNHuZMu/UXlViDfeds93/73/3704WdKtToAt3nFYiHTqNcKUwrCsH7jtvPeeMS3zn3N0FCJtIcIElvf1/lsYOK4GkfCaJVmAmABREUq42s/8BRRpW7WbRl45vnNjz+3cdX6HZt3D1XqFpRM7sidf9axbzhiUbleVcoTJJWQG4GERfl+huPQWgMAxGCsyRWyq7eWP/OD6+969IWeSb1z5s5t62wHwGq5sm3r1q1btqE0jjt0/kffcfwRCyZVyiH5njMbGSkG6OjoPO9r1/3xlicmz+k2MZuBhu/RzqGBOoQeqK72zhNPe9UXvv7pOXPnsGVS2EQhR3J0K7OP5Gi3olpS/NjJPXc+W6OU/sn3L/nyBd+IYs7rzNJZk4NA7dpZ6hso5zOBbaAm0qA7C1l0S1kAAET5ZKzpHzJICslDFLKsRXm+7weeVh4oiK2tNEQAl8zuOWjR5LPOOASMLQ8M7dhdQtQ93W1ZDxqVutKBCIOIRSa3JsZCJvC/e8kNp514xP5zOuoNa8QW88Gj64ZO/9f/mrbggD9c//tjXn14Pp8fZhyO16/bdPtt9//qot+9+tz//o9zzzj/jFfUShX0A0oVp1aqkNcCaBpGmOLI1sPKnKmT2ttz9Uq8aevAlZf96YG7HvrNNb9YeejB1sZj+FpkeMGkI+z4VoeMEtbGxr7O/PHyaz//8S9l/exhK2eff9Yrly2YpD01MFC5+s5nL73yoVJfXCgEBF5nISfUHFIHUJNCAQS2hsG25fMC3qb+8qoNfS+s2bFm87ahSlivS7VhSrVavVHvac8snt/1miMOOGHFfLGNRlSrxVppBan2c2EdAhTBIAOrtw7+7k8Pfuczby7Xh3xPlcD78JcvfcWxx199/a+1542eoULz5s+bN3/eB855x/e/97NPfvJTM3p733TswlIlJPSAGBkRpKOYBYCoFler9cWzO89/52lHLZvZngkqYXz739f88Nf3rN28+5wzz//TPddMnjpJeGxi1wg0A8f1DBMs04EJyZJNvWnDhq988usE6sRX7fejz701g41aNSaE9sntn//Aa447ZMk5X/lDucQeytRJRQR0vkpaR0MQwLKQWJ0p/PrmJ3917R3PrN9mJd/ZMWnu/Fl922rbtuy0SAcesuSow5fu3L7r/mdf/PmNvz58v1kXfvbtsyd5YcjMLKiS0JcAAhCJFcthfPJxh/7nRTf2D9RJoFBou+iq+7eW7W2/u1B7XhjVAz/7xGNP/eC7PyalPvyRc1YeurwRhSKsFXzsEx9avWrddy++7rRjP6uUcUlFwgIm7mwPAKNK3R5x0JSLv/iWqR3Zap2ZGwWf3nXq/vsvmnr+F698bu2GL13wtYt/9xNrY6RUbTRpOJLqqWhwf5Lge+l3QABjRZG+6Me/en7bxsVzu77x4dOwMRQblS/kgLjUMDu37zhy+fS3n76yWhvK+/7kniKzIClBAgKXpiiIxFaC/Ie/feW//NdlvcuO+K+Lf3r/E397dtN9v/j990FBPpfpLua3bFj/3nedecWVv/jH03c++Mid1aDnzM/8ctDmAk8LUhJLAUFy2c0IhI1GvHK/2bVa+PDTGwoZCi1f89eHzjjz9Pau9ihsBF6wbu2aM1771t/8/orf/PaKN5z8llWrnvM97SkfIWDmc/7l7K27aqvWbc/6HrMVEBRj4nByZ1YA4rj67tMOndrm7dg10AgriJwPvFJ/ecXs9gve/6rA11dfec3Df/+70h4z78HkQxlJ6GbysAOmAUEYfM/r2zVw7R9vUshvPXX5tB4Vm+wDT6z9y33P1iKvs5gnIa6H1kQNqE/t8WdP7Y6iGJGAUAhBIRAZgUKxcNeja35758PX33jlNddc+r73veOAA5fm88Wr/3DN8xtfFG2NxJt37vzZhb+01oZRvHzFQbfc+sfdFXv9bU9kO9oNaiCNLu0PERUBIpGKrJncXZg6qeu2B57VHg0MDK7Zsu2QV6wQERMLIN14/S3bdu2a0jFpasfkHX2D1193M6ECYKWQiKbPnhYU2zZs61e+ZmQQRKKoES+ZNaWrPYhA+vsHLQMhdORyu3ZVb7j3udWbh6JaeNIr5h160IyBuPGH3/wRAJIFkxO3CURH2iyzr/SD99y/dsOaWd1dJ62ct3N37YP/fsW9j64HUHN7C9/6zJuP3m+qCeuloUoVaqe8+pipXdlSpaqUEkBOV8eKspQJHn1uy/6LVpx62mvjOGTLLJzJ5HKFYgyxIdAAMYTFtqIiZa2Jjens7jzgwGXPrN4KpBBEyBOxAKCaqR1ALCof8MK5vQ88trZRN2E9rMcmm/Wc7Q8AWiODBecggcpkMsml7v09DUo1QkuIyBoQCCmKo8Xzeo86eP5ldzxUrcViJBfkfnnjE1+55E8DYcMD/4J3vPLzHzjhjKOW/O0fz91x+721eiUI/DQqNz5uQa3asRm8QEnWLzld+sTjTzagvmzRtCXzpv3+zw88tWbrdT/48JXfefdAvfHeL//qsee3eET9gxUAnDu1GyCpRiWpXyGIhAq073k+WQC2nhcEGT/IeIL89neeedTBK3cMbt02uGPW1OnnfOg9gOD7ntYIAIHvWxOjGzIx2PTuXBzDJWNbs2hO74bNfbv6q/lM4Gtq1BvMTARs4zPOOHXp4sVbhrZvGtg2dWrX615/sogopQSAmevVRqMeZgKFRkAIEASRlfZ9PbOnncCrhuC15a6589kP/+TKeXOn3f2zj3/5Q6f/+Mo7n3p251HLZ/dm2tas3bBuzQZFfjMRcFy/cUTxkRYINTEbXL261S+uA8BlC2bY2Jx85JLbf3zeEQs7XrN8xkVfeEt/xX7hwptqoqvlCEDlsxlAQsLEt5Uk5ooiNrbLD5i9Yc2afzz8dK1e29k31DdQ7uvr9wPvsqt+891v/fsXvviJq667bNqMabsHBgfL1SiMB/qGnnr6ucVzpwKjABK4JSkuLuZW6IqImMjOmTap1Khu2T3Q1ZmZPWnSQw89QUSMHBuZMmPmn2679stf+PQnP/Evf73j2rlzZzt+iqOIiB5/7JlGubpo1tRGFBMJuCQeAARsK2QFNBLuHIg+d8lNS6ZM/t1X37FybufHX7/81gs/2l2U3o7CwlmTS42htavXAyR533sVHc24/shx0AQCO7fu1uDPntLFhqd1Fz2ESj3maviaQ+Z/8NSjf/inm6++/SlWngLI5f10oDD1igQAiahWKR998IKjD5p/8jFvyHcWojgSEFQAoILAaysUhPFXl1weNuqEBKBzfqZai6Zk7Jteu6JeaZAmYElLbHAzDCMgzNzdmYtBdvbXiPjtpx72yYsuO/f89x940H4A0IjDydN6v/L1LwIAAMdR6Hk+IAZB8OILaz7ykc+fdPTCJbMmlUuDCpVNohwIwoV8RkCUylx8/aNbyuXvfuyNczq8XYNVrf35vYVaWCsGesbUIrxg16/f5N60dfF6k3ddloBO8yjGEBnRZWqZOB4aLGmgtoKHwMaIaK0VW4X1RuW9px9w+c33//Lah8TLBOD5vieA0IwEJvcWAWARD8Ifffntd9zzeCNiIlHomBQ1okCcFj7QzGRirkY2NOa0Vy7vbQ/q1RAJHWLkuJgQQdyqFGLmtpxPoIaqJqrGbztp2Z1PrD3m8BO+9rUvventr5s+bWor53h+IGKefOL5K3539Q+/f9GBsyf/5yfPrlcGRYTBYlI1kgHFD3QWvFVrdz7xwvaj5iw88RWLButhJhNYUaFhESKPOooBAPT397VStlVIuARbx9EjYqDDFJcky42FLVsAcGmWiIDAgqiZolq8fL+ZRy5b9LdH1/e2tWW1T6RaE+aG44wIiGiieHKRPvCWV4Iw2BisBbDJg0Sl4DI7oQUKgbwwDGvlGmoFnBQeTKIP7HyhpIS373kaVBgbpQmq1Qu/dNZP/3DXD7/ytf/86ndnL5m/YOHcrq4OT/u1em3Lth0vPL926+oXuvP+BWced95bD8uRqTZEayWASWE8BDcLAwgee3b79r7Bf/vQcV1Tu/o2bUPyUKyAABMQ+doHAOuWNLicv2HZO0z80Xi0C7K0gEooDKSU7wcWxMQ2MQeTWE6ksvn/uuyuVRt2FIJcbJKc9Kbbhil4LcCQrL4iY2xf/263Bo6sFWDB5rKDpg4lcKvekVH5ClFM7OYmY8rVLITAoARBiJSiDHooGoNc7LGOGp991wkfPOOVDzy+6oFH16xf89TzjzTCuKEVdnUW3r58yhHvO3z5/tN6CtlyqVFl1pQUPRTk9CVAISJgGOkgl//TzU/MmNz5puOWVMs1IhIQIAIkKwBAnvJS+k1o4Y3Ij24GLyBVZZat53ntHUUD8WC5nixyFLaGi23F71x2z2d/fVOv1wkSaBXEgKS0uGp/xCKSpFtKQhhBt5KIkmFQ5AwcFAG3ZLkZZRcH0WGS9dacduI0KyAgC6SL7gARCJXneS7ECOLtHix7njr56INOf9UKAYiNgThGYEVICHHM9Ua0a6hOCjxWw4lUIOx0mlhhVMCGY8J48w5zzld/S/Hb3nzSssGhslIaPUBF9YYABO0d7U2hgYgtGrFp7Y2H26XBQwEQywYAp8+cImA27SyBs4qAAl9tG4p/+Mf733r0yrv/8Mk3nrx/rRYRkjHGJTQggKc83/PBWGUlyYthJlellZOcekZHayKlHNFd7EPI2W+UrgjCBDaBJKVFgNktQmEGgNiyFQkCZZ3oRiEiY2RwqLKrr7+/f6A8VCpXyqVKtX+osnuoVqo3DIhWCoUYXdq1C79jUkZUOIotg8em9pV/Pf7235+3csGs7//u7krdaO18JYpE7R6MELxp06c4wgHgGLsj4VoaSd/ho81AEQAsPXAJgLdq3Y4YiEgzkZ/Lrt9aCuv242cdv3hK+6ff9eopPZlGbKPQECkB8VSw8cnV/c9tynhBZCIAQBa3Qge46YJKqzxLOpDk8Y0IRLRk7iVhoOFgnAgC1sNYgAt5n62R1CFABCL0SSkgAiL0iDylPK2SlXPNJgjiFvBhk80kMlEZqocsm3rma1bM6cm894yj12wtb9tdDnwtIr7y+svR+i19HbrNRbkmkhvu9/GR6KQyDAqRAoCDViwrYueqNTv6SkZnPECFStWFM0p5gVSHyt0dwcypbSFHxsbOQ2k04rZM8eGLr9p635OBF9goAmGV2udJsa9mGckRY+xo6TAaRgIBAjaQsl2aaZAMiKAgylC5Cgid7Vlm0K7qdJJR1ZIljIKQCKhmzBDTOZSelPbB8lAtiqE+e3onoak1Qk2oJQbUgJoZAz+zat2OjVt3zZ41bcGiBQAwqgrQKJt6Asgfk66QUiKybOWyBQtmr91R/sfzm3N5T5AbkSyY3aM99djzO/K5HAh5GcUg9TAiABIhlkxX237HHfnwD6948S8P6gilHnNsidN1dwnRW1YQpUvV0HEsolv2Evjc3lGgREqMiBu55dAE0D9Y8QPo7cgZGypfBYqa909vBUhOUo6QoM0vOJrWUA8NAIsxFEYa+dYHV02b3jVjSiGMLQigr+9+eM0ghysOX1ostllr9hxIHD0IoxKckNBY29ZWfM0px1SFb7jrGQs+CjeiaM6U9tccs+hnV9xbCinQWhEKYBQKIiILeQhoO/afs/jko1f9/LrHLrw+7q9DGNtqnawQIIIgSwK1J+w6XO8AEQDJAmWy2XU7w/++/E4r0lxuNBxNFkAWRbhtZynn04zewsMPbXzvBb8ohaLBAtuWtTMjnIjhTMmW921xjAEQjIkBBCTyM97jL/Rfede97zx9RVGzjaIgoB395b/d+0IW1elvPsVdMIqFR9GdRh0bJnEyx9GtAj7z7Lf05LN33Lf6/qc2FjJ5AaiV65/68OlDg6ULf3eTXwzAiIE4imNhY8VaNrroe3nVtXz+fmeevPuJNQ9867c7Hl1DqKJG3YaRCCYF6V20H8E518liI0mcS197X/3RTZff9LjKZoYTpQRgeLEUiEDcqK5cPMsnntRbuO2JTb+8+t5s1mcTYsupoxw292Vs1a8ELxawxgKApxTo3DcvvOaYFQvfd9rywb6SMTYf+Nff8thzG3csWTz3+NccKyJ73iUARhUYTJ4kgs2+AShSzPbgQ5e/9tRjt1eHfvr7e1mTDxxG0bz27A0/Pff4IxabcgW8mKEex5EYI2wRRICD9nxx6qTOlYv2P+s1YPixn1z19CU3cilC7XFoATBZ5AOQENGFqtyaYo6zPq3evPuuR9a++9RXtmU8K+h0GJASUkIkiKCoXK2/85TD/uuTbygN9M+b0vbqg+ddf8cTlUasEF2tNWHbDOs1DZfmHgpNlTjM4I7/WQDA80ga5U+9+/hff+bNKoxihpyK1m8e+PW1jza49tb3vLlYKDTLju6J0GPPGBMdSMbi458+v62Yu+OhjT+94p6Ozg6xUi3X5/T4S2d2cN0gEQC7SgYOkGBARtBdubbpncGMjqlH73/YOWcMbtx6/3/+csu9T3l+TkCDAQCFoFylDhRATiwTMKzJvrBxR1ni/RdOQkWAIi01qBO5S8qiyuf8wIuMUL6jOHfa5C07ywODda19AUa2yBasETZp6GCYrCPEBQACkEDrMhskYg4PXjA1SypmQYn8IPeNX972zOad+y1e8P5zzmY2e2VnGIXeNQVGy58ACBFZa5etOOi8j72vaks/+vUDv7r+ge62gEylXG2UwwgxCtBdnpaKdmYToCXAYqZ9Zq+xtnDIohWfOnvB8a/YfOtDD154+eCmncLJ0rK0yod1uSwibC1wbCCOI4muvfvp9VsGM9mgo6uQ8Ty26BH6JERASMwiCJ1tnRF5v/3Tg9fd9+zM7kIxF7BlSomKAAREScETSfcRSN55BIc5q5BcbjkLo4VgKApDiTWb7vb2b196+zV3PA/Y+MZ/fbmzs5PHCRiObahTarYSGlp+cTNOiMhY+5nPf+rRh5+85ea7vvLjm3f0Vc5/06GdqCu1ISJfeR5AU12RuKXdyXdFbYVIa6X8OA9dx67ofeWKXc+v61u/udjTrnKaneuYspuDHICkVoPDDpj9psOWXXjD7Vff9MjKpXNffcSS1x+/ZMHU7mq12ogZGDRKW0euv9L42ZX3X3Hjo09t2zE5n/3iR96Wy+p6reEpZQEJBQlELFq0VpCEtOdo2rQUHYODclyiwPNIaQBNWhRyHlQ+5/VF8JWf/PU3Nzxd5qHPfu7jJ596YhyHWgeQZvCMT2NEgHESaCa8gBCV7116xUVve8t7/3brnf9x6Z0PPr7uA284ZNncyZmsB6kSl+bCVQEnUomQM/6cow7WWT+PXhSGxtrph+6PQIYjZJbhscam+kYkRsxR/LMvnP76e5Zcd9cz/3hq661PvPirKx54z1sPf8OJB8/qCpTiUh1vunvD9355y33rNy/p7v7M244/+/RDF03pGKxXyPMsp0YFMxgWHbQXPGukWmsoRYyq6fSnBrVz4xSQ0oo8yGrK14G2lOoPP7Dq0hsffeTFgRCGzv/QB77+jS8YE2nt4R5I5gjq7s88XPeiVSGMoruTZsxMisrlysfOv+APv726JlEn5KdN7+7M+xv7qjv6+r//kdM+8PrDBocqylOuHqizWrTv9a3fmW3L+W1ZiS1ZdmU9FAgpJ2TAgrS6sAQgZNEiAOfyRYu4eVf1T/c8d/HvH3hxsH9+Z8/BS6e3Zf3n1u34++otbSrz8Xcd+843HNzbUzC1ejUMSaGwkAAKA1tho7T/nZ//ZfXu6ntef/RxK2bWqg1UGnDYf0nDpmhFejrbL/jvv178x3/MmdzRls/uHOzf1t9fhrC7ULjg85/8xKfPszZS5KV2z0SyY5iSIyqiN/OSJmgoAlZYkSLEv95086U/+/X99zyydbDPQtSmO40x3/voKe87/dCBUtnzNCClK+1FKV3Ztjso5nQ+AMupnERMigY65SnsEhUTwSogIgQWSFg0Yi7IBPlg9ZbS76/7+/W3P7Nqx0AMcW8md9IR8z9w1isPWzI1qjTK1rjgLYizoJFcFUhhAt64K7rw6nt+/Zf7P3rmSV997yvL1Rpq31WtBbf6EYiIjDU9ne0XfP+vv/jjY5qgwtUAMlMmtx13ylEf/Mg5yw9eajlC8MdU4Noj7V4SocFtlwLA1vraA4AXn3v+sSefKFcqF/30t48++uRF//a2d528YqBU8bRO3TJAQUvgIzMI2uSpLqdWAIxlEdFKCYCrJdHUUeKqaCOiACEKWLYS+EE2l93ZV1m/ZXejUZvW2zV7epc1Ub0eg9JISb0yh9e6+BcKW7Y+kk8SFHJ/uXf1mV/45aVfPfuUIxeUqpFHGtOiS664Dgt3dxY/+8Nbf3DFHW96/YmnvvnESV2T9l++dOq0yQBgbKhIv9RFx6Nk9DBWM8EvifWmiOLYAMrC/RYv3G8xAFz7x79YMJ7voVJAlKyHcbAoMAkYBkj3vwJgUspYy8bkchntqWq5BuiyUKFZC60VPWIRAlJKxyaO+ut5RcvndyN1x7GpDA25fDMAdogVIrroBCAIkrW2o5DfNVhDAK++6+RjF5154srfXvfwKccsRWkkBiw2n+NcFtBK1aG2dMUBZ77jbe5YbAwhKQqSGTjS2kAcVjBj26hhaVp14/4iAEIJQCFKkSJljAnDOArr1VJVg+97vlBSgtv9i87fczCVCEviOxhrPIR8IX/74+suufI+45B+sU1NCEScdsDBSwyU1HxVOhIsN0y5FoWWSWtAAjHALljDIMwIAmCN0Rx3dXXd/9yOE8776UXX3tfe09uoNo45ePHmrUPVSuwhiSQ1g8CtlxMrxoK1Dlwc3N1njY3CiJm1ctV2JaWMtP413fpx20veCrX5i7OLlCKlQBhFUIMKtOeiQckwOmxe0qpcyUJksQKazFAYfOSblz+1euMFZ57gaYwtIBGl0iNdEzdiwJMxEFaUJkGP4AlIihogWYMB2WxbsRLzj3977zcuuYMxPnrlUiPA6C2d17N0fhdq4kg117kiQJKazhZs7AKaURQprWCMH/dS20SEHgHfjDrETZsJAASQwAqbyGpQWpEz7wSS3V8BnHudVBh0ZpSwyebaz/mPy59dt/nmn31i7qT87v5qMhMwjRw0iwyNzMxsPlrAlVUaXgQqAMwWxfrgFXPZWOAvD6356WUP3PLki4u7O3/yxbOPXTlnqFQlVLNmdn39E28GYCAN4KaRpMadW84rRALAjXqYPnYcTPefIfRI5m2tCjTqJWnkjwiAxhoTGQXoeWp4XjXhekzLVQIAAIvkssFja3c/+Pi6q3/80Zk92d2DtbaONp8grJvQhIYtgEK3hhloOCCU0BNTH0NEXNK9ZWYE8Uhlg0A07Rqo/PnBdZf/7cnb/7E6Bnn7MQd98dyTZk8r9g+VPVJWDCEVC4G17DbhA7QAwMKA5HwPQdIkABiGsaPHuNQYRbR9IvQo5h3Lyy5G3uK7NiEYZMuxiRDAU5RgC+neV5LeLVE4AgKQyWQeXfXM4oXTly+cPDjYXyy0PfDomv5qtOKA2T1tmYxWCphZjDFiYmFmGa4HRoRMHhIqVKiAyNdKMdt6w+zsG3r6xXV3P77pzr+vfnLrdgvqFbOnnfe2I990/IHMcWWgrBWxZSAlIsYm1dwQQUC5NB8YnkeuDqw06o1WajigrslDI6kke6D1S6hu0BTNLdRLGN/EcRzFCECEwlbYkqIW1B0lrX2HRMACyosj01nMkmIARUo9vXrHt3/+Z5XJzps5eb+FU5fM7Z3e297dlm3L6mLG8zylCMAFdUWskthyvVGvVKOd/bXNO8sbNu9atXb7s+u2re/fGUPUhcWTDlrwxuMPOvmYJd3FTLlSJtAeIbMVQofwNKtuppo7sScB3KpPcCu7Go2G63iL7zauxtsTO8u+7FoxhtxjLT+IoyhshESoFRjmBMwEVykaksBSqnFQoWGePbVj06asBRBN1Vrtg289+oSjD7rxzqduufuZ62969BIbGuAAIKN0MRtkA9/3lSIEdCY4xbHUG3G1Edc4DMEwYBtQT0fhtEOWHbls9tEr5u43d1LWl3o1HKqESvkA4Cx4h1i1vA4OIwbgSilZFxr2CAEwDJ2MHpeFm3TYi9hGRL0Hu2IPrWWSCACEYRhFoSZShJikuQAIKreeDIaBGwAgpEqjccxBc1csmV2u1BFZMTaqQ7N7vU+9+8jz3/aKDVsHn1m7fdXabWs279q4Y3BgsFKpNvoHOIoNABBpIi/jqba8P3t6R29XYdbkznlze5fM7pkzs2NydzGj0ISNSr1eDlmRT0rSUmLYjK2Mkn7Db55+QwStNYJqNBogjEll5r1QcyLzTkTGKV61RyonMhpTpN61RiOMopgIPaVSjk9NaQBKltanwgcBrNHaawsI4pjA1dNRUd00qoNIMrs3s2DawjOOWcAMUcRhFNaiuNaII2Pcpi6axPdVkPFzmUwm43ueBkJrOIqisFapsSAppTJMsU2T9RKzZJTeSrH21leW1PXwPI0AsW2wRES+cDOfcF9b8+b4Ugp1U9OISqJtSS1KJlBRaKLIZhV4CpkBgJopk4l32xRwAAgiQFYsxkAAyOL2ygICJAUCYWjrdZNmjQIRtOf9zmLGwR8AgowsbITZRpVaKFZYiBR52gP0lHZxXJuE0t3+V9JMX8YWeQutPJ6ueADLIIzaIwRl2RU2prSwjLQ4LKMlwShh0Pp5/F0rJhqhiQ4YY9gaL1CeJkRpkRNJj1r2gJRmrA8hWQQHLdYfggAhUXM1AgiIBbQWLIFKHXe3Ww4gakQvUNlsJjJUbTS09lMFJwkwlTBvuuUFADQLaSfUGLkZTYpOa60A3JbjAuTAlr2QaCJhkHD0PpB4Ly02hlkUeR4FCCpRPC2PIUzrIiSgQsJamNRSH29OYtNwRUFURJGY/nLY1V5sL3okAtZG3KhVZc2GofueevbKWx58/2mHvvV1R5WrNdUsGQQAbl8MTG4JgCJAgCwsCM4cImyJnSbyXJRDHhHTCsr/K56hW3DYWuSxueoaWj+kWdAsgA47sy1Ubl6OrtpQGuJ3MoXB5R0kxAYcmc6aEjrxUgjLQ+b8r/x2oAzTugvZnMcsQ+X65h19OwfL3e2ZM197+LFH7F+vlhQgCktz0SegsEVkEWUNc2wRCRSQQkJhB2ONYDW3PoIVYJLFm3hJo5hBmp4UjOBlaQYIm4fElcykkeM/lkx7bUREqAAJlCJBAaHh94Tk5u6pMryl2Kh+j3q+s8OTcUQwsektZH705Xf+46nNTzy3cfvuUmRkzszuE45YsGzxnAMXT+stYLXaMDZxGdnJ46RiCBnDcaNhQuMW9ZBC7Wvta9TDACFi091HAIpjwyBKqT3HXse8y/joxR5ER4vKGI8qia4DBIAgkwl8LwptPTJaZcnY5mnDH5qyOEkPFQBgV+PUBVbSUm3YXO+XTIWkmLeJ4+k5Pf+4xWe+dikkKaACInEc1+uNXSX2UCGKTdUAALhkVBtJtVyP66E1jAwConzlWY+FffRQIbdk5zgaEdHgUIkhLrblPRUwj8Zb9tpaqYqtm52NbJTSepz9tpugBQC4dPZJU3p7J3Vs2rRj3Zb+pXM6IMVhmpsNAQCkq+pI3AYoAA6WB4dZN6G4lOGxdYQAAEBhKNCohlJpOAPA4UlICEqhKOvw7lSguviwCW3/pl1RzYDWYmxUawSBF+QzyIAISpOntEr9RCRSbiahXrN1CIHnLZgGgCysWiTaKJLugSObRB+dqTTuaWMua71GrLXdXd3LDl3a4Prd/1gjWhuxFsSAWAAL4Ep5JHV7mk9J0gAc0JzUNm+dAcOWAAuyq9ENCECIWimlSGntK+Ujea5GJaZj5zYUB0ZBU7e13YPbn183sG2XaZjajsFaf8lYicLYxGxisAaGiSCAbIU58GB7JXrkyR0eZFYedjgAuMDYy9GGLy0eM14T59G+/q2nB5T9yz0vPL9+dyHwkYFY0DIle1Mlbo5KUlYw9RhAADndvUncbyMzuVNbEJu81CyOZFEMQgwu9I7oKiq7NX2IYKE8UCn1DZGBuB7XhyrVSsXP5xqNMIpMbAwgk3J7hWKTAUwU5TOZWx9a9fzG/und3a969RGQrk6T9IX/CTLtKdM0PUFNsGMqiaAIKaVF5NTTTlm+fP+tuwZ+dPkdnqfYNJKccwf1uq2pHKYnggJuTxknHhycwwCIyEk4HJKQjAtPAQsIuR3ckrEQEXE7jAEk9omIIAuJkCAgWWPjWqM2VPfbO+JaWNqxO1MIolotbjRYLCoEBFfYyW07IgpByFfQV4t+fsVDdVs+4fTj5s1faG3c3CZmj/gEpiUdxznhJXP0KM/HfbXWZrLBuRe8L4bG1X974qq7n+/KZ6yx6UYLI5KvWhi6Cb2m/RRhBCa0CJyiaMkQJWs4h5HD5q1GvFazSroIM6NW2WzG97TK6LZJ7Zq82uCQACOwxDFHlk0MwAqQADRoMFzo7v7pNQ8+8cKOznzuvE9+CEbqtH23xEa1EUbYvjRpacN3ITLWnvGm1598yquGwvCrP/3rqm3lbEDWWAWokNIEe/B9ryWzfuSjBcRxOgux42Vh5y0guKpinJbfb7o9o2ehQJLxxIJEfsYP2nINjjumT8p3FspRI9fVli/kFEKAqKz4GhUlwLSJTWdX4bZ/rLvkD08AhOd88v3LDjjA2HjPGeb72EalG+zzZWOQKlflYeuWna898rQ1G7cct//033zrXQWSWASU5wQ5Iq7f2j9vWi9AbCVZltm6FMg1AiBATmSKtD7V/X+Yr1uqF0JikFpICv5AZEQqcd+uvrge+co3bMN66Guy1mbywa5KPGdWd0dnXnyNpNlysei9uL129icvW71t8Jhjl1998+W+0jAxF6diZBz0YxSqMdrq2Pc2dlRdIuSM6VMu/MX32rP5h54tfeJbf4r8og58w0lBk1yx8P1Lb3vgubXZbJ4tA0BTsLQSlAGsW+ntiNv8a77AaMqPsLkS5SngEaKGQlexfVKHX/AzbdnipCLlvI7O7PaQfnT9/dn2HCAgi4S1YhZWbRt6/2ev3LStvP/imT+79AeB7wHiXrdN3kcSvVxCt9yONak4jl95wit/cNF/+Br+ct+28772x5D9XOCzCAv6SubMmf7nW5/2fFcFM2HmBOFLQMGmN4guNb35l/roLQhsCgu1vA8qV2hCUAH4OS9TyASFTK49H7Rls+2Ftp72GQvn3vL42myxo72rncFyFLUVg4fW9L39U1c8s2Fb95TOX1518czZM601OPF2evtIH9dwD/vUplbYhHDUqA+OjTzPM8ac+c63fOMHnxcIb71n43s/96u+clTM+RxHthYdcdDMu/7+4tbdgx4xGwaxiRuArr4iU+oRkRPu7mf31+IsOxK70KR1gGqi9ZsutNsFizzfC/IZvxhki9liR7Gzq7NK/q33P3vi0UtJERvb2VP48yOb3/GZK9du6+vqCn511c/3P2CRMZFWGsapcy3NF2+xUcch3agfJyT0WI3X/H2iS9xxrXQcx+8/993f/MnnLNXueWTHGz72i7se39RTzDRK/QfMnlwL63+77/lCRiFbFmp5Cibr3pqbaEtix4Fb/Jc6NU6vNKHOJrrj7uEIMyxbhQlBK/I9BSiFtuydj6zeOVg/etl8aTTaenp/dN3jH/rq1TuGylOndlx+4++POGq5iUfUo5qIDs1ujzo67vnjE3qk+TWOSTexfgBA0Z6OTPwvH37Pj37zbSryMxv6zv7cb7//xwdY56ZPyy1dPPWyGx6MQIPYNHPAIXWUZn+MF2oaA6iPDEAnIJwFFnSFN8DtZJkEL4VRmNlYhb++9sH95k6du7CnZIJP/OimL//wrsFG4+Blc6+7+Y+HH3loHMVK/1Obeez5HGZuiYbt/QFN6HhctK/1Rxsb7Qf/ePiRc999/rOrNgDIMQfP+uZ5p67f2Tj7cxfd9P0PH7VkeikybsNNwbRAa1rFH0WAh1m9yc6I6PZVYpFEcsMwNxBKCk6pJEeS2Z0O1gYZ/+n1/a/50I+/97n3zpqR/+J3r1+1pgoQn/TGV/3459/v6m6L40hrLcA4ntPRStbWvQcQYa+SfC+iA8bIkIlECowhvdIqjMJDDlt5/W3XnfS64/LZ4IHHd5923s//9vCLnf6kS6950PoZT2lJMiKbd2lugTcs/JqyIvUH3fYoiVXiYKjW3kIKpYDDpAiZNCN5nv+7Gx7RqvDXB585+/xL16xrtLerj335nN9f/cuu7ry1VnsK9kjllke0dHlvVBaR/wPWS+kMm0h1BAAAAABJRU5ErkJggg==",
    "moderate": "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",
    "high": "iVBORw0KGgoAAAANSUhEUgAAAHgAAAB4CAIAAAC2BqGFAAABCGlDQ1BJQ0MgUHJvZmlsZQAAeJxjYGA8wQAELAYMDLl5JUVB7k4KEZFRCuwPGBiBEAwSk4sLGHADoKpv1yBqL+viUYcLcKakFicD6Q9ArFIEtBxopAiQLZIOYWuA2EkQtg2IXV5SUAJkB4DYRSFBzkB2CpCtkY7ETkJiJxcUgdT3ANk2uTmlyQh3M/Ck5oUGA2kOIJZhKGYIYnBncAL5H6IkfxEDg8VXBgbmCQixpJkMDNtbGRgkbiHEVBYwMPC3MDBsO48QQ4RJQWJRIliIBYiZ0tIYGD4tZ2DgjWRgEL7AwMAVDQsIHG5TALvNnSEfCNMZchhSgSKeDHkMyQx6QJYRgwGDIYMZAKbWPz9HbOBQAABUf0lEQVR4nLW9d5ydxXU3fs6Zecrt23e1u+pdqAsEGBBgEN0FjG3ca1wSx46dOI5jJ6/jFjvFfh3suCSObWzAgMFU00EU0RESEupt1VbafvtTZub8/njuvXu3CUHe33yk/dx7n3memfnOmTOnzXnQGAVjCyIyc/SRmRERAOFkBRGBWde+TvgwvjBWLiNU2uJqXeTRWhM+THwsIyKPuV75Uu35pHfV/8InrcPjfo+eyWzqbsRaVyYMoe7RmtXUl2mSO6Ys5k3dNVVhADM6BmaoDvLNP7ECfa17ZkKViT2falBcNwc1oCvXJgWaqvdNdvH/58I8eaPRz9HfCFxEnBTlqZ4waZlqnt7QQ950kZU+VDsTNT1V7erC4dpXZq6hEfGAifUnu2XM1bpGx2BRfeA4gEbXbNTuVI2Oa7f6wPF1o9UyxYhr1bC2quqGDNVR17peATC6bIwZrWeMnmwk0d2vwwQm8ME3XSauxEnW5ilUrhREqo7fTOAYp9T5KqD/z/jh699/kpX1hlA+9crMp7SaT/JArj6CGcbVmmI9jR+mMRM5+P+qRKyjftlOtrrq+lNXc3y1/1fMbrTFKlrMzHXiRNQNHN10GBAQEKP/o92r0ex4seH1Clf//j9ZrwAAaIyaehGNofdohNWKkyyF/6VswGMLEUop3+hQGViFmtkgAhFV91FkYGAkqt9jalxlIncy1bGINzeWiQWNUVMT46mLOycrtYmcZEaZDXO0TqWU466WSuVcNjcykh0ezuay2XKpXCgU8rm8H4bA4NiW49jxeCKRiDU2NTS1NjU1NTQ1N9mWW/8QrXW0KRFR/WYefQQA5okizakOcyJ09dQ2ZuATFZa6MrGZ2pr6X20OzMBGM4AQsl5GOHzk6N49B7a9tm3fzr0H9h48cqh3eHCkVCh5nq+MYWAN2lR6wFj5hxJIgnDiVjKdbu9omzGra+acmUtOO235yuWz5kxvbGisNWC00awQSAiByBEQzBMXzXhlZKoyFY1O/H1KoJkZkaZq6RQ58kQSNsYYZktGewNorQ/sP/DKps3PbXxp00uv7N93aHBg2Dc+AtlgWSAkSWEJIaQgFEKwJEIiQI5mi4G1YaONMcYYHbDSoYYggBAA4k68pb1hwZJ5q89Yufr0lctXLJs5c1alG8xGh1Uaf2NE8+Y4ZAXoKYAb34M3s+MxAyIb1kYLIYgIAPL57DNPv/jwg488t/G5fXsOjmTzAOSC41iOHbMs2xa2JEdICUIiiQgQgirHpEhKBYMIaJgZDIMx2ig0GlSoTKCVH/pl3y+FZSiFEEiQLW2NK85Ytv6iCy68+IKlyxYDCADQOgQmEqckfY3lPGM22ImwjKt2cooW4x705kQLrY2UFFlOnn/uxdtu/cPD9z6+f+/hALQNVsy23bgrHdtxyXWltG2yCAVhtJi4ohEwVAUQMFUtA6rbHGA0JGRARBAAhg3r0AS+Dr0w9MLQ017ZKwdlDSqTSK48fekVV19y1duvmDV7NgCw0doACcLx2s8kQE8E91RgeaOb4dibIz43dg5GPxBprYiIkEql4m233PHb//n9Ky9uL/rFOMZiSdd2LTdm23HLilkkBAIyMDOwMYiAVcvTxJ6NV2CqwnKlXajMERJGe6DRRqtQBcovKb+oy0W/WCqGUGxpbDh//bkf/bMPX3TxBQAiNFrAmI1xKv478dLEHxFrIwDgqSkaAP43Ox4zG22kJVUY/vbXN/7k+v/aunW7A7G4m0qk3FjKsRJS2CBIcESzDHXzBPWkFRESM2OdlHDqPalUJkYkYNCgQ0/5+cDL+4VcsRgWJOF5F5z1+b/9y0svXQ8ASikh3oxUN4kEMgHoyHAzcQLfDNAYqVWIRPTcs8//7Ze/+uzGl2OQSiYSsaSMNyachEUkENjoCnqEyDCGjrDeTlIDurZWTtqByBIxekvUpYq4ZBABCBHBMHt5v5ArlfNeqeAhqiuvuejb3/vmnHlztdYUKT+TrfVJKXpCFwCgnqJ51NaBGJlZ60vVtvd6+2w9/9JKSUsqrb/77e//4PvXe2XTmEjF41aqNePEXQQwhs3rUSXW+jT1+h2/eOuNIGONWZPjRSwEMbNfCvIDoZ8vZIu51rbMP37vHz7ysQ8wGGOQ3sDKGW9vGWeKqTcqTV71FCZwtGitpZQneo9/8uN/fv8DG5rtjB2zGlqT8Ya4AQZNWKdcnlzHHXfhVCTWcWa9SYlxLNEwAKBANFTMF/MDxXI2KKrcdR+95sc//aHrumPMb6+z470e0NroqaftFNuIAENjtBBi7+5d11390R3bexqTmXjazrSnyEKlgap9rn9QPTeIlvmYrxPocRJCPmWgp7ZHAyIIIVQQ5HrLpXypvzR0+WXn/+bmX6QbGrQxhATArwvC6KYC1T25znw0uhnWmRbHl5O0wdXtng1LIXp6eq64+JpjewdSyVS63U21ZIwJja6rPwXTqCfy+q8na7p2tSbu1d0FU6/C6oRPJHiQaOUGcoX+cKg48NaLz/zd7b9OJJNVPh8VU+3g1Iy0eqXe1UIM9UbJiVr/5F2arJhSqfjxD3zq0N5jqXS8sTOebk2HJmA2WC0wNVmNlqoNonbL1BVHjXwTOzy1paxqvZrskmLd0NHQ2Om2ppoefeSFL37uy0is9UkEs6m7N/YrIVCkatcsklP17CQPNdpIYf3T17/11MbnGpPpVHs81hhXoSJDaCYRlXAs4jgBNawz5lXqnLJIVz9D9XNcX2G03brfCZAQlPKTLYlES6wl0fj73/7h5htvkdLWWsPUZTL39XjHIZ6KhXtS6qj9aIwRQjz5xJNXrL86gemGtnR6WgMojShgFL0x7dLrMv3JWowYRe33SIg8udZaE8cn1XoQEXjUX4pEDIDMiCCEPXTwxOBArqk788TzD7a2tkFlhsaxjlFJhyt415gfj2Ed9cOYOLCpLtV+jNa4CsNvfv07JiQrZadbM6xDwApTqqEwXuPi8QCMUatoEhocb20gGv08dsMcbc7UmhsLS61FHL0l6pUBUMyBChNtmVgyeaDn8I9/+FMiMoZPYVHxhA+V8r+zdgJoo4no7j/e/fTTLzXEGjOtSZQVNa+idwCyqXinkBERkRCISEoSgiSRIJJEEkmO8jA0SED1bL2G3eh8jKHf6ucICwNsGBFQIAkiQcIiEkgWCouEIIosA5F1BBABsQYFMzKw1mRzLENpkbnx17cdPXpMSsGGq7Q8ultP+GVMR2pF1oTZepmx2uKUq7u2sRIis/nvn98gQSYzbjqV1loTSq6y/OhPZVjEyKCVNiEobdgYpVW0dhEFEZFAsklIC4FNJSJnjOpRGUOV+kbF4YqCjsBo2AghCMkoFfqhCnSlM8BCEJFAQYIEWYIkAQEBG2PYaDQVLBgACTVzsinp5fWRE8du+u0tX/67L2pjJtPOq+ueo7nHSeWRes3wDZjoIqCNMZLEK69sXn/222x022Y1uak4G1NDmZmREBBCT/klPygHxjccslakjVFGR440ZmZkIYWQwrLJdmUs4yYyCQQ0mgmwIplOKbRx1QoCiCSEKJbKhZF8WAxV2ahQadbMBgEJCKUUQlhCWFKQjdIlGbOcuCtsAaYStFNrQFqUPZE/3tO3bM2ShzfebVl2vY71hhCTlS2BT6akTQm3MUDinjvvzfml7uYGO2EbY0ZFCGSBolQojwxlS7nA9/wQNAG7worbbjxhJROxeIyEEGzYD9VwsZgtFrNZTVkrng29lNcwrUHGLVAGDFR1ndoWhFgx11R+MGzAkqBh+FhffsjPlUMDQVPCaWlyE650HItIaK3L5TBXCItlky+V/ZwyICRKNyZiSSvTknISLitGAoiYHrCbsOJ2YuuW7du2bVu9eo02mvAN8Nsak5AAprItjZ2ck8ihUBVeBEmt1eOPPCVByDgCkjEcOUQBQQqRHSgO9RZzpZxL+rTZLUsXzlg9v3NGR6a9pSkVd5NJx3ZtiWiMMUoXS37vSO7A4eH7Hn/t0ef3jAwaP8hnWu1UUxKJjdbAAEAAHNlTAQkYgZmRgVCQ9Avl4RO5Yr5cCr3Vi7vft3716YuntzYl4w450mYU2oDWYaEcDua8E8PZ/cdOvLrr8Kvbj+093F8oOaWCaulMpZszXBWctWbhCBGH7HDuqQ3PrF69hg3XMXMe92ESWqxt0VUPCzC/YY8OEe3Ztfu8My5RZd0xu9VNx0AREhKhlJQfKQ32FEK/cNEFcz75jnPXzGltiMtIoNSalWHDwGAYInpFWxDYliuBQd7/3L5/+a8HXt07EHNibqOdak64CVsgGaPZ1EnWWHFs++UwN5wrDgXZYqkxCZ/7wFs//fa1DY4IQuOpMGQQBgGAkZGEFOBIsghBYKjFUKH00mtH/vOWDZte63etROPcVDwV06FiAGVQSBo+Nnjo6LFrrrn85tt/p5QWk7ljTk6XzFwJCTtFm1F9McYQ0aaXN2fz+dZ0k+UKYwwBMbNhDnwzcjwX+t7H3nXG975wtfGLZc8byRfBICMCASEjIEfWcQQECjVzSZc0GzSXrp159tJP/tuvHvrV3ZsHjgfeSBhPW27alo4lJFJkzjegFQdhGOT9Us4v5cslyK9bOfO7n71yzdxpw9n8iSIAoGajGAgkIyOiACOEKaORIIANICUs+4qz5l101uIvfu+W2x7ZLfrYidnRqkFAZrBi0gVn52t7CsVCMpGsSQ0TTFRTFkSUE6WTU2HttfLqlq0E5MQsaVvGCCBmw4BUyJeK+XL3tOSXPrJeFbLFUKMgkjYAAJtoDJXWmCvSPoJB47quJZ18Ieda+O3Pv/OS81f85KaHntp8pLcPrD7hukIKi9ACIAatNSg/8E0gySyYnf7QO9/6wUtWxjUPj5QVkFI6DFSoWSnWHBowrIVEcBywXbJttG0pBCnAgaLfGNN/9eFLH3l+fzZbjhXLiUTCaA1gwICwbMe2jh7u7Tl85LRFi8aJ83BS1lErciL29bedZEVEv+98bbcAabtORGIAwADEoMpB3vhnLV/QkqBCwUchAAxXVCeqyHxVUQGYyTBKcC1n8NCJ3hN9C89YHiodZLPnLul6y3c+8fy2fQ8+s+OFrYeO9BWLZR0GZa1BCBF3rY7O5NJFnevPXHjB6tnN6WQhm80zoi3CkvI87QdhEJhQodYmUNqEEhGcGMQTViLGSoEbsywLLClKXji7I3na/OZHXj7IfsjJqoGbwbKF4zojuWzPvoOnLVr05gJvxwN9irTMzEKIIAgO9xy10CJLAGLkKEE0iMBKA5g505sEsDYm8rVWJo0ie6jWDIKQmdkoBMCceO6x5x6+7Z5rPv9BKUn5PhEWSh4Cv2XJ9HOXz82Xgv7hYq4UFL1Ah1oKzCTcjtZMQyZGrMslb3AkK4W0wWhjGEgbDBV4Afs+B34YKGMCQAIvRGWE0aS0USZIxMGySCltIbS3JQLwOVT1AqVlWY7r6Bwc3N9z6hBFpWooBHlysW5q7sMA0Heir/f4gCVJ2BT5nhEIiQHQMAAoNxZnY1ArJGZAIALEaAeUliUZw0ApNhKt0kDpvl/d/sLTL7/30+9eedHpw7m8FALYECID58o+m7KF1N3oiJYYEiGiNkYbE6owN+IBkhBCCiQwihkBCZlRa41aox9qzwcvQO0pBuNqC1BFOgQbAK0TCVuCYjS2ZQlgRoicw4iIgILQsiQCHD7UC1Vz88l3vypEo9Z1eXKUp5o9w4ZAnDjRV8oV45ZLsrJ1RKqPECRIIAil9KjpBoGAgQ0DWLbj54L+Q8etVDzVkBk8MvDA7+7ZuWn75W+7ZMVZywq5YWkEApvINxGtFSEMgKc0qEjTQ0OR2QyFZVWka+ZI4EZgIVAQkgBGNmgMoBfocjZQyrhlYziCmAgIQCP4CZeYqRQYBCFIIBGYSqwYEgpXIogjR47WiO8kVrZJy3jWUY/y1FNQMTP09fX5YZBy4kgUSV0IyACIJCxJILPZAgqKwreiyCJjjLBk/tCJPS/sSrS1NtvJ/Rt3PPnHP/X1HD3vnLPnr5kPSQeFjLyZiAiEEIntlb0TAACIACAKo2LDdbocAhhEZGSSJKQQ0ghJUpKwWAgwhEqbQt4DiJFRAoQgQ0QCtAQRhHowWyaQliUQRlc6A5IlBMiBE4MAUezkqSBW060qQI8a+sZxkUl3Ra7EBCIADPQPKlZkoUCrzp2EAChtIcDu7S8oYCIiRgaD0T5Y9vr2HknFUqT5+fsefe3pzToMVp135qyzlrQumhHLxMJQIQEYIKhq36P2XZwkUq6uy1C1yVmWiLtChUYrMMqwUTouVQjARoc6KIcFgUKAkGTZaEnWhvKFoK+/YKEtLYFgGBkYDTMyWEJIFIP9I57vu45lzOs5lytYVeBmBAmTsYiJHopxJtNo+MPDwwaMIDH6hIh62QjbspAOHMkVArCE0IYRhTHKElTq8wTIgf7h5zY+P9zb74CYNmvakrOXNcztSDQmVBhgHaBTbSGV+Z5KIjKAaGKO1Ia1McwCiJmZ0HJsCgPFGohBKa0VGQ0MaFv2oYH80RPDMddBxzJVM3VkoEAEIigW8+VS2XWcyQ4avU6pKCx1f+uMs1OUiOkCQLFYAgAUNGrvrqIgbct27KPHc/3DxelNTuiHCIYEKU8NHBo4vOfY/fc/ZUITc5zQC9tnTpu2ZFa8LWmUHzEfqDAMRqg/nVXxAFVWTS1OKjJNVIXHSIDUiEgccwUbCxEZ2BiNSCRBhwAGkFFKEBKEEIQYi7sHdvdmC35zU4Isu97fxACATAI9z/N9rwZCvQW8XnOpt8Jz1YpEAAQ8hmm8ruOq9sTACxDAIBus2s+qpmhhoRsTA9nc3sP9jusiAiGRsLP9xb5jw48//pw24MSs089aLWJO26yudEsmVAoMI0fPY2QmjqLpIOLv1UXGkUHUGFMJ9dcMmtmAgYqtCdmAZlAsAWKOTCRkIiETMZmIyWTCicfteMyKxSkWt2zHEpJsR7qJxM4Dx5nJiTtCWGgwCrSpYIfIiEZBzac1jq9OCh2P8g6QUOUDb6KEQViTN+sforURUriuGBw2Ow4cv/ycJcyIUgSeLg0Vn9/4UjlXlJZcs2bF9M6WnTZl2hrKfoGE4IoZIZqvqsCNyMCEJKXQSkWSIxhTCcqQQliSBGllgnJQzBdZKScWl3ELCABQCEzGpGuLmK3KnvYC4wdCawTQRGhZ5MSE5QpG2nvwhATXiTs86pKp4hXxMWMioBEm4bcnZwNTSh0nKWNs8FEoYZ17LGrPAABJCZTLFoABSCDJYDi/6fEXjuw5kEmm5iycs/TMRfHG+Gl9S+INMQZDMMamjhUzSMRJRKjUUN9gPJlKpBKWLRiZtTaByWdLxw8eO7jz4LGegUK5lEi7zc0N7TNblq49TUjBiNEOTBJkSibiMgiUHxg/ZMUEiILQcYRlSw0mXyoJRCFEZZ4j8zEzEJko/h1HmcnE4MuJnGQc0G/KEh3dTAIBkZkM61pIJzAIBDaBF2iAjvY0aA0Ig/uPP/qbu3c8v3XOnOkLly2etqh77lnz8/lS9+IZVsyKhofGVPxKkekjEu7YABILe8+OQ0d3Hg5UGI+7ruuGyowM5gb7hk2gm5tTMxd1z1w8s62r1YnbEWNhqFgHobq32hbalhWPk2FSJrIPMwoiEo4jp7W2Ag/6Rc/NOFARSIGZ0UQsQQNrrG5n1fC5SZxYk9K1xPFnqU8RaQYAN+YaqHgvaq5kAyClKA0WivmgrSV24dqFJc+TKLfc9+SO5zbNXbLkrKsuaJ83LdWZDLXvxO3OhZ2xTBKqvjSs6PFR7GdFaUA0UorzLj+3tK7ce+jE8Z7eXH+WUM2c27H2gqXTprdnmhukI0KlgkApZjBMCEgkCKQURAI0e35gGAShICQCiysh2BrIMCOYS9ctv+OB7YXhcjwTlzHSmqse9IoXCBAjq39tN64HeqKxqVYi693ol1M0J0XVASCZTgEAm8inHW3OIIAgVKWhchiE77/8rHldHflyuTyQffWJF7qnTz/76rd2LZsVSztB4EljKTIN09o0axLoxFwiQkZT5RgGERi00kqHHIbFUAnLmr1k5rxls4ENGs1GqzDUvi4HPvpg2cJ2JBKSQVbglbz8cGlocGQkl3US1rwl80hIYxAF1kgdEYENAZQLpUvXnnbO6TOfePGQ3Z9rmp42PEqDxmhjNAmyLKsegRpW4z5MIEselaMnsvapUa60kkilAAg0s2bG6NCYkZbIDZbK+aCrI/Hxq88pFfLxdOaBP9zCQl7x6fdk5rS5DbHQ9wklSyAGzSxIDh0f2rlll5fzyyVPh0xCuMlYuiHT0N7Q0tXU1N5oxx2ttAr8cs6reN44knBR2iJu22GhNHw8O3h8eOBI//HegeGhEa9cJsLG9qbuOd0t7a0kBDJE6GEtJqvq5NXMSRl84UMXPfvqL/MjZTtjxRJOdTIYGNiEliNt2wGomBrqdLTXL5InnC09lRLd0tLSIkEqpYwxIBAYkMAPvdJw0QsKH3rn+tmtyYJSB17ZfmjPvg9++y87lswMyqVABygItIncQlXXXGxad2cxW8xlC4XBUi5bOHF8MJ/bFZQD23Fau9vmL587b9nsls5WOykrvkI0bExQ9PsODxzYsnf3tv3HD/cHQZhsznRObz9t9dKu2e1NbZlUQ1LYaJTywkq4dEQmEQuoLEMAQsjlsuuWTbvy/Pk3PfSq3c9urLnidWLSmjVDzE04rgunsKdN5Af1J2ffGNQA0NzSaJOMTkSRFAwGkUoj5UK+3DUtcd0lK7K5ciyRfOL2hy7/2Hu6Vs8uDORIEKAANkBU2WyQATCeTixYNb+m3GttwiAs5ssDJ4b27+zZ/VrPo394cuM9z3TN6uyc25FuTgukYqE0cmJoqOd437F+FaqG9uZVF65ZuGJe+4zmeNImxECFWoVe4HFARAgkAQxWRf5IuUNgw5FGpLVhv1T66FVn3bvh1XKuXC6EsaRrjCHCyL6VSaddx2E2gBOFjrHoTCBeWdN/anz9FAyAlSltak7HErZRBIaxEtfApZJX0IXL1p07LZMoB+rg9p2dszoXnXFavj9rW1IbQwwABBhJSwYAmcFoUw79mtWFwSBALOXMaZy+4LTucy5ZffTA4N5XDxzbd3jTo4cDXzEbJHRcu7mtecWFa2cvnds5tz2Ziukg8H2vXPSqcZKEhJEMWmWhjKjZRGghQOSQYAYUCGWvvGzB9LUrZz/8woFEsRRPuwhABMiEINvaWkmQ1poI6/ltvRVoHIA1hjyJHD0R5YkBDFGdpqbmTKpxuH+EGQRZwKhCpUoqRrj+jPnolyE0qYbEOW+7oFTKSUFmbLfqHsiIKES1l1H8EAMzB74OgG3bWbB85oKVs8MyF/JeqVTUStuOFU/FYxnXcSw0EPhBsVBCYCYUIOoHWQtCjLa+CkGzqRhVILI8AzMzclzoi9Yuuv+FA6EfArAQQhCBBgZqm9YMAMDjowDH4TbRRsQ152zd3/oyqoVMnA9mbmxqbGlt7u8dMtHZMZB+OQh9093etmhGZxAEBjCRigOD1iGARFMJF6jwRY4k5pr4XX1y9UhbJOQBEDN45cCgISFTLW6DjEdSqdbGaFPKlwCICKOIPQSqxCNUOo7RrFU0c20Q2BLCtYUgYYzWWgcqVIpIABKBH5w+v7vJEeBLo9h2BQMbZRh4Wlf72J5OTo7jiCkq9UBPAmYN03EfENEYY0mrvbN565adrAyiIUGsMFBm0ezW5sZUkBshQawNMwMhoGYGViaysDASkKjRABNWYxEpspYhVA06FUsDEAhg1n6gfeIKO0AAIBRQF/0d9a4yV9U1rhlYK0dSKu6GDAMjud7jhXyuLC1qyiS6WpONSbtUCH1jPNCzupu621t6jpchABGHUKEODYLp7O6sRycKxJ3IJWBCfN0YOXrSmTmJ3hjVmTF7hoandGCifUx7AYFZNLcz5sqwELlAAAmMMgQsJVq2LUgwsGIIldbGACBRxCRr55iqAbBVNQGj4KGaSoyGESIDkiDUhgGpNuTI+BRpF4BotGE2CdeWTrp3MHv301sfeW7fpr3H+oZyoc8kOB5z53clLzlnwXveurKzIZUveA2ZzMyupt2H9oeBilEMlDKhkShrQEdjp2o466R2j3FwndzWMYl+Oa7MmjMDgU2okNmAUV5oA83pakajAAFQaBUChKmYY9DuHcr3nOgbyfuWFB3NqenTWhobUsSqXPJ9XwkiEFA9S1Q1KVQcRwARjYKxSSijgAVrTZLyHrtSAAEBVPY3RkDNJLTWAkwqGUOSr/X03f7Qk/c9uvNAb86AJRy2Rdx1CRB9pV/amX96+xO/u3fzNz7ztvWruy0TdrWnfQhCL0Qko4wKVDwRnz6zGyYj4altSbXtEUYTYtSmpe62kzoRAAFgwbw5DsgwDCPhJQy1JbirOa3DkBFABwkHA0rc9cKe2x/e/MrOoydyng5IECYd2dneuHxxx/lnzz9v9bwZzZnALxc8n4xAIkTDjEgEzFzxkjEZNAy9Wa81Y0GonJizadfx2x595Xt/+bZiPs9CgLQICJkVoIXQkIz7SE9sPXjzfS8+/vTBwULgOk4ymQAyDBBqDkPD2gtMYEvLjSUO9Bbf/39+ets3P3HluuXTOzIIRgeajQm18sKgpauxc1oHVJTWUzEQcVWiQwAcNSqd3Pg0KdIAMGvu7EQyFvpah4aBdKhiMdHamFBK61CnYtbeE8W///kdj75wQLDlOLG4bZGrNYBWYv/R4vaDu2+/f+f0abFL1i269pLlK+fOsIC9YsnTGtBEtiXGSvSTNMZxEv/625s/cvWFK7vSloN/fGp7CORaEFq2sKxQaxLCsmTatrPl4Pbn9tx497PPv3ikrCjuxlJpm1lpUEobpYwbc1rbus5cOX39qo4ZactgEITm+GC+sy1pVDCjq8kBS4cMjDrkIAxnzJjW0NBojI5s1JMidBLoJmEd4yS5icUYNsYggjGmtb013ZzpPzaoQoUklNItzU5zOq51mIiJ57cdf89X/+uE0SmII/ol39c+MgjXsmM2uS7GXIFg9Q3qn9/y0s13vfKW02dcc9GKC0+f19KcAqVDX2mNApgESjtVHB5x48I31rM7e9bMX2UU9RwfXDWvC9h6ZtteJxGfM71ZszrRP/L81v13bNi6becJwU4skUqDUWwMK1SglIo3Ns2Yt3jmjDmxZNIi3p3FjmZr9WxhcwiWVQq1ClVna0Pccoxmo4wOtALV1d1ujImOzgMAVeLmuRqLW0/IVTKs4xZT8uhJUUYAZQIpnFqgX0try5wFcw/3HAtCYwlQmpNJO5lwNARSykCVPvjOM2Z1TkvEbMcSoVInRso7D/Zu2dO77+Cgz5yOZSxBZIdp1zEKHti478GNuxdNbzrn9Hnnrpo7f3ZrIh0jY04MeJu37LnqnCUpklLg0EAOAY1hYhrIFsGxfnPvS3c/u3f+tCalzVA2KPjate1UKo1GK61BMLAOfZNIZJYuXDxz7gI7nvYC5ZdVmc3gsHntYGHZTHHtWa1NVokIlWM1p5PJhO0FRofGKK1BrTlzlRAC0AiK7EpGayWIJnW11Ax8td9HzaRTmfjqi2YjhbNn1547brl9x2vb/SBYuHiJXyqjEGE5JNsyBpoz6Zhjq1CVQ163ZuHF5yxn5QObynlsksbAcNF/YUfvHY9seuC53X2FIOkkHBuQIJ2MAcj9x9X2O7b86o4tTWk3GXeQTf9I0bV5/bnLDOKxvuLsrgbBAjFcOLN145a9HOjT5nff/uzeQ8OB0GBZViZjs2GlA0QC1p5v0onEosULZi1cmoxnPN8vlYsMhIgCUcYEoLvjaOnXTw587KLuVqeojUnHYqmkU+ovqkD7nk44ye2v7vrsJ/7iyKHDjc0N519wwXve/+5UOhUqJcXrMutRiq6n9slLtE0SiX/91r/8+Ie/PjJ8woAPIODOu1LQmognSoWsceOKg4ZM3LJk4AMILiqTz+YwCqOvyBEBsBGEF63ovnjF7C0He2965NX7ntjWM5iLYyoeQwEckzJlS0bjKy6OhBYaVvHTljV3trmH+wo7Dx77y4+cy6yKvv/ei1fu3LXXy5UuXrvg/968QRBLgRqU0YiArHUQqlQsvXjR4nkLlqbSaV+FBa8IgAxkDCAwEgEwQhBPJo6NhLc8dfzj66fFORt37IaU29tbKBV9E4Qxy/7JL29kKEZi5823/OnH1//yhz/+9gUXXqjCQEjxuttjdNgkEjbMuKqjcggwMwshvvqFv7/+P/7Hpdily5eevWaW4+L+3uHHN752uH8wjulyUFSgMimHQBkDAgAQScpq5LjRrMiQJSxhIaMR7K9d3LV2zeKvfeqd92x89ZZ7Nu3Y14/GMmgCDhEQCWxiYYtiuXzB2jluU8Pjdz3xluVz161ZWBopKoZZHfFvf+HdNz300nvfce7Hrj7z+lufTiUSbICYQ8WOnVi4dOWixatTmYznl7OlArMGREuiQGlLB0lEigwbxRwmYmLviXDjtqHLVroCqLUlvX3ncS9XLoWhVvkrV897y/KZ8Zi168jIo89s375997uu+tDvbv3Z5VdeFapAiCkP6Ecw1vNoHHettitqpaWUN/7qxp/+x/+k3cxn3n/WX31gXUoCqyAAc+g9F/zoN3/63UOviFSGQbU1JiBUyGHl+EoUZIEImhOJpGW5/UO5Q4cGDxwdOto7nC2XLUGZVENzY/o9l53+5IsHH3t+uzGGJAKANppVeLwQrJqVvu7yNfm+3NmrZ15x8SL2Ai2kYIdDv6Eh+ePbN3Z0tn71o1du2qe37t0ft4Tyw66u6bPnLvF9f8vLT2ezQ1Ki5xUNGz8IS4Wca8USqcbWtmndM2a3dHbG40nf97VWlmM/u6u0el5yZjO2taZCZrus25LmW3/+nivOmi8sQQwGxd6rz/7Sv//xqdd6v/DJv164cfHMWbO1AUlTWv1hgtRRNZ6N1SaFECf6+r77j/+XwX7/VSu+9pFLsyMnBoxhBsOmI4E/+sp7uzub/u2GjQ7hotmtrBUbAYaj/QAJWWs3Gd++v+/6Gzc8/uK2fKDjmUxzU0s6nTneO3joyBECm8HvbGvJtCQPHzvulTwATshEU0P6tLmZb//FVU0O571id0caQ+NpjcKQEQHHWhozS+d23blhy7IlSxYuXDNzyVlHD+3dvnVzb//RXfu2CsnzF83qnNuw6fktMcsp+6VVq5e/89orT/T2HTl6Ytdre5967N6yCpcuPX352rdY5FigR8q05WBpTlvjad1tChTL4k++/uELlrUP5wraszRrZDV7WvL6r1133d/+avOR/h99/z9/9PN/B62quZ6m8BnWSLjOXjqGurU2liVv+OXv9hzZv2bWrC+8+9ww35eKxTQbibpQLHshW15+9aLZvnmiq6lh6ZwOX/lAhIwVd7HgZNx9cd/QNZ/7UfeiZV/61v8557y1s2fNampqRIQrLrw6e6I/nkgUPHIs65Y7f6NAvbZlx0svvnLH7fc0xeUN3/1sK+XzpbKUlhcEyCSIgIkjg4cUZ6ye/5s/PrV3sOxrNMCvbn7J94cuuXL9Ve+8bM0ZqxYsWPjxD3/uxWdfsS0HgI709L7nfe+ePnM6ACildu/cc/+9j/7nj/5rwwP96y9/l2HWgDt7sv5iZ/HMjJQEAJmkzOY8ZUTKRuHENQhmM6c79cWPXfq5791y1+0Pfv7Ln5k7b341Tqxq7x4H9EQT6hh3LYOUwvfL995+vwXi2kuWTG92nnyt53d/ei6f47esmXHd+jW2CkDQ/qODHocz2htaG5Na+wRIUT5FZFBoZ2I33nHPjIULXtz8aN3qwW1btz7/7CuuHQsD37WsA0cPHj1y9JIr169Ysfz9H37vZz73ibeseevtDz392XeuhUIZmQVGRqeq7ksQBuGKhbP7Rx7Ytn8knk4dPLC3P9v7s1/88BN/9qGozrHe43+68/6USLA2cTt2dKDv9zfd/sUvf05p4zr2kqWLlyxdvO6CMy859+q+Y0faOroNh/0jZigbdHekWhpjvf3DR3uHF3ckCew9/dnbHn5qZ8/gW1bO/cA7zrrqgpU33fn8I1t33X3HfV/8279iNlDZmCYx41GNF9cu1dcwbBBx9/Y9e7bu7840vOO8ZU9t3nfNl/7riRcOvbbvxOd/fNvn//VObQuBVv9I2QBO72pOxuOaLYwsasxoDIWGVdDbP7Ri+So2XCqVqq5+6OzsbG1tMyFYFDMhNqYbZs2eCQCeH5S87IKF89esOmPPnkNCWGwMGAbmKPoQmYkNAYZhOKezKe64m7f3ODF7eLCvJZl5+zuuYGYVhgDQ0tI8Z850XykpbESSIOYvmC2llFJoY/wg8D1/xpwZqcaU7xUjY2oxMNmSak0nOlsSZdC9w0UnHnv1wMA7/vqGf73pqeNHC9//zwc/87Vfp9Lu2966EoGe3vAsj4kyrUU4jcYujTsLXktzMIbGX9u2oz8YXrSgc2ZXw4m+4fdddvrj//VXT/38L756zWW/f/r5H9/6nN3Q1D+UFyBndbdZjmWIGNFEx9MMs1GgzPT2hi1btyFhPB6XxIEfDPYPscGPf+YDBkJL2l4YXvf+d8czqUOHDxeLOYGOCVXvQH8qkUDQVD1GTMzAGsAwAbMJfD+TsNoaU9v39LBmBs6Vci8+/6JhLnn+8HCuXCj93T/+bVNzkwARlIPLLl5//vnrSiUPQAsix7Yd1+k5cGRkOJvINGrWBKgBPTBxV3Z2pBTooWzBU9ZXfnDnwEjhxm9/+rEbvnTnT7+0cEZzKZtdu2Jmh5Xes23P0MBAlZAj1xHWTrmN3wyrlcZQfvRh9659CoLFs9pVEFx49vwrLlpRLgTA/LefuOS5rYd+9Ifn3vO2c8qBFoCzOpuiGJ8q/2FgBALleVe9ZclPv/bz9137KTDB7n0HhgezXqHMSrsx17JEIci6rrztlrtv+NUtlrTIosZUgqTcfmD7tz/06TAsE1IlLgsNMbJGCIxFIgiV5QbNTc6Wg0O+7xNKAvGx9326c9o0pbQOVBAEjpvUofbKZYG0a9vuc0+/lCUkE7GWluaurq6FS+Y9/dgzMTvdkMlEYTdSCFeCQJjd0QxgCgHc+uBLGw/s+8ZHrr7motMGhwaXLkifvvw6rxC2tTVM68jsPTF0+PDR5paWsW6XMdxjogo+KnjX4O492gcgpjUnLSEMQ7HoC2mV2aQS1ifee95Hvn3D7+56ueSRA7KjKa2CsKadMCIwGcKir9Yunf7nV6x78rlHZrY1n93Z1LWqvbOpqaG5wUnEY3EHBYDhUtn3csVSrpAP1XDBP9J3/LNXXbPutJnFckiCOMoboVjlgnJ/rmfngb2HjyU7mi666vzGVBK435LsOjFXurPmLkOwMo5jW5aQFhPajiVIsDGeVw78MPT9YrGwf9fA1lcO3f2Hx6WgM85eJy3b9xUDJF3I2AJ00N3aQGDtOpLb8Oy+zljr+69am88WECxV9kc8bQE3OG5rU3LL4WNRjDobrnGEej4M1ZCwGsTjNZfIFprL5wFMIu4wEApBZJEAB2RQLF92ztKzZi+67YFNSTeWdhKZuKtKPipfh2zA9kNlAs1GkwAp+BufuBidq1IxJAQwGtkEBgwjIzKQJGk5AmMOOKmevUdefXXXVz5yMQalfKFogIANMXIpzB0d6tl2+Nmnn+8bGJq7atHqZXNTzYmYE2tM4KxGOtjQqJm7u2bOXbAi8P1q3AaDGR27IIp8OWwMQJQWzgCgUlpK6ftmWhPGE6hAtLU1pDH+ypYDfUPFT1931pyO1PBwXkrBDDaADjVJJW3hQTk7NBLRJjBXQ/SwjrpfN8ixYoQ3WIk8YcLIo0xgjHSTh47lm9LJfceGS165Iekk4qLkB+zzzld3hRhvbe/wC2WUBGQEsaRSPBHzYihtBBAeh/FY0nZdIaRhGPHUwLGRHfv7n962Zyhb+PS7LijmR/xQSSEgOjafDwZ39L7w+PObXt7SPqvrw599/7xV07VFYLRjWxCUz5pt7+hJd3bPeenpR9vbp7OwTRhg5AmIzotVoukqmERFVHLdMgoUghw0K2c1WrHAsNXR0pR23SAUMcc2KAbzJuZYfugJkKAV6hCMFfns/SCosoNR8a0eyKmAHqO5xN04A/mBoehsIAJojifTdz2z94vf/G3BN5l42rCJubYbjxsVjGRDIVs23PfIirVnOJk0s5IWCUFSYhCUyp4dT5Abt+9+dMvTOw4ECpWm0OdisazYdLY1XXTO0mvXr0raulguCctiZoUqFU/tevGVe/7nrlCr9Ze/ddV5y5PdGV8IrdkVbDSYQC+a7p4zzx0ZXrXh8XtffnbDGedfLsDWOozOwFSdtVhxDyPUibZMKBBZK9PeyMtmySAwriOSCce2pa8tgeonNz/28qa9P/vGBzozlg61JgBgxaoceADkJmJQtVVU0eNqW5PzaKhjJpXZb29rAOD+bBGFJVFoAMuioYL3nevvSCUzf/ups+98YMuW/YNCxC2gQFHBZ3Ji3V0zn7jn0aXnn2vHXccVrmNJCzkwoYIgpLjGt1206qwzlxwbyOfKZUtaTenUzO7W6e0pi8J8tlgsGwJEgxpNIhE/vq/vvjseXLT2tLXnr063pDhmKYFCCKMVM5cD34k5LPSla5vzPg0OnPnyy08YMmvPXm/Zjuf5zBUX2ajkBVzFunKczAjSYfmKNS1JW5XLAAyGiKQoFwtvPWv66gXnf/d/7v7+L+7+6dffVwiygqVEUfRVPle0wWltbQYAqKaurZbaCQyUtRCFyTwslZvmzJtNYO0/lvUZgYC1cWLWM1t7eo73Xv/1D37o6resWdz1gb/5bckLy0HggvZCnc+VGqZ1W6ljGx54fNm558czqURcxWOWtjhAHUNCK7Qdmt/VuGJ+u0AGAGXQD4LSyEh0WpGiRLsIRMLLll/Z+PI1n3zv3KXTy+ViyAaRCMkgGEBAGXgmk4hblg2m9O4LW2JyjQqLm7Zsyg5nl68+u7VjBiJqFZooS2fl/FpEU0xIUpBm9oqlK05vWjPTKpXL0VHGgqfy+dKCmS0/+Ltru9qbeo4MPPTcphPD+YxDShtLiuP9xSN9Iy2pTGdnF0x2YKvmi6k/dF8/F5XP0Z3LVixLi/Rru48O5YpNrvDDELUeHMgKUnOmpbNHjk5vdFsa3N6hwnC23JmS2guUrwolv3P+4hP54uaNT3ctPK1lRnejJo5rLZCFkp4s2zySKwYqBKockSNgBCHZMKuI4JQOUEPghxe8bZ2btHKlgkCySBqgyEEOKBhFsRg0ZlIWyVLIFobvWpdoa7vov+9q2LDhyT/96daZs2bOnXtaa2unG0+SkFGMh0AiZAKh2BS8IC7Da89tvnBhzPNKiMCGSdjHjg7kgtKcrpaUa/v54oI5rXc+GSpPS1d6WluOu7vnRG9xZOXSFdM6O6qpGserhVGRkYWuHuV6k0gkDi9evmTu/Om7d+198dX97zhnYa5QUoo629O+4UN9hZUzmhwpGxsSu4717d11pGv1nNA3yghloBjqdNeCgb1bera+TIrlzBmIFgojJPpBIAOyihgTjogLA5qAgZFBA0eJCIzROmbZliOLRGS4VC4TCY7CeSNqQEQkxTiS8+bNaybQwrETjpMr5tctdhZ3n/fgmTN+f88jz2/bs/PgrgaroaO1vbG5PZbJSCkIQKHLxmTidO7KWZetbJ7RKn2vKKK4HmIA3LvtKILV1pCyBRFxz/H+xmQsk44ZHQKhtOQzmw8EoFesWhpPxsLQjxIB1eNbA/N1XguBiFqrVCp18aXrNu187baHNl985kIBplQOVizqWtrddfvDW961bplLfkdbOtjOG5/bdvqCDhCsADQJIywMg0zXHFTlwd1bTWFYLFnqigRhKKUUvok5JlSKmKI8UhwlsGEQzMYoadu7D+Ve3XfoHesWqSgxEyIDGgAAAsEMSIi+Z4Zzpemts0XcfebJ7S9tP/DlP7vCK440u/ixCzreceaHN+09/uSLO17aum//0YF9fUcC1oIw05BevmDRBafPOW9V5/x2m7hULqIgZCTN7MSd/bsP79h22ALZ2hxzHfvISPH+x7a+45JlmYydHQoSrrVvsPD4swdjkFl/2QUwhvtPUioelkibmwJrAoD3vP/qX/7sxkde3PXClv3nLZ81VCw3CPn9v3v/NZ/74a8eXPpn7zgjHRcGaN+BE7u27OuaO7NAeUuCtDFG2g+KzTNm+zr0jhw4MNKvl63oXDBDsasUqZCVCm0tpVX3LiBEAyCMCdn5zPd+IQS9++JV5XI5Sj2BhBWF01DgaweprP1ikF8wqxXKvhVP/t+bn1y3dslbVnaXil7ZyycQ1i9rvHzNBYXg/MF8mCv7QRi6KJrSicaM7YAJA68U+sgokMBAdLBF+/TMI68M5coKwHaJHecf/uUGy6W/+tD5paKvCeOJ9C03Pbanb3jh3OkXX3Zh5BiZCF7tLwGYKOZqUuMeABCR1uHqtasvvfz8gSD/g5ufLgrLsa1i2T9n2cwffe2DrAqsWaAwEKIUm1/Yns968bhj2dK1MNHU0NbWkRAyGUs0TJvRPGvO0e1bdz62sX/fIRMGWulQKaM0GODKUWaM3ItuMvH8zgOv9Bz91LVvJdTIXHmHAjASAFI5Gx4/MLh369Ejr/Vcc+Zps1Lp3gP9q+a0zW5vv+ORV2zLQWSQtiar4KmRXFEH5eYkL5wWXz6zYV53ImMHQSGXKxQ8pQVES0oja6M817E3Pb2190C/jLsGlGU5ulia25H4zXc/0piyy4HKJONbDw7d/KfNAPzBj7+3sak5Sqs5lqijtC8YvVvj9dP7IEZhh/jXX/2rtnjjxi1HfnnbM5nWZgM8MjxyzdmL33f+mqBUkJIYwoUr5rd1ZJ577Ll4Ih6LyUTSTjSmks1tjmtbMTcESM+YNe/cdW1zZ+VOnDi0bYcql8EwGzBsoBLVSYhk2AjbeW1fb4wSZ61aiJIUkGZgJIOCUWoNuaFCvr8weGTg+I4D57cmiod6B45nEwjT2lp27z/uh4xCICIRkSQpJQqhNHiBKvuh56sQkEWEMERaMQGABims3oN9D9z62GmrF2baU2UoK60Rw7/5zOULpzcWi6FrxXyMfefH9xweLK1auvCTf/7xyDcy1i0F1QirKr2ORXUSumZmQUKpcNXaVX/193/usf/Tm57+wwMvNzY2A6hcOe+X8gACBQKgdOGaD11WzA/veGVbe3tTKuOmM7FYHERCYjxmTKCVMtJqmtl12hkrZy2YJ4nAQC0DYUWDBUQSIC1JMjB824MvHhoMMs3NDY1pQYK1IWahNRiPVVGXC+XcsJfLxWRMon3TQ1te2XsolbAEYaRocy26DKoOn8phpCg4r3I+lBmLnhop+P393s3/80BbV9eai5aV/DyDZu1joLODuZLv2ULEGzP/cP2dT750yLH4W//3HzINqQmMFyv59OvAlDBqEa2HeIwZjzFKCKa/9OUvvPrSjjvvfPArP7h3KJf/2OWrVVAql8psAhAMQEGgWrtaPvS56/54w32xZGLG4rknYESiKTNyOpGNjBkWCTCKOR53ySEgImIC1BVOhQiAUpa9cP35q2+779V/+PU9v7j16QvXzrt03WkXn70wE8diNquVQgMQahth9pw5R1Hcuu3QC7c8veXY0Qbb+vC7LzSsjTZR+hDmSv5BgmpuCmBkE1EeExgjiqWwWPCNkQ/e/hgL9+wrzxnOloOAGTBQYRBoNDqVcBU73/zhnX+4Z3vZ+P/wrS9feNH5WmshRJ1/alSEq89NKicGVNfTch0DQQCQlv2LG35UuvbP7nvo4X+4/v7ntuz/6NvPmtfV1JRujLspAhAkQqU6ZrV86C/ec/8dj5w4bLd0TrNs6ZRKQZOjZ7S1NrpCohOTrgO2ZMsSRFGmL40ATJXkSggUBmpWs7zh3z5x9+ObH9y4/a4N236/Ycs5i7s//5EL37pyTtpVsdlWa0d6pKhu2bDt+rufHSyUFzS0fPzqdR9++5kL57UWC1khqMr3AZmBwVQxB4jCyaOoSCz7plBmj+2XNm4zdvqM85YOFULFAlkCaJSum3ZPFEovPt/zyz88tWHTUQ3wN1/73N/8/eeVNrKyB75OEB1qHUahTePIeeyHCtbKaEmiXC799Re+esN/3VSEoNVOL5rVNqOr6dDR/LY9xz96xfLvf/nawWzWsW0v5722eV8806QUe8VS4PteKUilkmSh49gxBxIJy4nJeNyOxS0gjgJ4gYgBBACBNKwtaceTiaJvtu07/Iubn7zjsa0lUJesWXLZ2jnpjOwbKt/+2CvP7t21uGXW5z9w0eXnLOpsz2ilyn4QxRNWwrWiI8asybDSmgVUTukiEoAxNJwPCj71nhg5dizb2tXllUthaJpS7o9+f8/jW/etWTBjXnfL7gNHduzvy4PflGz65j9//TOf+4TWuiJxcs24MQlulZ9OmuN/kq0yysKGiPff+8AP/+X6l17cnvVyBoJWakem91+56F/+9upctoQARhsVQHakWC4FvhcGgVbGOI6wbWlb5NjCtshyKBazpCUqmWMwyhqIAEhMlXBMYwAplYwx4JOben5+x5NPPL97QHkAoQHVZKU+eumaz73/wpnTUsWyFwYaBCGJmp6NlaVJgKBDTiRcP18CihIFICKGoekfCQeGda5oyoZK5bJmNgoaE/H/+uPdz712JDB+CYYBnKZY41svPu+r//A3q89YHaFcW+sAo4eaJw1bjJyzbyD/GhExszbm8qsuu/yqS7du2br11e25bPFPf3x4w2PPkXCYEYwmMkIwCJ1KgWuTHzjKAJImlEQoLONYUZJQKSSZiLYqJjauctUodWMkOJtsoYDE61ZPO3fNh/YdHt6yq2doxGtKOcuWTl/UkQ694kiuREhCkGZmrWux4qa6E8ZT8ade2/vStkNf+uRlQS4HLJhDQAoNl3xTKIcjgSj6WgUUGGRjLKkZ7ZIpXXT+uvPWn9PW3rzm9FUrV64EAF8pW4jJguimDKubykw6zh8znocIBKUUCbFsxfJlK5YDwPGjvX967BEAZXTIRkdCk20L2xLKhpgRyghjDBAKgUKwJaQQwoDmKDYfwWgwxiADRSdDq60TCiSWwGComC8DeXO6kkvmnA6EoFXZD/IlD0AK0EYpA1oIdC3Hch1GMAyIkphLnl/MF89Yveg3d238s2/c/PN/en+YyxuWCOyH4PnaU+z5Yb5M2RJoNjZxzAJBbgDhuevO/urX/iYau9aKgW0pgCcB9CSBuLLOAlLvCI+QHc2zghiFTdZObWCkCGltVBgKKQr5kgbNrMGEUS5wQgGAQCxtEog2oAEBFV1bA5KONn8EAiSDJDgeTxAKYwxAQEajQaXZV9porbVBFJHluFQsFwveqBsDUQJalnBiCILyJbP16PCL2zdv23F4YKjkxqwzl8+78oKVbY1uUCr95z99ev2Hv/N/fnjXd794dW54CAjDAIMQ/FD7Cj1f5XwwDBJN3EUkywK3UCoopZTSliWJEGCSQ4YTHa3jga6bjfp7xj9nXAhw7R2ARCiEkFIGSgFoFIjMyAZrfJ8BuJLhWqAxkR5dOc2JiBKYjQE75oTCefDFXc9s2tnXn9VGNWdic7taFsxqn97Z2JZOpJI2aENoAgDNlTcRCSEc20WiUqCPD+Zf2XHwqZf3Pvbc9j3HBzzAac1dMdfVpnTTE3f94DeP/vtXrl2/diGq4s++84m3ffwH685YdPnps0a8QFOoAEMDoTZlhYaBUXgGShqBBIFArrwrlIig7pVo9WXs6aDRWIM6oKOMLZPz6HqOMcpDxtdFAADthwBgExEwsAYWNTGyNtEmMiWYyOCOTIyMitGJWwcG/a9874YHXt4WF4m2aZ0awqHB/cVy1kDQaiXmdTUvnNOxZG73vO7W9rZMKpVwbFsDD+WK+w7ue3XX4c3bD2zdc2QkCBozzWvPOeuTF513xllrli5btGHDxhWrlh/rOfK5z375g1//1a3f+9S5K2eunN3+8evO/c5Pbr3gl38vODTMDAggGEzACAii4tYSSBIBdKjHj3ayUq+OTDA7g6zpTvU31FtDAODkrwaNps/3SgBs25Iw2iXIGFNx7ETNV1wMQNHOJ1ylAofQtmioyJ/4659uPjzy37/8WUdXE5G48MJze4+f6D3ad+BAzyOPPPnisy8+sWP494/t8KAogG2QDlgIVAbWYDWmGpcvX/jxL1zVOq3tgx+4tqWtOepYqVwaHBlpbWuZ0T3twcduO3PVZV/9wa33/Pjz5Hsfv/b82/707KMvbb/s9AVGlRARhRAIJLQ0wjBKNLYgKUiADsIQqo6CWtzLpCDUwcXVfHFVoCdjFG+wMABAoAwAxhwHQDBKZSIOISLPMFZdRoZBG5NJZ/7zxkfXLpu/cvF0ssUPf3Lnq0f7b7/nhiuuvPTY0WN333vf+vUXTu/unN7dvfbM1eevP+exDU9ffdXlRw4dPnS49/ChI4d7jg72jaTT6Rlzuhcumrdw8fy2lmbN5tFHN7S0NfthABpIUE/PEUuQa8lQhfncsPb87QO5Pz7+8qeuPL0r7l62buVLW3dfceYCwygECclI6BIyakNgCUrGKG6jBgz8AKbgvFOX8YRf4dGRg3I8eKO+xfFBIWMehAAAXhACQMy1lYGSFxjDgtCxLduSgqIprkRzWTbtOXTirg1b33b5WcThzoN9v7l3wwXnXnTFlZf65VJTc1M2m+sb6G9ubNTGA4ZUPJmwHEfa8+cvmD9/weRzzXz44OGYEwcAx7LBAgA4cqi3q2saIlrSuv3me48NHElS4wPPvPaRy88QfmHd6bOf33IQDVtgbGAbUUpIWAJZC0m2RQ0xSrqSAb2yB9XIi0nFsInCxkRdW0Zy1NgLPPYD13GMUW9jrY3oU+iHBEJKK5dX2byHZCOxq8JkHGxHAAqDWiChNjHXefjpF+Jxe1rSYtZ3Pbq5pMXml19+/tkXzzz7DACYOXvO/gNH2lpahZAAYAOcufb0inJn2LCOlCwEAwCEkoFJCAOQbkgPDY0MDQ8PDw8d6z3x+OPPEYk777q/VPKfum9Dg9NmjDl4JN+fK3ek5crZnU1u3CsXHcsIMjZB3EKMoWujsMgSnErIhGshaM8PqiPmuh1nksPf1Q+T8PExGWjgDS8QwOpC8MuBAAmGsgXOlgFQC6LQMYwqSeDYXHn7DTOgfHF7z9yuNhuCkbLZuGm3Q4lywf/X7/7oO//+Dc/zAMTLL20xoa+NEVK6MRcUe2U/nUnZtu04jhAWAjAYNqZc9orFIJfLbt+xb2h4cN+efSPZXBAGiJBMJRPx2Ow53clE8vjBwxse2ZR0E4VSfrDoTWtqyaRgdXNHELB0LMfWrg1JbSxCDWhLKQmb43YyRgCglJoI31h/FcN4Nj0ep3Gxd+Mv1y6eHGuldaFcJpAaRc7zi75BkERg2BCREExoLMuKXgIeKt0/WFg4sxsJ+3Peod4REirpJB7+05PK+qe5c2cBkOs4Kiik0+m2aR2tVkvMjjm2Y9u2JS0iBGDNHBmyhbBSadHUnHRjbv9Q36oVK2od27ptx44dO9/z7qsBIGXbGx7+oMVJASgIpG2VtIIQ0QKbdcyRcYeNRttiRrCIBZp0TCXjgqtAjwuLGRfoPBaS8ewFsXIqayocJ0od4wszE5EKw1K5JEEwOyUPglBGJ7sNgiCDpAgFkQJCZK2ZldG2Q0DS80PfN0hYCrzWjqbr/+P707s7H374qVwu+653XVVrpVTyXNeGKBknCYh4mQAAqKU46p4+TdoCAFQYKhUiYWtry4anBoMgBIAzzzlz9eolmzcdmNOebG1MhwosEkxsjHGkjMVMMjREWpmAo7eIsEnEIB6TCgxXpI5xFD0RrUjA5rrck5G1jplZnpRXjBcGpypaaxNoAqGMyQc6H1Sy/ykAiYyoJYEQFHOYmS3glCtLng8AjoW2LTDArB741Ac/Nr27k4GPHDm6aNFcrbVSIVRCHkwlZAKJQQ/0DRw6ePTQwSPHT5zIZfOadTKZaG1taWpqKC+c19nV4cbiANDRHmtuagzDMJGIA1jXXnf1Ey99ddniM9qbMl65HKVYiHwhyYSDzJaEUFvGkE0WUdjSgNJCBq3Vyd5IVofWyax38tT4w+vDjYAIQhssB1AOQRuDQAbAAgNgiFggWIQCwCIzd8a0I8f6dRi0NybmdjXtf7VnRvu0T//FJ7SO8mebrq5pQoiau1Nr/ermLc888+JzT7/y6padR3sOF4pZBOWAEEAGtA9hCEqBdjHZ3tk9e+6MZSsWrz1rTV/f0KYXNrd3tO7es/f3t/wxTfzRt68lvwBA0UszEBCBpYBU0nYsGWrLMEkbiITlCCCOArLrIJpciZsCrkoFxPH5OibT+U4BaMTIM4JagwrRD1lpNkzGkE0hAlsCHakcx0o4wihz3toF/3nDo/kAHEmffd+Fj2/+aaZpKSFFYsbcBdNnzOj0/eLePQdfeO6lxx954qmNL/QcOSZBzW1qWbZw1jXvfsu8me1dHenGTMKxBQL7vh7JFfoH8wePDmzfe3jrvt03Pff0f1z/EwQhQQCwD353uukXf/+xs5d0lcslIYTmavAdgmEAQbG4FTPCAAKC0YrYRiQCAqoXw6aCqJYxpCZ4jKa3ZMbRw0ITQ8KiXpyKHCKEkJZg4EIQelp7gQkVhkqHUjsCCMH2jSPRcSDmUr6kzl819+Y7n9p5aHDl/I71Zy/62Vc+/PUf3bt63lvXnrtm7rzpvSf6f/DPP9u9Y2fPwYMM4azGxreumLvufeuWL+qe3dGYSseBBKgg1EobE71SSLCUHXFLtqFcBCACw4M571j/8OFj/SMjOa2xu7156byOtqRdLhXJsrSJGL4BQjCVcUavQkNmZhSMUghjQAILq+bwe10kJsBeLTWpYxI069yLU3IfRGTDtuM0NqUNhCOFkh9SuQyBIaXZ83VMgkS0yLiWiPtaBSQtiAvxifde4JeKQsbyuZH3vf301Svm3HrfM8++tPvJzS9KaccTzrq5rWe8c/XqJTNmd7Y0xCw0ga/C0Ct6Q0UrZll2zLWs6AAHoQHWfikczgWAfuR1TAmxtLtpxczWyOWvlfJKYankC2EZjYZRYigEaW2gEmlroBrwCEgaUEvqHykpEE1trQBjTBl1UEzOSSbOiJy4HCYj4UkdXZWijZYkZ82b8diTTx/pPbF4zpxA6QCQgUJFxXIYk8KRGCgOjFHGCOkU/GDtabMAsVzMSxK5odzs9uQ/fu6dfhj6niIgp3K4NgiCsOwVs1lQxtg2pdOp4ULw0rajL2w/urunf2TEQ8Dm5sxpczvOP3PeojntYSGnWWpWvta+NmCCKFKyYk8VFGoNyig2gjDMlSHuSEtWwtI1RZEYREAIgTI7dvch0Lz5M6qwVN7yCwCVxPCjcI3CiFHq2bEo1lTwCdhOXqZcPGefv/Z/fnnj7v2HT1+2DMlmjYwgiH1DoSaljNZGaWEYGFkA6lADISEDoBAQemWv5BGRRQaZw8B4WoGhKPaAiVMJdySvv3/Dfbc8+tKJ4WKTm+zuyDQ0pgTK7ft7Hnnm1W/+4u71Zy74969cF3M0qorxsJZ3yaAhptAL/aLPQYA2lgv+/s27Vq0/00hdyZFVebcfsjauJff2DGzd3puRztq3nF6dqCggYsyWOKl8PBHPcR4WnLCxjsG3LnJ7dDIj59all100c1pn7/HBbbt2r1iyKgi1EEyCCClkMECGQRvQxlTTn2E1U1jkTWAhAJm1qWZWRIslI2s24NjixZ29n//OjRqc91923vlnLVg8o70x6UrLAEitIet52/ac2L3/KBpfaqm5EjCJVDPSYxCqcrascmHoefGU++w9G2aftlgFCogsxwYAABO9V8qEhpLJ39372MHhvlUr55959lpmrkTawCj3mOjEGkeJ9SjJui841n40CdD1j67fPJXSba3tH/jke7/5rX99edvuubPmJWMpw0YKsgSS1CQqCXywsvqiVGAIgFEin8pr3MBgbRaj0xwgCI0gC4H+7tPXXHHeqlScQy8IwjD0SkE5Ch/gJOEFS9ouXj09ly8oHXK06Vf8swRAAqAc6JG+EVYYs92tz20r5soz5naXCkUHU5YFDBAFXesgjLty0/ae2+7f7EPw3o9dl0iklAqEEJHXbbJAcgAY85qH+qilyi+194JH2tZJFcXJZmD0iTw8kr1w7eUH9x1addqSt1+2XgeBbZEUEJeQsTEdp4YktqYw0xATojajusbiDDIyiLqZNggaWACjQeHYcccqlbzQmEqEPle9EGgqThw2lYwtXDM7RrFZxMoM9Az07D6UbmgyI4Un7n/4gisuyEzvcFPSzSTjKUdHM2YYlNa2/bG/v+mxrUcWLZnx+DMPpVLx6rRhPdBvqNQf6AQYvxx4wlZZtePXvlcEQdLGNDc1ffffvwFgtu3av2nrltbmVNzCpIsxh23bWBZawnJjCUvKaHOvBGxVI7QBKsEu1dCw6kQikhB+oLP5EoMhQhw9wFB5fRxQ5FSroIxRdlnDbIzRxihVGMwfeXW35UM4kHv6/kenz56ZyDR4HochopSaiEkQCxHqVDr1/Z8/8PTWw0T+t77/j5lMio2KmPiErD6VHp7UnFQFui4sYVJhYxKgq8nAx9S0hKWUuuodl3/mC58sKrXx2S27DhxsaU0LNJYQti1sSzpp66d3b+gvelIIw4bZmDpGQYBR+srKETAEACAGMKjZSGKK8t2NdsdUJz5KQAhRok2s+M8jnw6QYVXyel7bH/jaAnzl2efZqHnzZh/uz9254WW0bLAtgwhAgQ7izQ0/ueOZG/70igf+X37x01dedblSAQlZdVBNguA4FjFxGqI6b3IhTNIesCChtf7Ov33jqivPH8gXbr/7iW379jU3Z2xpXIdsodsbYzv3nHjwidficZuVxio5jDODjTtwU3+our7A2N2m2ot6PZejFHi53mEKOZFK79m+68jho7MXLwbCTYf6tvbnGlqSWiAyGh02Nzb/7r5XfvTLjWUj3/aOy7/5z9/QOhx7LOUNY1Xr55Q+wOjjKRqVqjcCIkohf/7rH64+c9Gx4aHf/vaRzdu2T+9oSCO6dpgSvHZp9x8eein0NRoAbWr4QfXd1qcyqKms6wiVWNGq1oCE6BXK5WwxlnSHenq3vrpnwWnLpGUpDc9vP3ba3BmphgQB2Qyppsaf3f7Md65/JBeYt5y34r9//RMpZRT0WycmvAE0RscRyWZ1MOEEAokePflkTGRMXN0bm1tab7vrt6vXLj5eyP7sN4/+/oGNjR1uV1MyzJfPWDl7076el3ceTFjIyMiAhtFwxDeid69E/wQA8XhMGQCrFQiQGASMnrGK3jzOJJAEokAhgEW54EnbyvUXXnx20+IVpzV0tJX98hHfbDras3LJNBWGcRu1Y337+vu/+9PHTvjeGeuW3XjHbzINGWZGpAoB/C+AjoAaBfHkvKZ6z5iFPOlDicgY097efsd9v7vw0rP7g/wvb934xR/ccaJQlq5Z0tHW3JC58eFXrJio5pKoPHBcz6Jpw+idN3WIY/V0whguUt1RKRoSIQtiIqW0sGxdME/c++iCZfOXrFjgjQzPWjD7iYO9YMtl85rjLvb05T751Rv/+9bnSyp82zUX3XrPjS0tLVGI4US8JpZT5L1U6/+pTBczVmd4qgocuQKMMa0trbff/dvP/sUHPC4++Oye93z5Nzdt2N7S1nTtRatufeTlniHPjcSpGqce2/UqepF/n+vddeMard1ZeRMRM1ci+NmKOaTo0dvvW7Fm2dmXnOeHYffsLqsldd/LO646f9W8+bN/cdemd33xl/e8tCcQ/l98+eO/u+2X6XSqDuUpQXyjQjC9wUUxpvIEp0OF80RYa22EtH/w43//6a//o6U1/tqJE1/413s+8s1fLV66IO+HNz20JZ6JKx1y5dYoMroqAmFFSoYofByr1BpRcvSq9GrjkfRNkd5TefMTAAAKCvKlDfc9dNalZ5997Vv9BDTObp61dPpTew6fKPiLFy/89Dd/+8Uf/XH3QF/3jNaf3/Sf3/qXbwBEuRqZWTPrqrvETER2aj/WJIWZsZr8/Y3tpzjhvO1UDWijLWnt2bP377/y9Xv/+JgBmNWSGi6ahrj90H9/piVmh16IVuW4Q40jRbw4OsJdlV4rgh3WJroqfzOPMjREBEIEwURgy/6Dx8g3LdPbBgaHOVQSOWDnun/63ZG+YsKi/cURF63r3v+2b33vm13dXUoFUUTyuGFGCmFtRPWX6qEYA+sE9N8k0CctY/wODKy1tqQFAL+/5ebv/eO/vbZ7V6PVGGj1jgsX/eQfP5KU6JfKfhBoY5DqzzRFYfqmklO6Eqo+CjRXAcZIN4mGh9Uc9lE1SdrX5WIoLUrabojin//7/p/d+ZJtWX1+/4oli//xW19/5zVvAzChVpImnl+rldc5VcVcO1leMy+PES4wSusNABUbz6jR402XyMM2Rlwx2jCyFHJocPAn1//8Zz/+TWGwkKTYgrnp696++oK1C7vbmmKEoQqCUIHmatcJgNnoijxjokAOjCL4q+9+Q4iycVYMlywQGIjZEKJ0HdtyQ8ATA9mnXtl/070vv/jaUcWcyDif/PMPfeFv/jKdyWgdTipEjV2vU52qql9f44h1DIzIXNv7J9785krtOVTjBtEwAq0dKQHgte3b//kb399w/9Nh2Va63NFqrVoy65xVs1ctnT5nWqtrkQ49ZE3AYCoBZVzXy8qr5tDUDPGVtwIgQ/RiWwQmO9B0uC/76s4jL+048vxrB3cf7o9TUrry3EvO/No/fXnpstMAQCstJJ58b6tnHRPGCNU5eB2g/z/NLpKkb4j5VwAAAABJRU5ErkJggg==",
    "critical": "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",
    "destroyed": "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",
}

def get_face_pixmap(score):
    """Return the correct face QPixmap for the given risk score.
    Faces range from happy (score 0) to destroyed (score 100)."""
    if score <= 20:   key = "clean"
    elif score <= 40: key = "low"
    elif score <= 59: key = "moderate"
    elif score <= 74: key = "high"
    elif score <= 89: key = "critical"
    else:             key = "destroyed"
    data = base64.b64decode(FACE_IMAGES[key])
    px   = QPixmap()
    px.loadFromData(data)
    # Scale to 70x70 maintaining aspect ratio with smooth scaling
    return px.scaled(
        70, 70,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation
    )


# ── Session activity tracker ──────────────────────────────────────────────────
class SessionTracker:
    """Tracks everything that happened during this session.
    Used to generate the 'What Have I Done?' summary popup."""

    def __init__(self):
        # Record when this session started
        self.start_time = datetime.datetime.now()
        # List of (scan_name, timestamp, findings_added_count) tuples
        self.scans_run = []
        # List of (action_verb, item_name, timestamp, succeeded) tuples
        self.actions_taken = []
        # Risk score when the first scan runs (None until then)
        self.score_at_start = None

    def log_scan(self, name, findings_added=0):
        """Record that a scan was run. Capture the starting score if first scan."""
        if self.score_at_start is None:
            self.score_at_start = RISK.score()
        self.scans_run.append((name, datetime.datetime.now(), findings_added))

    def log_action(self, action, name, succeeded=True):
        """Record that the user took an action (removed/disabled something)."""
        self.actions_taken.append((action, name, datetime.datetime.now(), succeeded))

    def build_summary(self):
        """Build a plain English summary string for the popup."""
        now = datetime.datetime.now()
        duration = now - self.start_time
        mins = int(duration.total_seconds() / 60)
        try:
            hostname = subprocess.run(
                ["hostname"], capture_output=True, text=True, timeout=3
            ).stdout.strip() or "Unknown"
        except Exception:
            hostname = "Unknown"
        score_now  = RISK.score()
        score_then = self.score_at_start if self.score_at_start is not None else score_now
        improvement = max(0, score_then - score_now)

        lines = [
            f"SESSION SUMMARY — {now.strftime('%d %B %Y  %H:%M')}",
            f"Hostname: {hostname}",
            f"Session duration: {mins} minute{'s' if mins != 1 else ''}",
            "",
        ]

        if self.scans_run:
            lines.append(f"SCANS YOU RAN ({len(self.scans_run)}):")
            for name, ts, count in self.scans_run:
                lines.append(f"  ✔  {name}  [{ts.strftime('%H:%M')}]"
                              + (f" — {count} issue{'s' if count != 1 else ''} found" if count else " — nothing flagged"))
        else:
            lines.append("No scans run this session yet.")

        lines.append("")

        if self.actions_taken:
            lines.append(f"ACTIONS YOU TOOK ({len(self.actions_taken)}):")
            for action, name, ts, ok in self.actions_taken:
                status = "✔" if ok else "✗ FAILED"
                lines.append(f"  {status}  {action.title()} '{name}'  [{ts.strftime('%H:%M')}]")
        else:
            lines.append("No actions taken this session — nothing has been changed on your system.")

        lines.append("")

        if self.score_at_start is not None:
            lines.append(f"RISK SCORE CHANGE:")
            lines.append(f"  Started at: {score_then}/100")
            lines.append(f"  Now:        {score_now}/100")
            if improvement > 0:
                lines.append(f"  Improved by {improvement} points — good work.")
            elif improvement == 0 and self.actions_taken:
                lines.append(f"  Score unchanged — actions may need a rescan to reflect.")
            else:
                lines.append(f"  No change yet — run a scan and fix some findings.")

        lines.append("")
        outstanding_high = RISK.findings.count("HIGH")
        outstanding_med  = RISK.findings.count("MEDIUM")
        lines.append(f"STILL OUTSTANDING:")
        lines.append(f"  🔴 HIGH priority:   {outstanding_high}")
        lines.append(f"  🟡 MEDIUM priority: {outstanding_med}")
        if outstanding_high == 0 and outstanding_med == 0:
            lines.append("  Nothing critical remaining — nice work.")

        return "\n".join(lines)

# Create a single global session tracker
SESSION = SessionTracker()

# ── Risk score tracker ────────────────────────────────────────────────────────
class RiskTracker:
    """Tracks all the risk findings and calculates an overall score 0-100.
    HIGH findings are worth 20 points, MEDIUM 8, LOW 3, INFO 1."""

    def __init__(self):
        # Simple list — one entry per finding (e.g. "HIGH", "MEDIUM")
        self.findings = []

    def add(self, risk):
        """Add a new finding's risk level to the tracker."""
        self.findings.append(risk)

    def remove_entry(self, risk):
        """Remove one instance of a risk level (when an issue is fixed)."""
        try:
            self.findings.remove(risk)
        except ValueError:
            pass  # Already removed — ignore

    def clear(self):
        """Reset all findings (call before a fresh scan)."""
        self.findings = []

    def score(self):
        """Calculate the current risk score. Capped at 100."""
        # INFO findings are informational only (inventory/status notes), not risk.
        # Counting them inflated score during package inventory scans.
        weights = {"HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        return min(100, sum(weights.get(f, 0) for f in self.findings))

    def label(self):
        """Return a (text, colour) tuple describing the current risk level."""
        s = self.score()
        if s == 0:  return "ALL CLEAR", T["OK"]
        if s < 20:  return "LOW RISK",  T["OK"]
        if s < 50:  return "MODERATE",  T["WARN"]
        if s < 75:  return "HIGH RISK", T["DANGER"]
        return "CRITICAL", T["DANGER"]

# Single global risk tracker — shared by all parts of the app
RISK = RiskTracker()

# Tracks package names the user has chosen to ignore for this session
IGNORE_LIST = set()

# Tracks all undo log entries added during this session
UNDO_LOG = []

# ── Undo log helpers ──────────────────────────────────────────────────────────
# Maps "action command" to its "undo command" for common actions
UNDO_MAP = {
    "apt purge":             "apt install",
    "apt-get purge":         "apt-get install",
    "systemctl disable --now": "systemctl enable --now",
    "systemctl mask":        "systemctl unmask",
    "ufw enable":            "ufw disable",
    "dnf remove":            "dnf install",
}

def make_undo_cmd(cmd):
    """Figure out the reverse command for a given action command.
    Returns the undo command string, or None if we can't reverse it."""
    for trigger, reverse in UNDO_MAP.items():
        if trigger in cmd:
            pkg = cmd.split()[-1]
            return f"{reverse} {pkg}"
    return None

def save_undo_entry(entry):
    """Append one undo entry to the persistent log file on disk.
    Uses append mode so previous entries are never overwritten."""
    try:
        with open(str(UNDO_LOG_FILE), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logging.error(f"Failed to save undo entry: {e}")

def load_undo_log():
    """Load all undo entries from the log file (from previous sessions).
    Returns a list of dicts, oldest first. Bad lines are silently skipped."""
    entries = []
    try:
        if UNDO_LOG_FILE.exists():
            with open(str(UNDO_LOG_FILE)) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass  # Skip corrupted lines
    except Exception as e:
        logging.error(f"Failed to load undo log: {e}")
    return entries

# ── Worker thread classes ─────────────────────────────────────────────────────
# All shell commands run in background threads so the GUI never freezes.
# Qt requires all GUI updates to happen on the main thread, so workers
# emit signals which the main thread handles.

class CommandWorker(QThread):
    """Runs a shell command in a background thread.
    Emits output line by line so the terminal updates as it runs."""

    # Signals — these are like events the main thread listens for
    output_ready = pyqtSignal(str)  # Fired when there is output to display
    error_ready  = pyqtSignal(str)  # Fired when there is error output
    finished_ok  = pyqtSignal()     # Fired when the command completes

    def __init__(self, cmd, sudo=False, timeout=60, env=None, password=None):
        super().__init__()
        self.cmd      = cmd       # List of command parts e.g. ["apt", "purge", "ftp"]
        self.sudo     = sudo      # Whether to prepend "sudo" to the command
        self.timeout  = timeout   # Seconds before giving up
        self.env      = env       # Optional env dict; None = inherit from parent process
        self.password = password  # sudo password for -S mode (bytes or None)

    def run(self):
        """This runs in a background thread — never touch the GUI from here."""
        try:
            if self.sudo and self.password:
                # Pass password via stdin with sudo -S.
                # input= sets stdin to PIPE and writes the bytes then closes it.
                full = ["sudo", "-S"] + self.cmd
                p = subprocess.run(
                    full,
                    input=self.password + b"\n",
                    capture_output=True,
                    timeout=self.timeout,
                    env=self.env,
                )
            else:
                # No password — use DEVNULL for stdin so sudo cannot block waiting
                # for a password on the parent terminal. If credentials are not
                # cached, sudo will fail immediately with a clear error message
                # rather than hanging silently in the background.
                full = (["sudo"] + self.cmd) if self.sudo else self.cmd
                p = subprocess.run(
                    full,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=self.timeout,
                    env=self.env,
                )
            # Decode output — ignore encoding errors in case of binary output
            stdout = p.stdout.decode("utf-8", errors="replace") if p.stdout else ""
            stderr = p.stderr.decode("utf-8", errors="replace") if p.stderr else ""
            # Strip the sudo "Password:" prompt from stderr so it doesn't show in terminal
            if self.password and stderr:
                stderr = "\n".join(
                    l for l in stderr.splitlines()
                    if not l.lower().startswith("[sudo]") and "password" not in l.lower()
                )
            # Emit output to the main thread for display
            if stdout: self.output_ready.emit(stdout)
            # Only treat stderr as an error if the command actually failed.
            # apt and many tools write warnings to stderr even on success.
            if stderr:
                if p.returncode != 0:
                    self.error_ready.emit(stderr)
                else:
                    self.output_ready.emit(stderr)

        except subprocess.TimeoutExpired:
            self.error_ready.emit(f"Command timed out after {self.timeout} seconds.")

        except FileNotFoundError:
            # The command itself doesn't exist on this system
            self.error_ready.emit(f"Command not found: {self.cmd[0]}")

        except Exception as e:
            logging.error(f"CommandWorker error: {e}")
            self.error_ready.emit(str(e))
        finally:
            self.finished_ok.emit()


class HttpWorker(QThread):
    """Fetches CVE vulnerability data from Ubuntu's security API.
    Runs in a background thread to avoid blocking the GUI during network calls."""

    result_ready = pyqtSignal(str, object)  # (package_name, (version, data_or_error))
    finished_ok  = pyqtSignal()
    MAX_ATTEMPTS = 2
    TIMEOUT_SECS = 8

    def __init__(self, packages):
        super().__init__()
        # List of (package_name, installed_version) tuples to check
        self.packages = packages
        self._cancelled = False

    def cancel(self):
        """Request graceful cancellation (checked between package requests)."""
        self._cancelled = True

    def _classify_error(self, exc):
        """Return short error class: timeout / network / error."""
        if isinstance(exc, TimeoutError):
            return "timeout"
        if isinstance(exc, socket.timeout):
            return "timeout"
        if isinstance(exc, urllib.error.URLError):
            reason = getattr(exc, "reason", None)
            if isinstance(reason, socket.timeout):
                return "timeout"
            return "network"
        msg = str(exc).lower()
        if "timed out" in msg or "timeout" in msg:
            return "timeout"
        return "error"

    def run(self):
        """Fetch CVE data for each package with light retries."""
        import ssl
        # Use the system's trusted certificate store for secure connections
        ctx = ssl.create_default_context()

        for name, version in self.packages:
            if self._cancelled:
                break
            err_class = "error"
            err_text = "Unknown error"
            for attempt in range(1, self.MAX_ATTEMPTS + 1):
                if self._cancelled:
                    break
                try:
                    url = (f"https://ubuntu.com/security/cves.json"
                           f"?package={urllib.parse.quote(name)}&limit=5")
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "linux-audit/4.2"}
                    )
                    with urllib.request.urlopen(req, timeout=self.TIMEOUT_SECS, context=ctx) as r:
                        data = json.loads(r.read())
                    if self._cancelled:
                        break
                    self.result_ready.emit(name, (version, data))
                    err_class = None
                    break
                except Exception as e:
                    err_class = self._classify_error(e)
                    err_text = str(e)
                    logging.error(
                        f"CVE fetch {name} (attempt {attempt}/{self.MAX_ATTEMPTS}): {e}"
                    )
                    if attempt < self.MAX_ATTEMPTS:
                        time.sleep(float(attempt))
            if self._cancelled:
                break
            if err_class is not None:
                self.result_ready.emit(
                    name,
                    (version, {"_error": err_class, "_detail": err_text})
                )

        self.finished_ok.emit()


# ── Worker lifecycle manager mixin ────────────────────────────────────────────
class WorkerMixin:
    """Mixin class that adds safe worker thread management to any widget.
    Keeps track of running workers and cleans them up automatically.
    Prevents memory leaks from workers that are never garbage collected."""

    def _init_workers(self):
        """Call this in __init__ to set up the worker tracking set."""
        # Using a set (not a list) so we never have duplicates
        self._workers = set()

    def _start_worker(self, worker):
        """Start a worker thread and register it for cleanup when done."""
        # When the worker finishes, remove it from our tracking set
        worker.finished.connect(lambda: self._workers.discard(worker))
        # Also clean up on any error that causes an unclean exit
        worker.finished.connect(worker.deleteLater)
        self._workers.add(worker)
        worker.start()
        return worker

    def _stop_all_workers(self):
        """Stop all running workers. Call when the widget is closed."""
        for w in list(self._workers):
            if w.isRunning():
                w.quit()    # Ask the thread to stop
                w.wait(500) # Wait up to 500ms for it to stop cleanly
        self._workers.clear()

    @property
    def _any_running(self):
        """True if any workers are still running."""
        return any(w.isRunning() for w in self._workers)


class ArrowSplitterHandle(QSplitterHandle):
    """Custom splitter handle that paints a small arrow cue."""
    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        p.setPen(QColor(T["ACCENT"]))
        font = p.font()
        font.setBold(True)
        font.setPointSize(max(9, fs(-2)))
        p.setFont(font)
        glyph = "⇕" if self.orientation() == Qt.Orientation.Vertical else "⇔"
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, glyph)
        p.end()


class CueSplitter(QSplitter):
    """Splitter with a more visible drag handle and arrow marker."""
    def createHandle(self):
        return ArrowSplitterHandle(self.orientation(), self)


# ── Terminal output panel ─────────────────────────────────────────────────────
class TerminalPanel(QWidget, WorkerMixin):
    """The scrolling text output panel at the bottom of the app.
    Shows raw command output, status messages, and scan results.
    Users can adjust the font size with A+/A- and clear it at any time."""

    def __init__(self):
        super().__init__()
        self._init_workers()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar with title and control buttons — styled via make_style() #terminal_hdr
        hdr = QWidget()
        hdr.setObjectName("terminal_hdr")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(8, 4, 8, 4)
        lbl = QLabel(L("terminal_hdr"))
        lbl.setObjectName("heading")
        hl.addWidget(lbl)
        hl.addStretch()
        # Font size controls — also affects the whole app
        for label, delta in [("A-", -1), ("A+", 1)]:
            b = QPushButton(label)
            b.setObjectName("neutral")
            b.setFixedSize(30, 22)
            b.setToolTip("Adjust text size for the whole app")
            b.clicked.connect(lambda _, d=delta: self._adjust_font(d))
            hl.addWidget(b)
        clr = QPushButton("CLEAR")
        clr.setObjectName("neutral")
        clr.setFixedHeight(22)
        clr.setToolTip("Clear the terminal output")
        clr.clicked.connect(lambda: self.output.clear())
        hl.addWidget(clr)
        layout.addWidget(hdr)

        # The actual text output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Terminal output appears here when scans run...")
        layout.addWidget(self.output)

    def _adjust_font(self, delta):
        """Increase or decrease the global font size by delta pixels.
        Rebuilds the entire stylesheet so all widgets update at once."""
        global BASE_FS
        BASE_FS = max(9, min(22, BASE_FS + delta))
        QApplication.instance().setStyleSheet(make_style())

    def append(self, text, colour=None):
        """Append a line of text to the terminal output.
        colour is an optional hex colour string e.g. '#ff4444'"""
        text = strip_ansi(text)
        if not text.strip():
            return  # Skip blank lines
        cur = self.output.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        fmt = cur.charFormat()
        fmt.setForeground(QColor(colour or T["TEXT_MAIN"]))
        cur.setCharFormat(fmt)
        cur.insertText(text + "\n")
        self.output.setTextCursor(cur)
        self.output.ensureCursorVisible()

    # Convenience methods for common message types
    def append_cmd(self, cmd):
        """Show a command that is about to run — displayed with an arrow."""
        self.append(f"\n▶  {cmd}", T["ACCENT"])

    def append_ok(self, text):
        """Show a success message in green."""
        self.append(f"  ✔  {text}", T["OK"])

    def append_err(self, text):
        """Show an error message in red. Strips ANSI codes first."""
        self.append(f"  ✖  {strip_ansi(text)}", T["DANGER"])

    def append_warn(self, text):
        """Show a warning message in amber."""
        self.append(f"  ⚠  {text}", T["WARN"])

    def append_info(self, text):
        """Show an informational message in the dim colour."""
        self.append(f"  ℹ  {text}", T["TEXT_DIM"])


# ── Risk score + face health panel ───────────────────────────────────────────
class RiskScorePanel(QWidget):
    """The panel at the top showing the Duke Nukem-style health face,
    the risk score progress bar, and the system profile label.
    The face changes as the score improves — instant visual feedback."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(80)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(14)

        # The health indicator face — 70x70 pixels
        self.face_lbl = QLabel()
        self.face_lbl.setFixedSize(70, 70)
        self.face_lbl.setToolTip(
            "System health indicator — the face improves as you fix issues"
        )
        layout.addWidget(self.face_lbl)

        # Right side: labels and progress bar
        mid = QVBoxLayout()
        mid.setSpacing(3)

        # Top row: section title + profile + update age
        top = QHBoxLayout()
        lbl = QLabel(L("risk_label"))
        lbl.setObjectName("heading")
        top.addWidget(lbl)
        top.addStretch()

        self.profile_lbl = QLabel("Detecting profile...")
        self.profile_lbl.setObjectName("status")
        top.addWidget(self.profile_lbl)

        self.update_lbl = QLabel("")
        self.update_lbl.setObjectName("status")
        top.addWidget(self.update_lbl)
        mid.addLayout(top)

        # The score progress bar
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setFormat("0 / 100  —  ALL CLEAR")
        self.bar.setFixedHeight(26)
        mid.addWidget(self.bar)

        # Breakdown of how many HIGH/MEDIUM/LOW findings
        self.detail = QLabel("Run a scan to calculate your risk score")
        self.detail.setObjectName("status")
        mid.addWidget(self.detail)
        layout.addLayout(mid)

        # Show initial state
        self.update_face(0)
        self._check_update_age()

    def update_face(self, score):
        """Update the health face image to match the current score."""
        px = get_face_pixmap(score)
        self.face_lbl.setPixmap(px)

    def update_score(self):
        """Recalculate and display the current risk score from RISK tracker."""
        s = RISK.score()
        label, colour = RISK.label()
        self.bar.setValue(s)
        self.bar.setFormat(f"{s} / 100  —  {label}")
        self.bar.setStyleSheet(
            f"QProgressBar::chunk{{background:{colour};border-radius:5px;}}"
        )
        h = RISK.findings.count("HIGH")
        m = RISK.findings.count("MEDIUM")
        l = RISK.findings.count("LOW")
        self.detail.setText(
            f"🔴 HIGH: {h}   🟡 MEDIUM: {m}   🟢 LOW: {l}"
            f"   Total findings: {len(RISK.findings)}"
        )
        self.update_face(s)

    def set_profile(self, key, conf=0):
        """Show the detected system profile in the top right."""
        label = PROFILES.get(key, {}).get("label", "Unknown")
        suffix = f" ({conf}% match)" if conf > 0 else ""
        self.profile_lbl.setText(f"Profile: {label}{suffix}")

    def _check_update_age(self):
        """Show a warning if the system hasn't been updated in a while."""
        days, msg = check_update_age()
        if days and days > 7:
            colour = T["DANGER"] if days > 30 else T["WARN"]
            self.update_lbl.setText(f"⏱ {msg}")
            self.update_lbl.setStyleSheet(f"color:{colour};font-size:{fs(-1)}px;")


# ── Pre-action confirmation dialog ────────────────────────────────────────────
class PreActionDialog(QDialog):
    """Shows a clear confirmation dialog before any command runs.
    Displays exactly what command will execute, what it does,
    and how to reverse it. Nothing runs until the user clicks 'Yes'."""

    def __init__(self, action_type, name, cmd, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Confirm Action — {name}")
        self.setMinimumWidth(580)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Big clear title
        title = QLabel(f"⚠️  About to {action_type.upper()}: {name}")
        title.setStyleSheet(
            f"color:{T['WARN']};font-size:{fs(1)}px;font-weight:bold;"
        )
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        # Show the exact command — no surprises
        cmd_label = QLabel("Command that will run with administrator access (sudo):")
        cmd_label.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        layout.addWidget(cmd_label)

        cmd_box = QTextEdit()
        cmd_box.setPlainText(f"sudo {cmd}")
        cmd_box.setReadOnly(True)
        cmd_box.setMaximumHeight(50)
        # Amber border so the command really stands out
        cmd_box.setStyleSheet(
            f"background:{T['BG_DARK']};color:{T['ACCENT']};"
            f"border:2px solid {T['WARN']};border-radius:4px;font-size:{fs()}px;"
        )
        layout.addWidget(cmd_box)

        # Plain English explanation of what will happen
        impact_text = {
            "remove":  f"'{name}' will be completely removed from your system, including its configuration files.",
            "disable": f"'{name}' will be stopped immediately and will not start again on future boots.",
            "upgrade": f"'{name}' will be upgraded to the latest available version.",
            "enable":  f"'{name}' firewall rules will be activated — network traffic will be filtered.",
        }.get(action_type, f"Will execute: sudo {cmd}")

        imp = QLabel(impact_text)
        imp.setWordWrap(True)
        imp.setStyleSheet(
            f"color:{T['TEXT_MAIN']};padding:8px;"
            f"background:{T['BG_CARD']};border-radius:4px;font-size:{fs()}px;"
        )
        layout.addWidget(imp)

        # Show undo command if we know it
        undo = make_undo_cmd(cmd)
        if undo:
            ul = QLabel(f"↩  If you change your mind:   sudo {undo}")
            ul.setWordWrap(True)
            ul.setStyleSheet(
                f"color:{T['TEXT_DIM']};font-size:{fs(-2)}px;font-style:italic;"
            )
            layout.addWidget(ul)

        # Confirm/Cancel buttons
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText(
            "✔  Yes, run this command"
        )
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("✖  Cancel")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ── Plain English explanation database ───────────────────────────────────────
# For each finding type we know about, we have four sections:
# what it is, why it matters, what happens if ignored, and how to fix it.
EXPLANATIONS = {
    "UFW firewall enabled": {
        "what":   "UFW is your machine's front door lock. Right now the door is wide open.",
        "why":    "Without a firewall any service listening on a port is reachable by every device on your network — and potentially the internet if your router forwards ports.",
        "ignore": "If you are behind a NAT router and never expose services the risk is lower. But enabling UFW takes under 30 seconds.",
        "fix":    "Enable UFW with a default deny rule, then allow only what you need: sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable",
    },
    "Fail2ban installed": {
        "what":   "Fail2ban watches your login logs and automatically bans IPs that fail too many times.",
        "why":    "Without it an attacker can try thousands of passwords against SSH with absolutely no consequence — automated bots do this constantly.",
        "ignore": "If SSH is key-only auth the risk is lower — but fail2ban is free and works automatically.",
        "fix":    "sudo apt install fail2ban  — it works out of the box with sensible defaults.",
    },
    "Unattended upgrades enabled": {
        "what":   "Automatically installs security patches in the background while you get on with your life.",
        "why":    "Most real-world attacks exploit known, already-patched vulnerabilities. People just haven't applied the patch yet.",
        "ignore": "You can patch manually — most people forget for weeks at a time.",
        "fix":    "sudo apt install unattended-upgrades  — applies security patches only by default.",
    },
    "Core dumps restricted": {
        "what":   "When a program crashes it can write its entire memory contents to disk as a debug file called a core dump.",
        "why":    "That memory can contain passwords, encryption keys, and session tokens that were in RAM at the time of the crash.",
        "ignore": "Low risk on a personal desktop — higher risk if you run services that handle passwords or sensitive data.",
        "fix":    "Add fs.suid_dumpable=0 to /etc/sysctl.conf then run: sudo sysctl -p",
    },
    "SSH PermitRootLogin disabled": {
        "what":   "Controls whether the all-powerful root account can log in directly over SSH.",
        "why":    "Root has unlimited power on your system. If an attacker gets root SSH credentials the entire machine is theirs.",
        "ignore": "Never ignore this — always log in as your regular user and use sudo for admin tasks.",
        "fix":    "Edit /etc/ssh/sshd_config — set PermitRootLogin no — then: sudo systemctl restart sshd",
    },
    "SSH PasswordAuthentication disabled": {
        "what":   "Controls whether SSH accepts passwords as well as cryptographic keys.",
        "why":    "Passwords can be guessed or brute-forced. SSH keys are mathematically too large to guess — effectively impossible.",
        "ignore": "Set up SSH keys before disabling password auth or you will lock yourself out.",
        "fix":    "Generate an SSH key, copy it to the server, then set PasswordAuthentication no in /etc/ssh/sshd_config",
    },
    "ASLR memory randomisation": {
        "what":   "Randomly shuffles where programs and libraries sit in memory every time they run.",
        "why":    "Many exploits rely on knowing exactly where code lives in memory to redirect execution. ASLR makes that guesswork.",
        "ignore": "Very safe to enable — it is on by default in modern Linux and almost never causes issues.",
        "fix":    "Add kernel.randomize_va_space=2 to /etc/sysctl.conf then run: sudo sysctl -p",
    },
}

# Glossary terms — shown at the bottom of the explain dialog if the
# finding's name or detail contains one of these terms
GLOSSARY = {
    "ASLR":       "Randomises memory layout making exploits harder.",
    "mDNS":       "How devices announce themselves on local network.",
    "CVE":        "Numbered list of known security bugs in software.",
    "UFW":        "Uncomplicated Firewall — controls network traffic in and out.",
    "Fail2ban":   "Watches login logs and bans IPs that fail too many times.",
    "Core dump":  "When a program crashes it can write its memory (possibly containing passwords) to disk.",
    "Unused":     "Software that nothing else depends on — a leftover from a previous install.",
    "RDP":        "Remote Desktop Protocol — port 3389 is one of the most attacked on the internet.",
    "CUPS":       "Print server. Not needed if you do not print from this machine.",
    "Lynis":      "Free security auditing tool that checks OS configuration.",
    "SSH":        "Secure Shell — encrypted remote terminal access.",
    "Telnet":     "Old unencrypted remote shell. Should not be used.",
    "Hardening":  "Reducing attack surface by disabling unused services and tightening configuration.",
    "Rootkit":    "Malicious software that hides itself on your system.",
    "SMART":      "Hard drive self-monitoring — drives report their own health data.",
    "LEFTOVER":   "Software installed as a dependency of something else. That something has been removed, leaving this behind.",
    "sudo":       "Lets a regular user run specific commands as administrator. Short for 'super user do'.",
    "Port":       "A numbered door on your machine through which network traffic enters or leaves.",
}


class ExplainDialog(QDialog):
    """Shows a plain English explanation of any finding.
    Triggered by double-clicking a row or clicking the ? button."""

    def __init__(self, name, ftype, risk, detail, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Plain English Explanation")
        self.setMinimumSize(580, 420)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Risk level uses both colour AND shape for colour-blind accessibility
        icons  = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
        shapes = {"HIGH": "✖ HIGH RISK", "MEDIUM": "▲ MEDIUM RISK",
                  "LOW": "● LOW RISK", "INFO": "ℹ INFORMATIONAL"}
        cols   = {"HIGH": T["DANGER"], "MEDIUM": T["WARN"],
                  "LOW": T["OK"], "INFO": T["ACCENT"]}

        title = QLabel(f"{icons.get(risk, '⚪')} {shapes.get(risk, risk)}  —  {name}")
        title.setStyleSheet(
            f"color:{T['ACCENT']};font-size:{fs(2)}px;font-weight:bold;"
        )
        title.setWordWrap(True)
        layout.addWidget(title)

        rl = QLabel(f"Type: {ftype}")
        rl.setStyleSheet(
            f"color:{cols.get(risk, T['TEXT_DIM'])};font-weight:bold;font-size:{fs()}px;"
        )
        layout.addWidget(rl)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        # Scrollable content area for the explanation
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border:none;")
        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setSpacing(8)

        exp = EXPLANATIONS.get(name, {})
        if exp:
            # Show all four sections if we have them
            for section, content in [
                ("📌 What is this?",         exp.get("what", "")),
                ("⚠️  Why does it matter?",   exp.get("why", "")),
                ("🤔 What if I ignore it?",   exp.get("ignore", "")),
                ("🔧 How to fix it:",         exp.get("fix", "")),
            ]:
                if content:
                    sl = QLabel(section)
                    sl.setStyleSheet(
                        f"color:{T['ACCENT']};font-weight:bold;font-size:{fs()}px;"
                    )
                    il.addWidget(sl)
                    cl = QLabel(content)
                    cl.setWordWrap(True)
                    cl.setStyleSheet(
                        f"color:{T['TEXT_MAIN']};padding-left:12px;font-size:{fs(-1)}px;"
                    )
                    il.addWidget(cl)
        else:
            # Generic fallback for findings we don't have detailed explanations for
            rd = {
                "HIGH":   "Take action soon — this is a real security concern.",
                "MEDIUM": "Worth addressing — reduces your attack surface.",
                "LOW":    "Minor concern — review when convenient.",
                "INFO":   "Informational — no immediate action needed.",
            }.get(risk, "")
            gen = QLabel(f"{detail}\n\n{rd}")
            gen.setWordWrap(True)
            gen.setStyleSheet(
                f"color:{T['TEXT_MAIN']};padding:8px;font-size:{fs(-1)}px;"
            )
            il.addWidget(gen)

        # Show any relevant glossary terms at the bottom
        found = {
            k: v for k, v in GLOSSARY.items()
            if k.lower() in (name + detail).lower()
        }
        if found:
            sep2 = QFrame()
            sep2.setFrameShape(QFrame.Shape.HLine)
            il.addWidget(sep2)
            gl = QLabel("📖 Glossary")
            gl.setStyleSheet(f"color:{T['ACCENT']};font-weight:bold;")
            il.addWidget(gl)
            for term, defn in found.items():
                tl = QLabel(f"<b>{term}</b>: {defn}")
                tl.setWordWrap(True)
                tl.setStyleSheet(
                    f"color:{T['TEXT_DIM']};padding-left:12px;font-size:{fs(-2)}px;"
                )
                il.addWidget(tl)

        scroll.setWidget(inner)
        layout.addWidget(scroll)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.close)
        layout.addWidget(btns)


# ── Findings table ────────────────────────────────────────────────────────────
class FindingsTable(QWidget, WorkerMixin):
    """The main table showing all issues found during scans.
    Supports:
    - Deduplication (same item from multiple scans only shows once)
    - Auto-sorting (HIGH findings always at the top)
    - Interactive column resizing (drag column headers to resize)
    - Live score updates when findings are fixed
    - Search/filter bar to find specific findings"""

    # Signal emitted whenever the risk score changes (finding added or removed)
    score_changed = pyqtSignal()

    def __init__(self, terminal):
        super().__init__()
        self._init_workers()
        self.terminal    = terminal  # Reference to the terminal panel
        self.expert_mode = True      # Show all findings vs essential only
        self.profile_key = "mixed"  # Current system profile (affects tagging)
        self._bulk_depth = 0        # >0 means bulk insert mode (defer sort/repaint)
        self._seen_findings = set() # Fast duplicate check: (name, ftype)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header bar with title and controls — styled via make_style() #findings_hdr ──
        hdr = QWidget()
        hdr.setObjectName("findings_hdr")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(8, 6, 8, 6)
        fhdr_lbl = QLabel(L("findings_hdr"))
        fhdr_lbl.setObjectName("heading")
        hl.addWidget(fhdr_lbl)
        hl.addStretch()

        # Search box — filters visible rows without removing findings
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings...")
        self.search.setFixedWidth(200)
        self.search.setToolTip("Filter the findings list — results update as you type")
        self.search.textChanged.connect(self._filter_rows)
        hl.addWidget(self.search)

        clr = QPushButton("CLEAR ALL")
        clr.setObjectName("danger")
        clr.setFixedHeight(28)
        clr.setToolTip("Remove all findings and reset the risk score")
        clr.clicked.connect(self.clear_findings)
        hl.addWidget(clr)
        layout.addWidget(hdr)

        # ── The findings table itself ──
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["NAME", "TYPE", "RISK", "TAG", "DETAIL", "ACTIONS"]
        )

        hh = self.table.horizontalHeader()
        # Interactive mode: users can drag column borders to resize them
        for col in range(6):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        # Set sensible default widths
        self.table.setColumnWidth(0, 180)   # Name
        self.table.setColumnWidth(1, 90)    # Type
        self.table.setColumnWidth(2, 110)   # Risk
        self.table.setColumnWidth(3, 90)    # Tag
        self.table.setColumnWidth(4, 400)   # Detail — widest
        self.table.setColumnWidth(5, 240)   # Actions — needs room for buttons
        hh.setStretchLastSection(False)

        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        # alternate-background-color is handled globally in make_style() so it updates on theme change
        # Disable the built-in sort — we handle sorting ourselves
        self.table.setSortingEnabled(False)
        self.table.cellDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self.table)

        # "All looks well" banner — shown after a scan that found nothing bad
        self._ok_banner = QLabel(
            "✔  Great! All looks well — nothing concerning found from this scan."
        )
        self._ok_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._apply_ok_banner_style()
        self._ok_banner.setWordWrap(True)
        self._ok_banner.setVisible(False)
        layout.addWidget(self._ok_banner)

    # Risk priority for sorting — lower number = higher priority = shown first
    RISK_SORT = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

    def _risk_display(self, risk):
        """Format the risk level with both colour emoji AND shape symbol
        so colour-blind users can still tell them apart."""
        return {
            "HIGH":   "🔴 ✖ HIGH",
            "MEDIUM": "🟡 ▲ MEDIUM",
            "LOW":    "🟢 ● LOW",
            "INFO":   "🔵 ℹ INFO",
        }.get(risk, risk)

    def _risk_colour(self, risk):
        """Return the hex colour for a given risk level."""
        return {
            "HIGH": T["DANGER"], "MEDIUM": T["WARN"],
            "LOW":  T["OK"],     "INFO":   T["ACCENT"],
        }.get(risk, T["TEXT_MAIN"])

    def _get_tag(self, name, ftype):
        """Determine the tag for a finding based on the system profile.
        If the item is expected for this type of machine, tag it as NORMAL.
        Returns (tag_text, tag_colour)."""
        profile = PROFILES.get(self.profile_key, {})
        n = name.lower()
        # Check if this process is normal for the detected profile
        for proc in profile.get("normal_procs", []):
            if proc in n:
                return "NORMAL ✓", T["OK"]
        # Check if this port is normal for the detected profile
        port_match = re.search(r":(\d+)$", name)
        if port_match and port_match.group(1) in profile.get("normal_ports", []):
            return "NORMAL ✓", T["OK"]
        # Otherwise use the type-based tag
        return {
            "LEFTOVER":  ("LEFTOVER",  T["TEXT_DIM"]),
            "NETWORK":   ("NETWORK",   T["WARN"]),
            "SERVICE":   ("SERVICE",   T["WARN"]),
            "CVE":       ("CVE",       T["DANGER"]),
            "HARDENING": ("HARDEN",    T["WARN"]),
            "OUTDATED":  ("UPDATE",    T["TEXT_DIM"]),
        }.get(ftype, ("REVIEW", T["TEXT_DIM"]))

    def _is_duplicate(self, name, ftype):
        """Check if an identical finding is already in the table.
        Prevents the same issue appearing multiple times from repeated scans."""
        return (name, ftype) in self._seen_findings

    def _drop_seen_name(self, name):
        """Remove all cached duplicate keys for a finding name."""
        self._seen_findings = {k for k in self._seen_findings if k[0] != name}

    def _apply_ok_banner_style(self):
        """Re-apply banner style so theme changes update colours immediately."""
        self._ok_banner.setStyleSheet(
            f"background:{T['OK']}22;color:{T['OK']};border:1px solid {T['OK']};"
            f"border-radius:6px;padding:14px;font-size:{fs()}px;font-weight:bold;"
        )

    def refresh_theme_styles(self):
        """Refresh styles that are computed from the active theme at runtime."""
        self._apply_ok_banner_style()

    def _build_action_cell(self, name, ftype, risk, detail, cmd_remove=None, cmd_disable=None):
        """Create the ACTIONS widget for one findings row."""
        cell = QWidget()
        cell.setStyleSheet("background:transparent;")
        bl = QHBoxLayout(cell)
        bl.setContentsMargins(4, 3, 4, 3)
        bl.setSpacing(4)

        exp_btn = QPushButton("?")
        exp_btn.setObjectName("neutral")
        exp_btn.setFixedSize(28, 28)
        exp_btn.setToolTip("Explain this finding in plain English")
        exp_btn.clicked.connect(
            lambda _, n=name, ft=ftype, r=risk, d=detail:
            ExplainDialog(n, ft, r, d, self.table).exec()
        )
        bl.addWidget(exp_btn)

        ign_btn = QPushButton("✕")
        ign_btn.setObjectName("neutral")
        ign_btn.setFixedSize(28, 28)
        ign_btn.setToolTip("Ignore this finding for this session")
        ign_btn.clicked.connect(lambda _, n=name: self._ignore(n))
        bl.addWidget(ign_btn)

        if cmd_remove:
            rb = QPushButton("REMOVE")
            rb.setObjectName("danger")
            rb.setMinimumWidth(80)
            rb.setFixedHeight(28)
            rb.setToolTip(f"Remove {name} from this system (asks for confirmation)")
            rb.clicked.connect(
                lambda _, c=cmd_remove, n=name, r=risk:
                self._act(c, n, "remove", r)
            )
            bl.addWidget(rb)

        if cmd_disable:
            db = QPushButton("DISABLE")
            db.setObjectName("warn")
            db.setMinimumWidth(80)
            db.setFixedHeight(28)
            db.setToolTip(f"Disable {name} so it no longer runs (asks for confirmation)")
            db.clicked.connect(
                lambda _, c=cmd_disable, n=name, r=risk:
                self._act(c, n, "disable", r)
            )
            bl.addWidget(db)

        bl.addStretch()
        return cell

    def begin_bulk_update(self):
        """Defer expensive UI work while adding many findings."""
        self._bulk_depth += 1
        if self._bulk_depth == 1:
            self.table.setUpdatesEnabled(False)

    def end_bulk_update(self):
        """Apply deferred UI work after bulk add."""
        if self._bulk_depth <= 0:
            return
        self._bulk_depth -= 1
        if self._bulk_depth == 0:
            self.table.setUpdatesEnabled(True)
            self._sort_by_risk()
            self.score_changed.emit()
            self.table.viewport().update()

    def add_finding(self, name, ftype, risk, detail,
                    cmd_remove=None, cmd_disable=None):
        """Add a finding to the table and update the risk score.
        Skips duplicates. In Simple mode, skips INFO and LOW findings."""

        # Skip if user has chosen to ignore this item
        if name in IGNORE_LIST:
            return

        # Skip duplicate findings from repeated scans
        if self._is_duplicate(name, ftype):
            return

        # In Simple mode, only show HIGH and MEDIUM findings
        if not self.expert_mode and risk in ("INFO", "LOW"):
            return

        self._seen_findings.add((name, ftype))

        # Update the risk tracker
        RISK.add(risk)
        if self._bulk_depth == 0:
            self.score_changed.emit()
        # A bad finding appeared — hide the "all looks well" banner if visible
        if risk in ("HIGH", "MEDIUM"):
            self.hide_all_ok_banner()

        # Build the new row
        row = self.table.rowCount()
        self.table.insertRow(row)

        tag, tag_colour = self._get_tag(name, ftype)
        rc = self._risk_colour(risk)

        # Add the text cells
        for col, val in enumerate([name, ftype, self._risk_display(risk), tag, detail]):
            item = QTableWidgetItem(val)
            if col == 2:
                # Risk column — bold and coloured
                item.setForeground(QColor(rc))
                item.setFont(QFont("", fs(-2), QFont.Weight.Bold))
            elif col == 3:
                item.setForeground(QColor(tag_colour))
            else:
                item.setForeground(QColor(T["TEXT_MAIN"]))
            self.table.setItem(row, col, item)

        # Store row metadata in hidden data so sorting can rebuild action buttons safely
        row_meta = {
            "name": name,
            "ftype": ftype,
            "risk": risk,
            "detail": detail,
            "cmd_remove": cmd_remove,
            "cmd_disable": cmd_disable,
        }
        self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, row_meta)

        # Build the ACTIONS cell — explain + ignore + remove/disable buttons
        cell = self._build_action_cell(name, ftype, risk, detail, cmd_remove, cmd_disable)
        self.table.setCellWidget(row, 5, cell)
        self.table.setRowHeight(row, 42)  # Tall enough to show buttons properly

        # Keep findings sorted: HIGH at top, then MEDIUM, LOW, INFO
        if self._bulk_depth == 0:
            self._sort_by_risk()

    def _sort_by_risk(self):
        """Re-sort the table rows so HIGH risk items are always at the top.
        All Qt item data is copied to plain Python structures BEFORE touching
        the table — Qt deletes QTableWidgetItem when setItem() replaces it,
        so holding live item references across setItem() calls causes crashes."""
        rows = []
        for r in range(self.table.rowCount()):
            risk_item = self.table.item(r, 2)
            risk_text = risk_item.text().split()[-1] if risk_item else "INFO"
            name_item = self.table.item(r, 0)
            user_data = name_item.data(Qt.ItemDataRole.UserRole) if name_item else None
            row_risk = user_data.get("risk", risk_text) if isinstance(user_data, dict) else risk_text
            priority  = self.RISK_SORT.get(row_risk, 3)

            # Copy every cell's data into plain Python — no Qt references kept
            cells = []
            for c in range(5):
                it = self.table.item(r, c)
                if it:
                    cells.append({
                        "text":      it.text(),
                        "fg":        it.foreground().color().name(),
                        "bold":      it.font().bold(),
                        "font":      QFont(it.font()),
                    })
                else:
                    cells.append(None)

            if isinstance(user_data, dict):
                action_data = dict(user_data)
            else:
                action_data = {
                    "name": cells[0]["text"] if cells[0] else "",
                    "ftype": cells[1]["text"] if cells[1] else "",
                    "risk": risk_text,
                    "detail": cells[4]["text"] if cells[4] else "",
                    "cmd_remove": None,
                    "cmd_disable": None,
                }

            rows.append({"priority": priority, "cells": cells, "action_data": action_data})

        rows.sort(key=lambda x: x["priority"])

        # Rebuild rows from copied data, including action widgets so buttons stay aligned.
        for i, row_data in enumerate(rows):
            for col, cell in enumerate(row_data["cells"]):
                if cell:
                    new_item = QTableWidgetItem(cell["text"])
                    new_item.setForeground(QColor(cell["fg"]))
                    if cell["bold"]:
                        new_item.setFont(cell["font"])
                    self.table.setItem(i, col, new_item)
            if self.table.item(i, 0):
                self.table.item(i, 0).setData(
                    Qt.ItemDataRole.UserRole, row_data["action_data"]
                )
            self.table.removeCellWidget(i, 5)
            action = row_data["action_data"]
            self.table.setCellWidget(
                i,
                5,
                self._build_action_cell(
                    action.get("name", ""),
                    action.get("ftype", ""),
                    action.get("risk", "INFO"),
                    action.get("detail", ""),
                    action.get("cmd_remove"),
                    action.get("cmd_disable"),
                )
            )
            self.table.setRowHeight(i, 42)

    def _ignore(self, name):
        """Remove a finding from the table and add it to the ignore list."""
        IGNORE_LIST.add(name)
        self._drop_seen_name(name)
        removed = False
        for r in range(self.table.rowCount() - 1, -1, -1):
            item = self.table.item(r, 0)
            if item and item.text() == name:
                data = item.data(Qt.ItemDataRole.UserRole)
                row_risk = data.get("risk") if isinstance(data, dict) else data
                if row_risk in ("HIGH", "MEDIUM", "LOW", "INFO"):
                    RISK.remove_entry(row_risk)
                self.table.removeRow(r)
                removed = True
        if removed:
            self.score_changed.emit()
        self.terminal.append_info(
            f"'{name}' ignored — won't be flagged again this session."
        )

    def _on_double_click(self, row, col):
        """Open the explain dialog when the user double-clicks any row."""
        n  = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
        ft = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
        r  = self.table.item(row, 2).text().split()[-1] if self.table.item(row, 2) else ""
        d  = self.table.item(row, 4).text() if self.table.item(row, 4) else ""
        ExplainDialog(n, ft, r, d, self.table).exec()

    def _act(self, cmd, name, action_type, risk):
        """Run an action (remove/disable) after showing the confirmation dialog.
        Prompts for sudo password via a GUI dialog if credentials are not cached."""

        # Determine if we need a password
        sudo_password = None
        if not check_sudo_cached():
            pw, ok = QInputDialog.getText(
                self,
                "Administrator Password Required",
                "This action requires your sudo (administrator) password.\n"
                "Your password is used once and never stored.",
                QLineEdit.EchoMode.Password,
            )
            if not ok or not pw:
                self.terminal.append_err(
                    "Action cancelled — sudo password not provided."
                )
                return
            sudo_password = pw.encode()

        # Show the confirmation dialog
        dlg = PreActionDialog(action_type, name, cmd, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        self.terminal.append_cmd(f"sudo {cmd}")

        # Prepare the undo log entry
        undo     = make_undo_cmd(cmd)
        info     = get_rollback_info(cmd, name)
        entry    = {
            "time":             datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action":           f"{action_type} '{name}'",
            "cmd":              f"sudo {cmd}",
            "undo_cmd":         f"sudo {undo}" if undo else "N/A",
            "risk_level":       info["level"],
            "rollback_does":    info["does"],
            "rollback_risk":    info["risk"],
            "rollback_exploit": info["exploit"],
            "name":             name,
        }

        # Run the command in a background thread
        w = CommandWorker(cmd.split(), sudo=True, password=sudo_password)
        w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
        w.error_ready.connect(self.terminal.append_err)
        w.finished_ok.connect(lambda: self._verify(cmd, name, risk, entry))
        self._start_worker(w)

    def _verify(self, cmd, name, risk, entry):
        """After an action runs, verify it worked. If it did:
        - Remove the finding row from the table
        - Remove the risk entry (score updates live)
        - Add to the undo log"""
        pkg = cmd.split()[-1]
        success = False

        if valid_pkg(pkg) and ("purge" in cmd or "remove" in cmd):
            # For removals, check the package is actually gone
            still_installed = pkg_installed(pkg)
            if not still_installed:
                self.terminal.append_ok(
                    f"Verified: '{pkg}' removed successfully. Risk score updated."
                )
                self._remove_finding_and_update_score(name, risk)
                success = True
            else:
                self.terminal.append_err(
                    f"Verify failed: '{pkg}' may still be installed. "
                    f"Check the terminal output above for errors."
                )
        else:
            # For non-removal actions (disable/mask), trust that it worked
            self.terminal.append_ok(f"Action complete: '{name}'")
            self._remove_finding_and_update_score(name, risk)
            success = True

        if success:
            # Save to undo log
            UNDO_LOG.append(entry)
            save_undo_entry(entry)
            # Track in session summary
            SESSION.log_action(entry["action"], name, succeeded=True)
            # Notify the undo panel if it is open
            app = QApplication.instance()
            if hasattr(app, "undo_panel_ref") and app.undo_panel_ref:
                try:
                    app.undo_panel_ref.add_live_entry(entry)
                except Exception as e:
                    logging.error(f"Undo panel update failed: {e}")

    def _remove_finding_and_update_score(self, name, risk):
        """Remove a finding row from the table and reduce the risk score."""
        # Find and remove the row
        self._drop_seen_name(name)
        for r in range(self.table.rowCount() - 1, -1, -1):
            item = self.table.item(r, 0)
            if item and item.text() == name:
                self.table.removeRow(r)
                break
        # Remove from the risk tracker so score drops
        RISK.remove_entry(risk)
        self.score_changed.emit()

    def clear_findings(self):
        """Clear all findings and reset the risk score to zero."""
        self.table.setRowCount(0)
        self._seen_findings.clear()
        RISK.clear()
        self.score_changed.emit()
        self._ok_banner.setVisible(False)

    def show_all_ok_banner(self):
        """Show the green 'all looks well' banner if no HIGH/MEDIUM findings.
        RISK.findings is a flat list of strings e.g. ["HIGH", "LOW", "MEDIUM"]."""
        has_bad = "HIGH" in RISK.findings or "MEDIUM" in RISK.findings
        if not has_bad:
            self._ok_banner.setVisible(True)

    def hide_all_ok_banner(self):
        """Hide the all-ok banner — called when a bad finding is added."""
        self._ok_banner.setVisible(False)

    def _filter_rows(self, text):
        """Show only rows where any column contains the search text."""
        text = text.lower()
        for r in range(self.table.rowCount()):
            # Check if any cell in the row matches
            match = any(
                self.table.item(r, c) and text in self.table.item(r, c).text().lower()
                for c in range(5)
            )
            # Hide non-matching rows; show all rows when search is empty
            self.table.setRowHidden(r, not match if text else False)

# ── System profile definitions ────────────────────────────────────────────────
# Profiles tell the scanner what is "normal" for a given machine type.
# Ports and processes listed as normal won't be flagged as suspicious.
PROFILES = {
    "gaming": {
        "label": "🎮 Gaming Rig",
        "normal_procs": ["steam","sunshine","steamwebhelper","lutris","wine","gamemode"],
        "normal_ports": ["27036","27015","47984","47989","47990","48010"],
    },
    "docker": {
        "label": "🐳 Docker Host",
        "normal_procs": ["dockerd","containerd","portainer"],
        "normal_ports": ["2376","2377","9000"],
    },
    "hypervisor": {
        "label": "🖥  Hypervisor",
        "normal_procs": ["qemu","pveproxy","lxc","kvm"],
        "normal_ports": ["8006","5900","5901"],
    },
    "webserver": {
        "label": "🌐 Web Server",
        "normal_procs": ["apache2","nginx","php-fpm","caddy"],
        "normal_ports": ["80","443","8080","8443"],
    },
    "fileserver": {
        "label": "📁 File Server",
        "normal_procs": ["smbd","nmbd","nfsd"],
        "normal_ports": ["139","445","2049","21"],
    },
    "headless": {
        "label": "⚙  Headless Server",
        "normal_procs": ["sshd","systemd","cron"],
        "normal_ports": ["22"],
    },
    "laptop": {
        "label": "💻 Personal Laptop",
        "normal_procs": ["NetworkManager","pulseaudio","pipewire"],
        "normal_ports": [],
    },
    "workstation": {
        "label": "💼 Work Laptop",
        "normal_procs": ["teams","zoom","slack","chrome","firefox"],
        "normal_ports": [],
    },
    "mixed": {
        "label": "🔀 Mixed Use",
        "normal_procs": [],
        "normal_ports": [],
    },
}

def detect_profile():
    """Try to automatically detect what kind of machine this is
    by looking at running processes and installed packages.
    Returns (profile_key, confidence_percent)."""
    signals = {}
    try:
        procs = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        ).stdout.lower()
        # Only check installed packages on apt-based systems
        if PKG_MGR == "apt":
            pkgs = subprocess.run(
                ["dpkg-query", "-W", "--showformat=${Package}\n"],
                capture_output=True, text=True, timeout=5
            ).stdout.lower()
        else:
            pkgs = ""
        combined = procs + pkgs
        signals["gaming"]     = sum(1 for x in ["steam","sunshine","lutris","wine","gamemode"] if x in combined)
        signals["docker"]     = sum(1 for x in ["docker","containerd","portainer"] if x in combined)
        signals["hypervisor"] = sum(1 for x in ["proxmox","qemu","kvm","pveproxy","lxc"] if x in combined)
        signals["webserver"]  = sum(1 for x in ["apache2","nginx","php-fpm","caddy"] if x in combined)
        signals["fileserver"] = sum(1 for x in ["smbd","nmbd","nfsd"] if x in combined)
        signals["workstation"]= sum(1 for x in ["teams","zoom","slack","libreoffice"] if x in combined)
        signals["headless"]   = 2 if "DISPLAY" not in os.environ else 0
        signals["laptop"]     = 1 if os.path.exists("/sys/class/power_supply/BAT0") else 0
    except Exception as e:
        logging.error(f"Profile detection error: {e}")

    best = max(signals, key=signals.get) if signals else "mixed"
    conf = min(100, signals.get(best, 0) * 25)
    if signals.get(best, 0) == 0:
        best, conf = "mixed", 0
    return best, conf


# ── Quick security checks ─────────────────────────────────────────────────────
def run_quick_checks(terminal, findings):
    """Run the 8 core security checks and report to both terminal and findings.
    Each check shows a clear pass/fail with an explanation if it fails."""
    terminal.append("\nQuick Security Checks\n" + "─" * 50, T["ACCENT"])

    # Each check is: (description, command, pass_function, fix_command, why_it_matters)
    CHECKS = [
        (
            "SSH PermitRootLogin disabled",
            ["grep", "-i", "PermitRootLogin", "/etc/ssh/sshd_config"],
            lambda o: "no" in o.lower() or "prohibit" in o.lower(),
            "Edit /etc/ssh/sshd_config → PermitRootLogin no  then: sudo systemctl restart sshd",
            "Stops attackers from logging in directly as the all-powerful root account over SSH."
        ),
        (
            "SSH PasswordAuthentication disabled",
            ["grep", "-i", "PasswordAuthentication", "/etc/ssh/sshd_config"],
            lambda o: bool(re.search(r"(?im)^\s*PasswordAuthentication\s+no\b", o)),
            "Edit /etc/ssh/sshd_config → PasswordAuthentication no  (set up SSH keys first!)",
            "Forces key-based SSH login. Keys cannot be brute-forced like passwords."
        ),
        (
            "UFW firewall is active",
            ["systemctl", "is-active", "ufw"],
            lambda o: "active" in o.lower(),
            "sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable",
            "Your firewall is off. Everything on your machine is reachable from your network."
        ),
        (
            "Fail2ban is installed and running",
            ["systemctl", "is-active", "fail2ban"],
            lambda o: "active" in o.lower(),
            "sudo apt install fail2ban  — works automatically after install",
            "Blocks IPs that repeatedly fail login attempts. Stops brute-force attacks cold."
        ),
        (
            "Unattended security upgrades enabled",
            ["dpkg", "-l", "unattended-upgrades"],
            lambda o: "ii" in o,
            "sudo apt install unattended-upgrades",
            "Auto-applies security patches so you don't need to remember to update."
        ),
        (
            "Password file has correct permissions",
            ["ls", "-la", "/etc/passwd"],
            lambda o: "rw-r--r--" in o,
            "sudo chmod 644 /etc/passwd",
            "The password file should only be writable by root — not by other users."
        ),
        (
            "Core dumps are restricted",
            ["sysctl", "fs.suid_dumpable"],
            lambda o: "= 0" in o,
            "echo 'fs.suid_dumpable=0' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p",
            "Stops programs writing their memory (which may contain passwords) to disk on crash."
        ),
        (
            "ASLR memory randomisation enabled",
            ["sysctl", "kernel.randomize_va_space"],
            lambda o: "= 2" in o,
            "echo 'kernel.randomize_va_space=2' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p",
            "Randomises memory layout — makes software exploits significantly harder to execute."
        ),
    ]

    passed = 0
    for desc, cmd, pass_fn, fix, why in CHECKS:
        try:
            r  = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            ok = pass_fn(r.stdout + r.stderr)
            if ok:
                # Pass — show in terminal AND add green INFO finding
                terminal.append_ok(desc)
                findings.add_finding(
                    desc, "HARDENING", "INFO",
                    "✔ This check passed — no action needed."
                )
                passed += 1
            else:
                # Fail — show in terminal AND add MEDIUM finding
                terminal.append(f"  ✖  {desc}", T["DANGER"])
                terminal.append(f"     Why: {why}", T["WARN"])
                terminal.append(f"     Fix: {fix}", T["TEXT_DIM"])
                findings.add_finding(desc, "HARDENING", "MEDIUM", why)
        except subprocess.TimeoutExpired:
            terminal.append_warn(f"{desc} — check timed out")
        except FileNotFoundError:
            terminal.append_warn(f"{desc} — command not available on this system")
        except Exception as e:
            terminal.append_warn(f"{desc} — could not check: {e}")
            logging.error(f"Quick check '{desc}' failed: {e}")

    terminal.append(
        f"\n{'─'*50}\n{passed}/{len(CHECKS)} checks passed", T["ACCENT"]
    )
    SESSION.log_scan("Quick Security Checks", len(CHECKS) - passed)
    return passed


# ── Guided fix wizard ─────────────────────────────────────────────────────────
class GuidedWizard(QDialog, WorkerMixin):
    """Step-by-step guided fixes for common security issues.
    Shows the fix list first, then details when user selects one.
    Nothing runs until the user explicitly clicks RUN."""

    def __init__(self, terminal, parent=None):
        super().__init__(parent)
        self._init_workers()
        self.setWindowTitle("Step-by-Step Fix Wizard")
        self.setMinimumSize(660, 540)
        self.terminal = terminal
        self._cmds    = []  # Commands for the currently selected fix

        layout = QVBoxLayout(self)
        hdr = QLabel("🔧  GUIDED FIX WIZARD")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)
        info = QLabel(
            "Select a fix from the list. Each step explains exactly what it does "
            "before anything runs. Nothing happens until you click RUN."
        )
        info.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Stack: page 0 = fix list, page 1 = fix detail
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        # Define the available fixes: (name, fix_fn, check_fn, meta)
        self.fixes = [
            ("Enable UFW Firewall", self._fix_ufw, self._check_ufw, {
                "what": "Turns on a host firewall with deny-by-default inbound policy.",
                "helps": "Reduces attack surface by blocking unsolicited inbound connections.",
                "overhead": "Low CPU/RAM impact; may require opening ports for services you intentionally run.",
            }),
            ("Install and Start Fail2ban", self._fix_fail2ban, self._check_fail2ban, {
                "what": "Installs a daemon that watches auth logs and temporarily bans abusive IPs.",
                "helps": "Slows or stops brute-force login attempts against SSH and similar services.",
                "overhead": "Low overhead; can occasionally ban legitimate repeated failed logins (ban expires).",
            }),
            ("Harden SSH Configuration", self._fix_ssh, self._check_ssh, {
                "what": "Disables root SSH login and disables password-based SSH auth.",
                "helps": "Prevents high-risk root remote auth and blocks password brute-force vectors.",
                "overhead": "Requires SSH keys to be set up first; misconfiguration can lock out remote access.",
            }),
            ("Enable Auto Security Updates", self._fix_autoupdate, self._check_autoupdate, {
                "what": "Installs and enables unattended security patching.",
                "helps": "Closes known vulnerabilities faster without relying on manual updates.",
                "overhead": "Small background network/disk usage; rare package regressions after updates.",
            }),
            ("Restrict Core Dumps", self._fix_coredump, self._check_coredump, {
                "what": "Prevents privileged process memory dumps from being written to disk.",
                "helps": "Protects sensitive data (keys/tokens/passwords) from crash dump exposure.",
                "overhead": "Reduces post-crash forensic detail for privileged process debugging.",
            }),
            ("Harden Kernel Settings", self._fix_kernel, self._check_kernel, {
                "what": "Restricts kernel log access, hides kernel memory addresses, and limits process debugging.",
                "helps": "Makes it significantly harder for malware to gather information needed to exploit your system.",
                "overhead": "None for normal desktop use. Only affects kernel debugging tools.",
            }),
            ("Harden Network Stack", self._fix_network, self._check_network, {
                "what": "Enables SYN flood protection, disables ICMP redirects, enables IP spoofing protection, and blocks source routing.",
                "helps": "Hardens your network against common attack vectors like spoofing, flooding, and man-in-the-middle.",
                "overhead": "None for desktop use. These are CIS Level 1 workstation recommendations.",
            }),
            ("Block Uncommon Network Protocols", self._fix_protocols, self._check_protocols, {
                "what": "Prevents loading kernel modules for DCCP, SCTP, RDS, and TIPC — obscure protocols with repeated vulnerabilities.",
                "helps": "Removes attack surface. If the vulnerable code cannot load, it cannot be exploited.",
                "overhead": "None. These protocols are used in telecoms and clustering, never on a desktop.",
            }),
            ("Block Uncommon Filesystems", self._fix_filesystems, self._check_filesystems, {
                "what": "Prevents loading kernel modules for cramfs, freevxfs, hfs, hfsplus, and jffs2.",
                "helps": "A malicious USB drive formatted with one of these rare filesystems cannot trigger vulnerable parsing code.",
                "overhead": "None unless you mount macOS-formatted drives (hfs/hfsplus).",
            }),
            ("Block FireWire / Thunderbolt DMA", self._fix_dma, self._check_dma, {
                "what": "Prevents loading FireWire and Thunderbolt modules to block Direct Memory Access attacks.",
                "helps": "Stops physical-access attackers from plugging in a device that reads your RAM directly, bypassing all software security.",
                "overhead": "Do NOT apply if you use a Thunderbolt dock, external GPU, or Thunderbolt display.",
            }),
            ("Enable AppArmor", self._fix_apparmor, self._check_apparmor, {
                "what": "Installs and enables AppArmor, Ubuntu's built-in application sandboxing system.",
                "helps": "Confines programs to pre-defined profiles so that even if one is compromised, it cannot access files or resources outside those profiles.",
                "overhead": "None for normal desktop use. AppArmor is enabled by default on Ubuntu; this ensures it is installed and running.",
            }),
            ("Disable Ctrl+Alt+Del Reboot", self._fix_cad, self._check_cad, {
                "what": "Masks the ctrl-alt-del.target so pressing Ctrl+Alt+Del from a text console will not reboot the machine.",
                "helps": "Prevents accidental or malicious reboots by anyone with physical keyboard access at a TTY.",
                "overhead": "You lose the text-console Ctrl+Alt+Del shortcut. Graphical desktop shortcuts are unaffected.",
            }),
        ]

        # ── Page 0: Fix selection list ──
        sel_page = QWidget()
        sl = QVBoxLayout(sel_page)
        sl.addWidget(QLabel("Select a security fix to walk through:"))
        legend = QLabel("✅ = already configured    ⚠️ = not yet configured")
        legend.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-2)}px;")
        sl.addWidget(legend)
        self.fix_list = QListWidget()
        for name, _, check_fn, meta in self.fixes:
            done = check_fn()
            prefix = "✅  " if done else "⚠️  "
            item = QListWidgetItem(f"{prefix}{name}")
            item.setData(Qt.ItemDataRole.UserRole, done)
            item.setToolTip(
                f"What: {meta['what']}\n"
                f"Helps: {meta['helps']}\n"
                f"Overhead: {meta['overhead']}"
            )
            self.fix_list.addItem(item)
        self.fix_list.itemClicked.connect(self._on_item_clicked)
        sl.addWidget(self.fix_list)
        self.stack.addWidget(sel_page)

        # ── Page 1: Fix detail view ──
        detail_page = QWidget()
        dl = QVBoxLayout(detail_page)
        self.fix_title = QLabel("")
        self.fix_title.setStyleSheet(
            f"color:{T['ACCENT']};font-size:{fs(1)}px;font-weight:bold;"
        )
        dl.addWidget(self.fix_title)
        self.fix_status = QLabel("")
        self.fix_status.setWordWrap(True)
        dl.addWidget(self.fix_status)
        self.fix_content = QTextEdit()
        self.fix_content.setReadOnly(True)
        dl.addWidget(self.fix_content)
        self.run_btn = QPushButton("▶  RUN THIS FIX NOW")
        self.run_btn.setObjectName("ok")
        self.run_btn.setFixedHeight(40)
        self.run_btn.setToolTip("Runs all steps above with sudo — asks for confirmation")
        self.run_btn.clicked.connect(self._run_fix)
        dl.addWidget(self.run_btn)
        back_btn = QPushButton("← BACK TO LIST")
        back_btn.setObjectName("neutral")
        back_btn.setFixedHeight(32)
        back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        dl.addWidget(back_btn)
        self.stack.addWidget(detail_page)

        close_btn = QPushButton("CLOSE")
        close_btn.setObjectName("neutral")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)

    def _on_item_clicked(self, item):
        """Load the selected fix when the user clicks a list item."""
        idx = self.fix_list.row(item)
        if idx < 0 or idx >= len(self.fixes):
            return
        name, fn, _check_fn, meta = self.fixes[idx]
        done = item.data(Qt.ItemDataRole.UserRole)
        self.fix_title.setText(name)
        if done:
            self.fix_status.setText("✅ Already configured — your system already has this protection.")
            self.fix_status.setStyleSheet(f"color:{T['OK']};font-weight:bold;font-size:{fs(0)}px;padding:4px;")
            self.run_btn.setText("▶  RE-APPLY THIS FIX")
        else:
            self.fix_status.setText("⚠️ Not yet configured — review the steps below, then click RUN.")
            self.fix_status.setStyleSheet(f"color:{T['WARN']};font-weight:bold;font-size:{fs(0)}px;padding:4px;")
            self.run_btn.setText("▶  RUN THIS FIX NOW")
        steps, cmds = fn()
        self._cmds = cmds
        steps_html = "".join(
            f"<p><b>Step {i+1}:</b><br>{html.escape(s)}</p>"
            for i, s in enumerate(steps)
        )
        self.fix_content.setHtml(
            f"<p><b>What this changes:</b><br>{html.escape(meta['what'])}</p>"
            f"<p><b>How this helps security:</b><br>{html.escape(meta['helps'])}</p>"
            f"<p><b>Overheads / tradeoffs:</b><br>{html.escape(meta['overhead'])}</p>"
            f"<hr><p><b>Execution steps:</b></p>"
            f"{steps_html}"
        )
        self.stack.setCurrentIndex(1)

    def _run_fix(self):
        """Run all the commands for the selected fix after confirmation."""
        if not self._cmds:
            return
        if QMessageBox.question(
            self, "Run Fix?",
            f"This will run {len(self._cmds)} command(s) with sudo.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        for cmd in self._cmds:
            # cmd may be a pre-split list (for commands with shell syntax)
            # or a plain string (split on whitespace for simple commands)
            if isinstance(cmd, list):
                cmd_list = cmd
                cmd_str  = " ".join(cmd)
            else:
                cmd_list = cmd.split()
                cmd_str  = cmd
            self.terminal.append_cmd(f"sudo {cmd_str}")
            w = CommandWorker(cmd_list, sudo=True, timeout=120)
            w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
            w.error_ready.connect(self.terminal.append_err)
            self._start_worker(w)
        QMessageBox.information(
            self, "Running",
            "Commands sent to the terminal. Check the terminal panel for results."
        )

    # ── Fix definitions — steps (shown to user) and commands (what runs) ──
    def _fix_ufw(self):
        return (
            [
                "Deny all incoming traffic by default — nothing gets in unless you specifically allow it.",
                "Allow all outgoing traffic — your machine can still browse the web and get updates.",
                "Allow SSH connections so you cannot lock yourself out of remote access.",
                "Enable UFW — the firewall is now active and protecting your machine.",
            ],
            ["ufw default deny incoming", "ufw default allow outgoing",
             "ufw allow ssh", "ufw enable"]
        )

    def _fix_fail2ban(self):
        return (
            [
                "Install fail2ban — it runs as a background service automatically after install.",
                "Start fail2ban right now without rebooting.",
                "Enable fail2ban to start automatically on every boot.",
            ],
            ["apt install fail2ban -y", "systemctl start fail2ban",
             "systemctl enable fail2ban"]
        )

    def _fix_ssh(self):
        return (
            [
                "Disable root login over SSH. Make sure you have sudo access BEFORE doing this!",
                "Disable password authentication — key-based login only. Set up SSH keys FIRST or you will be locked out!",
                "Restart SSH to apply the changes.",
            ],
            [
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                "systemctl restart sshd",
            ]
        )

    def _fix_autoupdate(self):
        return (
            [
                "Install unattended-upgrades — applies security patches automatically in the background.",
                "Configure it to run automatically.",
            ],
            ["apt install unattended-upgrades -y", "dpkg-reconfigure -plow unattended-upgrades"]
        )

    def _fix_coredump(self):
        return (
            [
                "Prevent privileged programs from writing their memory to disk when they crash.",
                "Apply the change immediately — no reboot needed.",
            ],
            [["sh", "-c", "echo fs.suid_dumpable=0 >> /etc/sysctl.conf"], "sysctl -p"]
        )

    def _fix_kernel(self):
        return (
            [
                "Restrict kernel log access (dmesg) — non-root users cannot read kernel messages that might reveal security details.",
                "Hide kernel memory addresses — makes it much harder for attackers to craft targeted exploits.",
                "Restrict process debugging (ptrace) — prevents malware from attaching to and reading memory of your browser or password manager.",
                "Apply all changes immediately — no reboot needed.",
            ],
            [
                ["sh", "-c", "printf 'kernel.dmesg_restrict=1\\nkernel.kptr_restrict=2\\nkernel.yama.ptrace_scope=1\\n' > /etc/sysctl.d/99-kernel-hardening.conf"],
                "sysctl -p /etc/sysctl.d/99-kernel-hardening.conf",
            ]
        )

    def _fix_network(self):
        return (
            [
                "Enable SYN flood protection — uses cryptographic cookies to handle connection floods without exhausting your system.",
                "Disable ICMP redirects — prevents other machines on your network from rerouting your traffic through them.",
                "Enable reverse path filtering — drops network packets with forged source addresses.",
                "Disable source routing — prevents attackers from dictating how packets travel through the network.",
                "Apply all changes immediately — no reboot needed.",
            ],
            [
                ["sh", "-c", "printf '"
                 "net.ipv4.tcp_syncookies=1\\n"
                 "net.ipv4.conf.all.accept_redirects=0\\n"
                 "net.ipv4.conf.default.accept_redirects=0\\n"
                 "net.ipv4.conf.all.send_redirects=0\\n"
                 "net.ipv4.conf.default.send_redirects=0\\n"
                 "net.ipv6.conf.all.accept_redirects=0\\n"
                 "net.ipv6.conf.default.accept_redirects=0\\n"
                 "net.ipv4.conf.all.rp_filter=1\\n"
                 "net.ipv4.conf.default.rp_filter=1\\n"
                 "net.ipv4.conf.all.accept_source_route=0\\n"
                 "net.ipv4.conf.default.accept_source_route=0\\n"
                 "net.ipv6.conf.all.accept_source_route=0\\n"
                 "net.ipv6.conf.default.accept_source_route=0\\n"
                 "' > /etc/sysctl.d/99-network-hardening.conf"],
                "sysctl -p /etc/sysctl.d/99-network-hardening.conf",
            ]
        )

    def _fix_protocols(self):
        return (
            [
                "Block DCCP, SCTP, RDS, and TIPC kernel modules — obscure network protocols with a history of security vulnerabilities that no desktop user needs.",
                "Takes effect for future module loads. Already-loaded modules are not affected until next reboot.",
            ],
            [
                ["sh", "-c", "printf 'install dccp /bin/false\\ninstall sctp /bin/false\\ninstall rds /bin/false\\ninstall tipc /bin/false\\n' > /etc/modprobe.d/uncommon-network.conf"],
            ]
        )

    def _fix_filesystems(self):
        return (
            [
                "Block cramfs, freevxfs, hfs, hfsplus, and jffs2 kernel modules — rare filesystem types with known parsing vulnerabilities.",
                "A malicious USB drive formatted with one of these filesystems cannot trigger the vulnerable code if the module is blocked.",
            ],
            [
                ["sh", "-c", "printf 'install cramfs /bin/false\\ninstall freevxfs /bin/false\\ninstall hfs /bin/false\\ninstall hfsplus /bin/false\\ninstall jffs2 /bin/false\\n' > /etc/modprobe.d/uncommon-filesystems.conf"],
            ]
        )

    def _fix_dma(self):
        return (
            [
                "Block FireWire kernel modules — FireWire ports allow Direct Memory Access, letting a plugged-in device read your entire system RAM.",
                "Block Thunderbolt module — same DMA risk. WARNING: Skip this if you use a Thunderbolt dock, external GPU, or Thunderbolt display!",
                "Takes effect for future module loads. Already-loaded modules are not affected until next reboot.",
            ],
            [
                ["sh", "-c", "printf 'install firewire-core /bin/false\\ninstall firewire-ohci /bin/false\\ninstall thunderbolt /bin/false\\n' > /etc/modprobe.d/blacklist-dma.conf"],
            ]
        )

    def _fix_apparmor(self):
        return (
            [
                "Install AppArmor and its command-line utilities (aa-status, aa-enforce).",
                "Enable the AppArmor service so it starts on every boot.",
                "Start AppArmor now without needing a reboot.",
            ],
            [
                "apt install -y apparmor apparmor-utils",
                "systemctl enable apparmor",
                "systemctl start apparmor",
            ]
        )

    def _fix_cad(self):
        return (
            [
                "Mask the ctrl-alt-del.target systemd unit so pressing Ctrl+Alt+Del from a text console does nothing.",
            ],
            ["systemctl mask ctrl-alt-del.target"]
        )

    # ── Status check helpers ─────────────────────────────────────────────────
    @staticmethod
    def _run_check(cmd, pass_fn):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3,
                               stdin=subprocess.DEVNULL)
            return pass_fn(r.stdout + r.stderr)
        except Exception:
            return False

    def _check_ufw(self):
        # `systemctl is-active` prints exactly "active" when up; "inactive" contains
        # the substring "active", so use exact match on stripped output.
        return self._run_check(["systemctl", "is-active", "ufw"],
                               lambda o: o.strip() == "active")

    def _check_fail2ban(self):
        return self._run_check(["systemctl", "is-active", "fail2ban"],
                               lambda o: o.strip() == "active")

    def _check_ssh(self):
        # Use anchored regexes so commented-out lines and loose substrings don't match.
        root_ok = self._run_check(
            ["grep", "-i", "PermitRootLogin", "/etc/ssh/sshd_config"],
            lambda o: bool(re.search(r"(?im)^\s*PermitRootLogin\s+(no|prohibit-password)\b", o)))
        pw_ok = self._run_check(
            ["grep", "-i", "PasswordAuthentication", "/etc/ssh/sshd_config"],
            lambda o: bool(re.search(r"(?im)^\s*PasswordAuthentication\s+no\b", o)))
        return root_ok and pw_ok

    def _check_autoupdate(self):
        return self._run_check(["dpkg", "-l", "unattended-upgrades"],
                               lambda o: "ii" in o)

    def _check_coredump(self):
        return self._run_check(["sysctl", "fs.suid_dumpable"],
                               lambda o: "= 0" in o)

    def _check_kernel(self):
        return (
            self._run_check(["sysctl", "kernel.dmesg_restrict"], lambda o: "= 1" in o) and
            self._run_check(["sysctl", "kernel.kptr_restrict"], lambda o: "= 2" in o) and
            self._run_check(["sysctl", "kernel.yama.ptrace_scope"], lambda o: "= 1" in o))

    def _check_network(self):
        # Covers every sysctl _fix_network writes — IPv4 core set plus IPv6 redirects
        # and source-route denial. Keeps the ✅ badge honest after the fix runs.
        return (
            self._run_check(["sysctl", "net.ipv4.tcp_syncookies"], lambda o: "= 1" in o) and
            self._run_check(["sysctl", "net.ipv4.conf.all.accept_redirects"], lambda o: "= 0" in o) and
            self._run_check(["sysctl", "net.ipv4.conf.all.rp_filter"], lambda o: "= 1" in o) and
            self._run_check(["sysctl", "net.ipv4.conf.all.accept_source_route"], lambda o: "= 0" in o) and
            self._run_check(["sysctl", "net.ipv6.conf.all.accept_redirects"], lambda o: "= 0" in o) and
            self._run_check(["sysctl", "net.ipv6.conf.all.accept_source_route"], lambda o: "= 0" in o))

    def _check_protocols(self):
        return self._run_check(["modprobe", "-n", "-v", "dccp"],
                               lambda o: "install /bin/false" in o or "install /bin/true" in o)

    def _check_filesystems(self):
        return self._run_check(["modprobe", "-n", "-v", "cramfs"],
                               lambda o: "install /bin/false" in o or "install /bin/true" in o)

    def _check_dma(self):
        return self._run_check(["modprobe", "-n", "-v", "firewire-core"],
                               lambda o: "install /bin/false" in o or "install /bin/true" in o)

    def _check_apparmor(self):
        return self._run_check(["systemctl", "is-active", "apparmor"],
                               lambda o: o.strip() == "active")

    def _check_cad(self):
        # `systemctl is-enabled ctrl-alt-del.target` prints "masked" when masked,
        # "alias" in the default state, etc. Match on the first token only.
        return self._run_check(["systemctl", "is-enabled", "ctrl-alt-del.target"],
                               lambda o: o.strip().startswith("masked"))


# ── Dedicated Lynis output panel ──────────────────────────────────────────────
class LynisPanel(QWidget, WorkerMixin):
    """Shows Lynis audit results in a dedicated scrollable panel.
    Separate from the terminal so Lynis output is easy to read.
    Results are also added to the findings table."""

    def __init__(self, terminal, findings):
        super().__init__()
        self._init_workers()
        self.terminal = terminal
        self.findings = findings

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hdr = QLabel("LYNIS SECURITY AUDIT")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel(
            "Lynis is an industry-standard security auditing tool that checks your OS "
            "configuration against security best practices. Takes approximately 60 seconds."
        )
        info.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.status = QLabel("Click 'Run Lynis Audit' on the left to start.")
        self.status.setObjectName("status")
        layout.addWidget(self.status)

        # Dedicated output area for Lynis results
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText(
            "Lynis audit results will appear here...\n\n"
            "Results are also added to the FINDINGS tab above."
        )
        layout.addWidget(self.output)

    def _lappend(self, text, colour=None):
        """Append a line to the Lynis output panel."""
        text = strip_ansi(text)
        if not text.strip():
            return
        cur = self.output.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        fmt = cur.charFormat()
        fmt.setForeground(QColor(colour or T["TEXT_MAIN"]))
        cur.setCharFormat(fmt)
        cur.insertText(text + "\n")
        self.output.setTextCursor(cur)
        self.output.ensureCursorVisible()

    def _get_sudo_password(self, reason_text, force_prompt=False):
        """
        Return sudo password bytes if needed, b'' if cached, or None if cancelled.
        If force_prompt=True, always show the password dialog in the foreground.
        """
        if not force_prompt and check_sudo_cached():
            return b""
        pw, ok = QInputDialog.getText(
            self,
            "Administrator Password Required",
            f"{reason_text}\n\nYour password is used once and never stored.",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            self.status.setText("Action cancelled.")
            self.terminal.append_err("Action cancelled — sudo password not provided.")
            return None
        return pw.encode()

    def run_lynis(self, on_complete=None):
        """Check if Lynis is installed, offer to install it, then run the audit."""
        if not shutil.which("lynis"):
            reply = QMessageBox.question(
                self, "Install Lynis?",
                "Lynis is not installed.\n\nInstall it now? (requires sudo)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                sudo_password = self._get_sudo_password(
                    "Installing Lynis requires your sudo (administrator) password.",
                    force_prompt=True
                )
                if sudo_password is None:
                    return
                self.status.setText("Installing Lynis...")
                w = CommandWorker(
                    ["apt", "install", "lynis", "-y"],
                    sudo=True,
                    timeout=120,
                    password=sudo_password
                )
                w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
                w.error_ready.connect(self.terminal.append_err)
                w.finished_ok.connect(lambda: self.run_lynis(on_complete=on_complete))  # Retry after install
                self._start_worker(w)
            return

        sudo_password = self._get_sudo_password(
            "Running a Lynis audit requires your sudo (administrator) password.",
            force_prompt=True
        )
        if sudo_password is None:
            return

        self.output.clear()
        self.status.setText("Running Lynis audit — please wait approximately 60 seconds...")
        self.terminal.append_cmd("sudo lynis audit system --quick")
        self._lappend("Running Lynis security audit...", T["ACCENT"])
        self._lappend("This checks your system against security best practices.\n", T["TEXT_DIM"])

        w = CommandWorker(
            ["lynis", "audit", "system", "--quick"],
            sudo=True,
            timeout=200,
            password=sudo_password
        )
        w.output_ready.connect(self._parse_lynis_output)
        w.error_ready.connect(lambda t: self._lappend(t, T["DANGER"]))
        w.finished_ok.connect(lambda: self.status.setText("Lynis audit complete — see results above."))
        if on_complete:
            w.finished_ok.connect(on_complete)
        self._start_worker(w)

    def _parse_lynis_output(self, text):
        """Parse Lynis output and display results. Try the structured log file
        first (gives cleaner results), fall back to parsing raw output."""
        self.output.clear()
        text = strip_ansi(text)

        # Try reading the structured Lynis log file first
        try:
            with open("/var/log/lynis.log") as f:
                log = f.read()
            warns = []; suggs = []; idx = None
            for line in log.splitlines():
                if "|WARNING|" in line:
                    p = line.split("|")
                    if len(p) > 2:
                        warns.append(p[-1].strip())
                elif "|SUGGESTION|" in line:
                    p = line.split("|")
                    if len(p) > 2:
                        suggs.append(p[-1].strip())
                m = re.search(r"hardening_index=(\d+)", line, re.I)
                if m:
                    idx = int(m.group(1))

            if idx is not None:
                colour = T["OK"] if idx > 70 else (T["WARN"] if idx > 40 else T["DANGER"])
                self._lappend(f"  Lynis Hardening Index: {idx} / 100", colour)
                self._lappend(
                    "  (70+ is good, 85+ is excellent)", T["TEXT_DIM"]
                )

            self._lappend(f"\n── WARNINGS ({len(warns)}) ──", T["WARN"])
            for w in warns:
                self._lappend(f"  ⚠  {w}", T["WARN"])
                self.findings.add_finding(
                    w[:60], "HARDENING", "MEDIUM",
                    f"Lynis warning: {w}"
                )

            self._lappend(f"\n── SUGGESTIONS ({len(suggs)}) ──", T["TEXT_DIM"])
            for s in suggs[:20]:
                self._lappend(f"  ℹ  {s}", T["TEXT_DIM"])
                self.findings.add_finding(
                    s[:60], "HARDENING", "LOW",
                    f"Lynis suggestion: {s}"
                )

            SESSION.log_scan("Lynis Full Audit", len(warns))
            return

        except FileNotFoundError:
            pass  # Log file not available — fall back to parsing raw output
        except PermissionError:
            # Common when app is not run as root — not an app fault.
            self._lappend(
                "  ℹ  Could not read /var/log/lynis.log (permission denied). "
                "Parsing live output instead.",
                T["TEXT_DIM"]
            )
        except Exception as e:
            logging.error(f"Lynis log parse error: {e}")

        # Fallback: parse the raw output text
        warn_count = 0
        sugg_count = 0
        summary_warns = None
        summary_suggs = None
        for line in text.splitlines():
            clean = strip_ansi(line).strip()
            if not clean:
                continue
            mw = re.search(r"\bWarnings?\b\s*[:=]\s*(\d+)", clean, re.I)
            if mw:
                summary_warns = int(mw.group(1))
            ms = re.search(r"\bSuggestions?\b\s*[:=]\s*(\d+)", clean, re.I)
            if ms:
                summary_suggs = int(ms.group(1))

            # Treat explicit warning lines as findings (case-insensitive).
            # Skip summary counter lines like "Warnings : 5".
            if re.search(r"\bwarning\b", clean, re.I) and not mw:
                self._lappend(f"  ⚠  {clean}", T["WARN"])
                warn_count += 1
                self.findings.add_finding(
                    clean[:60], "HARDENING", "MEDIUM", clean
                )
            elif re.search(r"\bsuggestion\b", clean, re.I) and not ms:
                self._lappend(f"  ℹ  {clean}", T["TEXT_DIM"])
                sugg_count += 1
            # Try to extract hardening index from raw output
            m = re.search(r"Hardening index\s*[:\|]\s*(\d+)", clean, re.I)
            if m:
                idx = int(m.group(1))
                colour = T["OK"] if idx > 70 else (T["WARN"] if idx > 40 else T["DANGER"])
                self._lappend(f"\n  Lynis Hardening Index: {idx} / 100", colour)

        final_warns = summary_warns if summary_warns is not None else warn_count
        final_suggs = summary_suggs if summary_suggs is not None else sugg_count
        if summary_warns is not None and warn_count == 0 and summary_warns > 0:
            self._lappend(
                "  ℹ  Lynis reported warnings in summary; detailed warning lines were not exposed in live output.",
                T["TEXT_DIM"]
            )
        self._lappend(f"\n── WARNINGS ({final_warns}) | SUGGESTIONS ({final_suggs}) ──", T["ACCENT"])
        SESSION.log_scan("Lynis Full Audit", final_warns)


# ── Dedicated CVE results panel ───────────────────────────────────────────────
class CvePanel(QWidget, WorkerMixin):
    """Shows CVE vulnerability check results in a dedicated table.
    Separate from the main findings table so you can see per-package
    CVE counts and severity at a glance."""

    # The key packages we check — these are high-value targets for attackers
    HIGH_VALUE_PKGS = [
        "openssh-server","openssh-client","openssl","sudo","bash","curl","wget",
        "python3","perl","apache2","nginx","samba","rsync","git","docker.io",
        "containerd","postgresql","mysql-server","sqlite3","firefox","libc6",
        "libssl3","libssl1.1","gpg","gnupg","apt","nfs-common",
    ]

    def __init__(self, terminal, findings):
        super().__init__()
        self._init_workers()
        self.terminal = terminal
        self.findings = findings
        self._scan_cve_done_cb = None
        self._scan_upgrades_done_cb = None
        self._cve_scan_serial = 0
        self._cve_active_scan_id = 0
        self._cve_total = 0
        self._cve_ok = 0
        self._cve_timeout = 0
        self._cve_network = 0
        self._cve_error = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hdr = QLabel("CVE VULNERABILITY CHECK")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel(
            "Checks your installed packages against Ubuntu's live CVE security database.\n"
            "Requires an internet connection. Only checks important system packages."
        )
        info.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.status = QLabel("Click 'Check for Known Vulnerabilities' on the left to start.")
        self.status.setObjectName("status")
        layout.addWidget(self.status)

        # CVE results table — one row per package
        self.cve_table = QTableWidget()
        self.cve_table.setColumnCount(4)
        self.cve_table.setHorizontalHeaderLabels(
            ["PACKAGE", "YOUR VERSION", "CVE COUNT", "HIGHEST SEVERITY"]
        )
        ch = self.cve_table.horizontalHeader()
        for i in range(4):
            ch.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
        self.cve_table.setColumnWidth(0, 220)
        self.cve_table.setColumnWidth(1, 260)
        self.cve_table.setColumnWidth(2, 120)
        self.cve_table.setColumnWidth(3, 260)
        ch.setStretchLastSection(False)
        self.cve_table.verticalHeader().setVisible(False)
        self.cve_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cve_table.setAlternatingRowColors(True)
        layout.addWidget(self.cve_table)

    def _get_installed_version(self, pkg):
        """Get the installed version of a package. Returns None if not installed."""
        if PKG_MGR != "apt":
            return None
        try:
            r = subprocess.run(
                ["dpkg-query", "-W", f"-f=${{Version}}", pkg],
                capture_output=True, text=True, timeout=5
            )
            v = r.stdout.strip()
            return v if r.returncode == 0 and v else None
        except Exception:
            return None

    def scan_cve(self, on_complete=None):
        """Find installed packages and check them against the CVE database."""
        self._scan_cve_done_cb = on_complete
        self._cve_scan_serial += 1
        scan_id = self._cve_scan_serial
        self._cve_active_scan_id = scan_id
        self.cve_table.setRowCount(0)
        self.status.setText("Finding installed packages to check...")
        self.terminal.append_cmd("# CVE check — querying Ubuntu security database")

        # Build list of (package, version) for packages that are actually installed
        targets = [
            (pkg, ver) for pkg in self.HIGH_VALUE_PKGS
            if (ver := self._get_installed_version(pkg))
        ]

        if not targets:
            self.status.setText("No packages found to check on this system.")
            return

        self._cve_total = len(targets)
        self._cve_ok = 0
        self._cve_timeout = 0
        self._cve_network = 0
        self._cve_error = 0

        self.status.setText(
            f"Querying CVE database for {len(targets)} packages — please wait..."
        )
        self.terminal.append_info(f"Checking {len(targets)} packages...")

        w = HttpWorker(targets)
        w.result_ready.connect(
            lambda pkg, data, sid=scan_id: self._handle_cve_result(pkg, data, sid)
        )
        w.finished_ok.connect(lambda sid=scan_id: self._finish_cve_scan(sid))
        self._start_worker(w)
        SESSION.log_scan("CVE Vulnerability Check", 0)

    def _handle_cve_result(self, pkg, data, scan_id):
        """Process one package's CVE results and add to the table."""
        if scan_id != self._cve_active_scan_id:
            return
        if data is None:
            self._cve_error += 1
            self.terminal.append_info(f"Could not check: {pkg}")
            return

        version, cve_data = data
        if isinstance(cve_data, dict) and cve_data.get("_error"):
            err = cve_data.get("_error")
            if err == "timeout":
                self._cve_timeout += 1
                self.terminal.append_info(f"Could not check: {pkg} (network timeout)")
            elif err == "network":
                self._cve_network += 1
                self.terminal.append_info(f"Could not check: {pkg} (network unavailable)")
            else:
                self._cve_error += 1
                self.terminal.append_info(f"Could not check: {pkg} (request failed)")
            return

        self._cve_ok += 1
        cves    = cve_data.get("cves", [])
        count   = len(cves)
        highest = "none"

        # Find the highest severity level across all CVEs for this package
        for sev in ["critical", "high", "medium", "low", "negligible"]:
            if any(c.get("cvss_severity", "").lower() == sev for c in cves):
                highest = sev
                break

        sev_colour = {
            "critical": T["DANGER"], "high": T["DANGER"],
            "medium":   T["WARN"],   "low":  T["OK"],
            "negligible": T["TEXT_DIM"], "none": T["TEXT_DIM"],
        }.get(highest, T["TEXT_DIM"])

        # Add to the CVE table
        row = self.cve_table.rowCount()
        self.cve_table.insertRow(row)
        self.cve_table.setItem(row, 0, QTableWidgetItem(pkg))
        self.cve_table.setItem(row, 1, QTableWidgetItem(version))

        count_item = QTableWidgetItem(str(count))
        if count > 0:
            count_item.setForeground(QColor(T["WARN"] if count < 5 else T["DANGER"]))
        self.cve_table.setItem(row, 2, count_item)

        sev_icon = "🔴 ✖" if highest in ("critical","high") else "🟡 ▲" if highest == "medium" else "🟢 ●"
        sev_item = QTableWidgetItem(f"{sev_icon} {highest.upper()}")
        sev_item.setForeground(QColor(sev_colour))
        self.cve_table.setItem(row, 3, sev_item)
        self.cve_table.setRowHeight(row, 32)

        # Add HIGH/CRITICAL packages to the main findings table
        if highest in ("critical", "high") and count > 0:
            risk = "HIGH" if highest == "critical" else "MEDIUM"
            self.findings.add_finding(
                pkg, "CVE", risk,
                f"{count} known vulnerabilities — highest: {highest.upper()} "
                f"(your version: {version})",
                f"apt-get upgrade {pkg}"
            )
            self.terminal.append_warn(
                f"{pkg} ({version}): {count} CVEs — highest: {highest.upper()}"
            )

    def _finish_cve_scan(self, scan_id):
        """Show clearer completion summary including failure reasons."""
        if scan_id != self._cve_active_scan_id:
            return
        total = max(1, self._cve_total)
        failed = self._cve_total - self._cve_ok
        self.status.setText(
            f"CVE check complete — {self._cve_ok}/{self._cve_total} packages checked successfully."
        )
        if failed > 0:
            self.terminal.append_info(
                f"CVE check summary: {self._cve_ok}/{total} succeeded, {failed} failed "
                f"(timeouts: {self._cve_timeout}, network: {self._cve_network}, other: {self._cve_error})."
            )
        if self._scan_cve_done_cb:
            try:
                self._scan_cve_done_cb()
            finally:
                self._scan_cve_done_cb = None

    def cancel_active_scan(self):
        """Invalidate current CVE scan and cancel in-flight HTTP workers."""
        self._cve_scan_serial += 1
        self._cve_active_scan_id = self._cve_scan_serial
        for w in list(self._workers):
            if isinstance(w, HttpWorker):
                w.cancel()

    def scan_upgrades(self, on_complete=None):
        """Check which packages have newer versions available.
        Uses DEBIAN_FRONTEND=noninteractive so apt never waits for user input."""
        self._scan_upgrades_done_cb = on_complete
        self.terminal.append_cmd("apt list --upgradable")
        self.status.setText("Checking for available updates...")

        w = CommandWorker(
            ["apt", "list", "--upgradable"],
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        )
        w.output_ready.connect(self._parse_upgrades)
        w.error_ready.connect(self.terminal.append_err)
        w.finished_ok.connect(lambda: self.status.setText("Update check complete."))
        w.finished_ok.connect(self._finish_upgrades_scan)
        self._start_worker(w)

    def _finish_upgrades_scan(self):
        """Finalize updates scan callback."""
        if self._scan_upgrades_done_cb:
            try:
                self._scan_upgrades_done_cb()
            finally:
                self._scan_upgrades_done_cb = None

    def _parse_upgrades(self, text):
        """Parse apt upgrade output and add outdated packages to findings.
        apt list --upgradable lines look like:
          pkg/noble-updates 1.2.3 amd64 [upgradable from: 1.2.2]
        The old filter excluded any line containing 'upgradable' which removed
        every result. Now we skip only the plain 'Listing...' header line."""
        lines = [
            l for l in text.splitlines()
            if "/" in l and not l.startswith("Listing")
        ]
        self.terminal.append_info(f"{len(lines)} packages have updates available.")
        for line in lines[:30]:
            pkg = line.split("/")[0].strip()
            if valid_pkg(pkg):
                self.findings.add_finding(
                    pkg, "OUTDATED", "LOW",
                    "A newer version is available — consider updating",
                    f"apt-get upgrade {pkg}"
                )
        if len(lines) > 30:
            self.terminal.append_info(f"...and {len(lines)-30} more (showing first 30)")
        SESSION.log_scan("Check for Updates", len(lines))


# ── Recommended tools panel ───────────────────────────────────────────────────
class ToolCard(QFrame):
    """A single card showing one recommended security/monitoring tool.
    Shows: name, category, description, install status, and action buttons."""

    def __init__(self, tool_data, terminal):
        super().__init__()
        self.tool     = tool_data
        self.terminal = terminal
        self._workers = set()

        # Background/border handled via make_style() #tool_card — no inline style needed
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName("tool_card")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        # Category colour badge
        cat_colours = {
            "Security":   T["DANGER"],
            "Monitoring": T["ACCENT"],
            "Health":     T["OK"],
            "Network":    T["WARN"],
            "Backup":     T["OK"],
            "Storage":    T["WARN"],
        }
        cat_lbl = QLabel(tool_data["cat"])
        cat_lbl.setFixedWidth(75)
        cat_lbl.setStyleSheet(
            f"color:{cat_colours.get(tool_data['cat'], T['TEXT_DIM'])};"
            f"font-size:{fs(-2)}px;font-weight:bold;"
        )
        layout.addWidget(cat_lbl)

        # Name and description
        info_col = QVBoxLayout()
        info_col.setSpacing(2)
        name_lbl = QLabel(tool_data["name"])
        name_lbl.setStyleSheet(
            f"color:{T['TEXT_MAIN']};font-weight:bold;font-size:{fs()}px;"
        )
        info_col.addWidget(name_lbl)
        desc_lbl = QLabel(tool_data["desc"])
        desc_lbl.setStyleSheet(
            f"color:{T['TEXT_DIM']};font-size:{fs(-2)}px;"
        )
        desc_lbl.setWordWrap(True)
        info_col.addWidget(desc_lbl)
        layout.addLayout(info_col, 1)

        # Install status indicator
        self.status_lbl = QLabel("Checking...")
        self.status_lbl.setFixedWidth(90)
        self.status_lbl.setStyleSheet(f"font-size:{fs(-2)}px;")
        layout.addWidget(self.status_lbl)

        # Action buttons
        btn_col = QVBoxLayout()
        btn_col.setSpacing(3)

        self.install_btn = QPushButton("INSTALL")
        self.install_btn.setObjectName("ok")
        self.install_btn.setFixedSize(90, 26)
        self.install_btn.setToolTip(f"Install {tool_data['name']} using {PKG_MGR}")
        self.install_btn.clicked.connect(self._install)
        btn_col.addWidget(self.install_btn)

        how_btn = QPushButton("HOW TO USE")
        how_btn.setObjectName("neutral")
        how_btn.setFixedSize(90, 26)
        how_btn.setToolTip(f"Show setup and usage guide for {tool_data['name']}")
        how_btn.clicked.connect(self._show_how_to_use)
        btn_col.addWidget(how_btn)

        run_btn = QPushButton("RUN NOW")
        run_btn.setObjectName("neutral")
        run_btn.setFixedSize(90, 26)
        run_btn.setToolTip(f"Run {tool_data['name']} now in the terminal")
        run_btn.clicked.connect(self._run_tool)
        btn_col.addWidget(run_btn)

        layout.addLayout(btn_col)
        self._check_installed()

    def _check_installed(self):
        """Update the install status label based on whether the tool is installed."""
        installed = pkg_installed(self.tool["name"])
        if installed:
            self.status_lbl.setText("✔ Installed")
            self.status_lbl.setStyleSheet(
                f"color:{T['OK']};font-size:{fs(-2)}px;font-weight:bold;"
            )
            self.install_btn.setText("REINSTALL")
        else:
            self.status_lbl.setText("✗ Not installed")
            self.status_lbl.setStyleSheet(
                f"color:{T['TEXT_DIM']};font-size:{fs(-2)}px;"
            )

    def _install(self):
        """Install the tool with confirmation."""
        cmd = pkg_install(self.tool["name"])
        if QMessageBox.question(
            self, f"Install {self.tool['name']}?",
            f"Install '{self.tool['name']}'?\n\nRuns: sudo {' '.join(cmd)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        self.terminal.append_cmd(f"sudo {' '.join(cmd)}")
        w = CommandWorker(cmd, sudo=True, timeout=180)
        w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
        w.error_ready.connect(self.terminal.append_err)
        w.finished_ok.connect(self._check_installed)
        # Track worker manually for this simple case
        w.finished.connect(lambda: self._workers.discard(w))
        self._workers.add(w)
        w.start()

    def _show_how_to_use(self):
        """Show a popup with setup and usage instructions for the tool."""
        t = self.tool
        dlg = QDialog(self)
        dlg.setWindowTitle(f"How to use: {t['name']}")
        dlg.setMinimumWidth(520)
        layout = QVBoxLayout(dlg)
        title = QLabel(f"🧰  {t['name']} — {t['cat']}")
        title.setStyleSheet(
            f"color:{T['ACCENT']};font-size:{fs(1)}px;font-weight:bold;"
        )
        layout.addWidget(title)
        for section, content in [
            ("📌 What it does:",           t["desc"]),
            ("💡 Why you want it:",        t["why"]),
            ("⚙️  How to set it up:",       t["setup"]),
            ("✅ How to check it works:",   t["verify"]),
            ("▶  Run it with:",            t["run"]),
        ]:
            sl = QLabel(section)
            sl.setStyleSheet(
                f"color:{T['ACCENT']};font-weight:bold;font-size:{fs()}px;margin-top:6px;"
            )
            layout.addWidget(sl)
            cl = QLabel(content)
            cl.setWordWrap(True)
            cl.setStyleSheet(
                f"color:{T['TEXT_MAIN']};padding-left:12px;font-size:{fs(-1)}px;"
            )
            layout.addWidget(cl)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.close)
        layout.addWidget(btns)
        dlg.exec()

    def _run_tool(self):
        """Run the tool in the terminal panel."""
        cmd_parts = self.tool["run"].split()
        use_sudo  = self.tool.get("safe_run", False)
        self.terminal.append_cmd(
            ("sudo " if use_sudo else "") + self.tool["run"]
        )
        w = CommandWorker(cmd_parts, sudo=use_sudo, timeout=30)
        w.output_ready.connect(lambda t: self.terminal.append(t))
        w.error_ready.connect(self.terminal.append_err)
        w.finished.connect(lambda: self._workers.discard(w))
        self._workers.add(w)
        w.start()


class ToolsPanel(QWidget):
    """Shows the 15 recommended tools as a scrollable card list.
    Users can install, see setup instructions, and run tools directly."""

    def __init__(self, terminal):
        super().__init__()
        self.terminal = terminal

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hdr = QLabel(L("sec_tools"))
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel(L("sec_tools_sub"))
        info.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        layout.addWidget(info)

        # Filter box to find tools quickly
        hrow = QHBoxLayout()
        filter_box = QLineEdit()
        filter_box.setPlaceholderText("Filter tools by name or category...")
        filter_box.setFixedWidth(240)
        filter_box.textChanged.connect(self._filter)
        hrow.addWidget(filter_box)
        hrow.addStretch()
        layout.addLayout(hrow)

        # Scrollable card list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border:none;")
        container = QWidget()
        self.cards_layout = QVBoxLayout(container)
        self.cards_layout.setSpacing(4)
        self.cards = []

        for tool in TOOLS_DATA:
            card = ToolCard(tool, terminal)
            self.cards_layout.addWidget(card)
            self.cards.append(card)

        self.cards_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)

    def _filter(self, text):
        """Show only tool cards matching the filter text."""
        text = text.lower()
        for card in self.cards:
            matches = (
                text in card.tool["name"].lower() or
                text in card.tool["cat"].lower() or
                text in card.tool["desc"].lower()
            )
            card.setVisible(not text or matches)


# ── Undo / Rollback panel (lives inside the main tab widget) ──────────────────
class UndoPanel(QWidget, WorkerMixin):
    """Shows the undo/rollback log inside the main app panel.
    Updates live when actions are taken — no popup required.
    Previous session actions are loaded from disk on startup."""

    def __init__(self, terminal):
        super().__init__()
        self._init_workers()
        self.terminal = terminal

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hdr_row = QHBoxLayout()
        hdr = QLabel(L("sec_undo"))
        hdr.setObjectName("heading")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        layout.addLayout(hdr_row)

        info = QLabel(
            "Everything this app has done to your system is listed here. "
            "Click any row to see the full risk explanation. "
            "Click UNDO to reverse an action.\n"
            "Actions from previous sessions are shown in grey."
        )
        info.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # The undo table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["DATE & TIME", "ACTION TAKEN", "COMMAND RAN", "RISK LEVEL", "UNDO"]
        )
        hh = self.table.horizontalHeader()
        for col in range(5):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 170)
        self.table.setColumnWidth(1, 220)
        self.table.setColumnWidth(2, 420)
        self.table.setColumnWidth(3, 120)
        self.table.setColumnWidth(4, 160)
        hh.setStretchLastSection(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.cellClicked.connect(self._show_detail)
        layout.addWidget(self.table)

        # Empty state label — shown when nothing has been done yet
        self.empty_label = QLabel(
            "No actions taken yet — actions appear here automatically as you fix things."
        )
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet(
            f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;padding:32px;"
        )
        self.empty_label.setWordWrap(True)
        layout.addWidget(self.empty_label)

        # Detail panel — expands when a row is clicked
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(160)
        self.detail.setPlaceholderText(
            "Click any row above to see the full rollback explanation and risk details..."
        )
        layout.addWidget(self.detail)

        # Load previous session entries on startup
        self._load_previous_sessions()
        # Show empty state if nothing loaded
        self._update_empty_state()

    def _update_empty_state(self):
        """Show the empty-state label when the table has no rows, hide it otherwise."""
        empty = self.table.rowCount() == 0
        self.empty_label.setVisible(empty)
        self.table.setVisible(not empty)

    def _load_previous_sessions(self):
        """Load undo entries from previous sessions (from disk)."""
        for entry in load_undo_log():
            self._add_row(entry, from_prev_session=True)

    def add_live_entry(self, entry):
        """Add a new entry from the current session — live update."""
        self._add_row(entry, from_prev_session=False)

    def _add_row(self, entry, from_prev_session=False):
        """Add one row to the undo table."""
        row = self.table.rowCount()
        self.table.insertRow(row)

        risk_level = entry.get("risk_level", "LOW")
        risk_colour = {
            "HIGH":   T["DANGER"],
            "MEDIUM": T["WARN"],
            "LOW":    T["OK"],
        }.get(risk_level, T["TEXT_DIM"])

        risk_display = {
            "HIGH":   "🔴 ✖ HIGH RISK",
            "MEDIUM": "🟡 ▲ MEDIUM RISK",
            "LOW":    "🟢 ● LOW RISK",
        }.get(risk_level, "LOW RISK")

        # Add text to time with session note
        session_note = " (prev)" if from_prev_session else " (now)"
        time_text    = entry.get("time", "") + session_note

        dim_colour = T["TEXT_DIM"] if from_prev_session else T["TEXT_MAIN"]

        for col, val in enumerate([
            time_text,
            entry.get("action", ""),
            entry.get("cmd", ""),
            risk_display,
        ]):
            item = QTableWidgetItem(val)
            if col == 3:
                item.setForeground(QColor(risk_colour))
                item.setFont(QFont("", fs(-2), QFont.Weight.Bold))
            else:
                item.setForeground(QColor(dim_colour))
            self.table.setItem(row, col, item)

        # Store the full entry dict for the detail view
        self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, entry)

        # UNDO button cell
        cell = QWidget()
        cell.setStyleSheet("background:transparent;")
        bl = QHBoxLayout(cell)
        bl.setContentsMargins(4, 2, 4, 2)

        undo_cmd = entry.get("undo_cmd", "N/A")
        if undo_cmd != "N/A":
            is_high = risk_level == "HIGH"
            ub = QPushButton("⚠️ UNDO (HIGH RISK)" if is_high else "↩  UNDO")
            ub.setObjectName("danger" if is_high else "warn")
            ub.setFixedHeight(26)
            ub.setToolTip(
                "WARNING: Read the risk details below before rolling this back"
                if is_high else
                "Reverse this action"
            )
            ub.clicked.connect(lambda _, e=entry: self._run_undo(e))
            bl.addWidget(ub)
        else:
            nl = QLabel("No undo")
            nl.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-2)}px;")
            bl.addWidget(nl)

        bl.addStretch()
        self.table.setCellWidget(row, 4, cell)
        self.table.setRowHeight(row, 38)
        self._update_empty_state()

    def _show_detail(self, row, col):
        """Show the three-part rollback explanation when a row is clicked."""
        item = self.table.item(row, 0)
        if not item:
            return
        entry = item.data(Qt.ItemDataRole.UserRole)
        if not entry:
            return

        risk_level = entry.get("risk_level", "LOW")
        risk_icon  = {"HIGH":"🔴 ✖","MEDIUM":"🟡 ▲","LOW":"🟢 ●"}.get(risk_level,"●")

        lines = [
            f"ACTION:         {entry.get('action', '')}",
            f"COMMAND RAN:    {entry.get('cmd', '')}",
            f"UNDO COMMAND:   {entry.get('undo_cmd', 'N/A')}",
            "",
            f"── What rollback will do ──",
            entry.get("rollback_does", "Not available"),
            "",
            f"── {risk_icon} Risk that returns ──",
            entry.get("rollback_risk", "Not available"),
            "",
            f"── 🎯 How it could be used against you ──",
            entry.get("rollback_exploit", "Not available"),
        ]
        self.detail.setPlainText("\n".join(lines))

    def _run_undo(self, entry):
        """Run the undo command after showing a confirmation with risk warning."""
        risk_level = entry.get("risk_level", "LOW")
        warning = ""
        if risk_level == "HIGH":
            warning = (
                f"\n\n⚠️  WARNING — HIGH RISK ROLLBACK\n"
                f"{entry.get('rollback_risk', '')}\n\n"
                f"Are you absolutely sure?"
            )

        if QMessageBox.question(
            self, "Confirm Rollback",
            f"Run: {entry['undo_cmd']}\n\n"
            f"This reverses: {entry['action']}{warning}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        self.terminal.append_cmd(entry["undo_cmd"])
        cmd = entry["undo_cmd"].replace("sudo ", "").split()
        w = CommandWorker(cmd, sudo=True)
        w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
        w.error_ready.connect(self.terminal.append_err)
        w.finished_ok.connect(
            lambda: self._remove_undo_entry_after_rollback(entry)
        )
        self._start_worker(w)

    def _remove_undo_entry_after_rollback(self, entry):
        """Remove the row from the undo table after a successful rollback."""
        self.terminal.append_ok(f"Rollback complete: {entry['action']}")
        # Find and remove the matching row
        for r in range(self.table.rowCount() - 1, -1, -1):
            item = self.table.item(r, 0)
            if item:
                stored = item.data(Qt.ItemDataRole.UserRole)
                if stored and stored.get("time") == entry.get("time"):
                    self.table.removeRow(r)
                    break

# ── Left sidebar navigation ───────────────────────────────────────────────────
class SideBar(QWidget, WorkerMixin):
    """The left navigation panel. Contains all scan/check buttons grouped
    into labelled sections with subtitles explaining what each section does.
    Clicking any button clears previous results and shows 'Please wait'
    before populating both findings and terminal with results."""

    def __init__(self, terminal, findings, lynis_panel, cve_panel,
                 tools_panel, undo_panel, tabs, online_mode=True):
        super().__init__()
        self._init_workers()
        self.terminal    = terminal
        self.findings    = findings
        self.lynis_panel = lynis_panel
        self.cve_panel   = cve_panel
        self.tools_panel = tools_panel
        self.undo_panel  = undo_panel
        self.stack       = tabs        # QStackedWidget: 0=findings,1=cve,2=lynis,3=tools,4=undo
        self.online_mode = online_mode
        self._pending_section_action = None
        self._section_headers = {}   # section_id -> (button, title_key)
        self._section_done = {
            "scan": set(),
            "checks": set(),
            "cve": set(),
            "tools": set(),
            "undo": set(),
        }
        self._section_required = {
            "scan": {"unused", "network", "services", "os_installed", "user_installed"},
            "checks": {"quick", "lynis", "wizard"},
            "cve": {"cve", "upgrades"} if online_mode else set(),
            "tools": {"tools"},
            "undo": {"undo"},
        }

        self.setFixedWidth(252)
        self.setObjectName("sidebar_widget")

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Scrollable menu area so controls never overlap on smaller window heights
        menu_scroll = QScrollArea()
        menu_scroll.setWidgetResizable(True)
        menu_scroll.setFrameShape(QFrame.Shape.NoFrame)
        menu_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        menu_host = QWidget()
        layout = QVBoxLayout(menu_host)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        menu_scroll.setWidget(menu_host)
        root_layout.addWidget(menu_scroll, 1)

        # ── Helper: collapsible section header ───────────────────────────
        def section(section_id, title_key, sub_key):
            """Create a collapsible section. Starts collapsed on every app launch."""
            is_expanded = False

            # Outer container holding header + content
            outer = QWidget()
            outer_l = QVBoxLayout(outer)
            outer_l.setContentsMargins(0, 0, 0, 0)
            outer_l.setSpacing(0)

            # Header button (acts as a toggle) — styled via make_style() #section_btn
            arrow   = "▼" if is_expanded else "▶"
            hdr_btn = QPushButton(f"{arrow}  {L(title_key)}")
            hdr_btn.setObjectName("section_btn")
            sub_lbl = QLabel(L(sub_key))
            sub_lbl.setObjectName("section_sub")
            sub_lbl.setWordWrap(True)

            # Content container — buttons go inside here
            content   = QWidget()
            content_l = QVBoxLayout(content)
            content_l.setContentsMargins(0, 0, 0, 0)
            content_l.setSpacing(0)
            content.setVisible(is_expanded)
            sub_lbl.setVisible(is_expanded)

            def _toggle(_checked=False, _title=title_key, _btn=hdr_btn,
                        _sub_lbl=sub_lbl, _content=content):
                now_expanded = not _content.isVisible()
                _content.setVisible(now_expanded)
                _sub_lbl.setVisible(now_expanded)
                self._update_section_header(section_id, now_expanded)

            hdr_btn.clicked.connect(_toggle)
            outer_l.addWidget(hdr_btn)
            outer_l.addWidget(sub_lbl)
            outer_l.addWidget(content)
            layout.addWidget(outer)
            self._section_headers[section_id] = (hdr_btn, title_key)
            self._update_section_header(section_id, is_expanded)
            return content_l

        # ── Helper: add a button into a section content layout ────────────
        def btn(label_key, tooltip, handler, parent_layout=None,
                style="section_btn", shortcut=None):
            b = QPushButton(L(label_key))
            b.setObjectName(style)
            b.setFixedHeight(42)
            b.setToolTip(tooltip)
            b.clicked.connect(handler)
            if shortcut:
                b.setShortcut(QKeySequence(shortcut))
                b.setToolTip(f"{tooltip} [{shortcut}]")
            target = parent_layout if parent_layout is not None else layout
            target.addWidget(b)
            return b

        # ── SCAN YOUR SYSTEM ──────────────────────────────────────────────
        sec_scan = section("scan", "sec_scan", "sec_scan_sub")
        btn("btn_unused",
            "Finds software installed as part of something else that is now "
            "just sitting there — leftovers from old installs",
            self._scan_unused, parent_layout=sec_scan, shortcut="Ctrl+1")
        btn("btn_network",
            "Shows every open network port and which program owns it",
            self._scan_network, parent_layout=sec_scan, shortcut="Ctrl+2")
        btn("btn_services",
            "Checks for known insecure or unnecessary services",
            self._scan_services, parent_layout=sec_scan, shortcut="Ctrl+3")
        btn("btn_os_installed",
            "Packages that came pre-installed with your OS — not installed by you",
            self._scan_os_installed, parent_layout=sec_scan)
        btn("btn_user_installed",
            "Packages you deliberately installed — via apt install or a GUI store",
            self._scan_user_installed, parent_layout=sec_scan)
        btn("btn_fullscan",
            "Runs all scans above in one go — the best place to start",
            self._run_full_scan, parent_layout=sec_scan, style="ok", shortcut="Ctrl+R")

        # ── SECURITY CHECKS ───────────────────────────────────────────────
        sec_checks = section("checks", "sec_checks", "sec_checks_sub")
        btn("btn_quick",
            "Checks firewall, SSH, core dumps, ASLR — takes about 5 seconds",
            self._quick_checks, parent_layout=sec_checks, shortcut="Ctrl+4")
        btn("btn_lynis",
            "Full industry-standard Lynis security audit — takes about 60 seconds",
            self._run_lynis, parent_layout=sec_checks)
        btn("btn_wizard",
            "Guided step-by-step walkthroughs for common security fixes",
            self._guided_wizard, parent_layout=sec_checks)

        # ── CVE VULNERABILITY CHECK ───────────────────────────────────────
        sec_cve = section("cve", "sec_cve", "sec_cve_sub")
        if online_mode:
            btn("btn_cve",
                "Checks installed packages against Ubuntu's live vulnerability database",
                self._scan_cve, parent_layout=sec_cve, shortcut="Ctrl+5")
            btn("btn_upgrades",
                "Shows packages that have newer versions available",
                self._scan_upgrades, parent_layout=sec_cve)
        else:
            # Offline mode — CVE checks need internet so just show a notice
            notice = QLabel(
                "  ℹ  CVE checks require\n  an internet connection.\n  (Offline Mode)"
            )
            notice.setStyleSheet(
                f"color:{T['TEXT_DIM']};font-size:{fs(-2)}px;padding:8px;"
            )
            sec_cve.addWidget(notice)

        # ── RECOMMENDED TOOLS ─────────────────────────────────────────────
        sec_tools = section("tools", "sec_tools", "sec_tools_sub")
        btn("btn_tools",
            "Shows the 15 recommended security and monitoring tools",
            self._show_tools, parent_layout=sec_tools)

        # ── UNDO / ROLLBACK ───────────────────────────────────────────────
        sec_undo = section("undo", "sec_undo", "sec_undo_sub")
        btn("btn_undo",
            "Shows everything this app has done and lets you reverse any action",
            self._show_undo, parent_layout=sec_undo)

        layout.addStretch()

        # ── Machine info box at the bottom of the sidebar ──
        info_box = QWidget()
        info_box.setObjectName("sidebar_info_box")  # styled via make_style()
        il = QVBoxLayout(info_box)
        il.setContentsMargins(8, 6, 8, 6)
        il.setSpacing(2)

        try:
            hostname = subprocess.run(
                ["hostname"], capture_output=True, text=True, timeout=3
            ).stdout.strip()
            kernel = subprocess.run(
                ["uname", "-r"], capture_output=True, text=True, timeout=3
            ).stdout.strip()
            for label2, val in [
                ("Host",    hostname[:20]),
                ("Kernel",  kernel[:22]),
                ("Pkg mgr", PKG_MGR),
            ]:
                row_w = QWidget()
                rl = QHBoxLayout(row_w)
                rl.setContentsMargins(0, 0, 0, 0)
                ll = QLabel(f"{label2}:")
                ll.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-3)}px;")
                ll.setFixedWidth(55)
                vl2 = QLabel(val)
                vl2.setStyleSheet(
                    f"color:{T['TEXT_MAIN']};font-size:{fs(-3)}px;"
                )
                rl.addWidget(ll)
                rl.addWidget(vl2)
                il.addWidget(row_w)
        except Exception as e:
            logging.error(f"Sidebar machine info error: {e}")

        days, msg = check_update_age()
        if days is not None:
            colour = T["DANGER"] if days > 30 else (T["WARN"] if days > 7 else T["OK"])
            ul = QLabel(f"⏱  {int(days)}d since last update")
            ul.setStyleSheet(f"color:{colour};font-size:{fs(-3)}px;")
            il.addWidget(ul)

        built = QLabel(L("built_by"))
        built.setStyleSheet(
            f"color:{T['TEXT_DIM']};font-size:{fs(-4)}px;padding-top:4px;"
        )
        built.setWordWrap(True)
        il.addWidget(built)
        root_layout.addWidget(info_box, 0)

    def _update_section_header(self, section_id, expanded):
        """Refresh section header text with arrow + completion tick."""
        ref = self._section_headers.get(section_id)
        if not ref:
            return
        btn, title_key = ref
        done = self._section_done.get(section_id, set())
        req = self._section_required.get(section_id, set())
        complete = bool(req) and req.issubset(done)
        tick = " ✅" if complete else ""
        btn.setText(f"{'▼' if expanded else '▶'}  {L(title_key)}{tick}")
        if complete:
            btn.setToolTip("Completed section")
        elif req:
            btn.setToolTip(f"Completed {len(done)}/{len(req)} actions in this section")

    def _mark_section_action_done(self, section_id, action_id):
        """Mark one action as completed and update section tick state."""
        if section_id not in self._section_done:
            return
        self._section_done[section_id].add(action_id)
        ref = self._section_headers.get(section_id)
        if ref:
            btn, _ = ref
            expanded = "▼" in btn.text()
            self._update_section_header(section_id, expanded)

    # ── Helper: clear findings and show "please wait" before a scan ──────
    def _pre_scan(self, scan_name, section_id=None, action_id=None):
        """Clear results and show a 'Please wait' message before any scan."""
        self._pending_section_action = (section_id, action_id) if section_id and action_id else None
        # Cancel/invalidate any in-flight CVE scan so late network responses
        # don't leak into the terminal during a different scan (e.g. Lynis).
        if hasattr(self, "cve_panel"):
            self.cve_panel.cancel_active_scan()
        self.findings.clear_findings()
        self.terminal.output.clear()
        self.terminal.append(
            f"⏳  Please wait — running: {scan_name}...", T["ACCENT"]
        )
        # Switch to the findings page so the user sees results populate
        self.stack.setCurrentIndex(0)

    def _run_cmd(self, cmd, label, on_output=None, show_output=True):
        """Run a command in a background thread, output to terminal."""
        self.terminal.append_cmd(" ".join(cmd))
        w = CommandWorker(cmd)
        if show_output:
            w.output_ready.connect(lambda t: self.terminal.append(t))
        w.error_ready.connect(self.terminal.append_err)
        if on_output:
            w.output_ready.connect(on_output)
        w.finished_ok.connect(
            lambda: self.terminal.append_ok(f"{label} complete.")
        )
        w.finished_ok.connect(self._post_scan_check)
        self._start_worker(w)

    def _post_scan_check(self):
        """After any scan completes, show the all-ok banner if nothing bad was found."""
        if self._pending_section_action:
            sec, act = self._pending_section_action
            self._mark_section_action_done(sec, act)
            self._pending_section_action = None
        self.findings.show_all_ok_banner()

    # ── Scan: unused software ─────────────────────────────────────────────
    def _scan_unused(self):
        self._pre_scan(L("btn_unused"), "scan", "unused")
        self._do_scan_unused()

    def _do_scan_unused(self):
        if not shutil.which("deborphan"):
            self.terminal.append_warn(
                "deborphan is not installed. Install with: sudo apt install deborphan"
            )
            return
        self._run_cmd(["deborphan"], "Unused software scan", self._parse_unused)

    def _parse_unused(self, text):
        """Parse deborphan output — every result is a leftover package."""
        count = 0
        for line in text.strip().splitlines():
            pkg = line.strip()
            if not pkg or not valid_pkg(pkg):
                continue
            # A small list of known dangerous packages to elevate to HIGH
            is_dangerous = pkg in ("telnet", "ftp", "rsh-server", "rsh-client")
            risk   = "HIGH" if is_dangerous else "LOW"
            detail = (
                "Dangerous software with no dependents — remove immediately"
                if is_dangerous else
                "Software installed as part of something else — that something "
                "has been removed, leaving this behind. Safe to remove."
            )
            self.findings.add_finding(
                pkg, "LEFTOVER", risk, detail,
                " ".join(pkg_remove(pkg))
            )
            count += 1

        if count == 0:
            self.findings.add_finding(
                "No unused software found", "LEFTOVER", "INFO",
                "✔ No leftover packages detected — good."
            )
        SESSION.log_scan(L("btn_unused"), count)

    # ── Scan: open ports ──────────────────────────────────────────────────
    def _scan_network(self):
        self._pre_scan(L("btn_network"), "scan", "network")
        self._do_scan_network()

    def _do_scan_network(self):
        self._run_cmd(["ss", "-tunlp"], "Network port scan", self._parse_network)

    def _parse_network(self, text):
        """Parse ss output — flag risky ports, add all to findings."""
        # Known risky ports with explanations
        RISKY = {
            "21":   ("FTP",    "HIGH",   "Unencrypted file transfer — credentials visible on network", "apt purge ftp", None),
            "23":   ("TELNET", "HIGH",   "Unencrypted remote shell — everything you type is visible", "apt purge telnet", None),
            "3389": ("XRDP",   "MEDIUM", "Remote Desktop — port 3389 is heavily targeted by attackers", "apt purge xrdp", "systemctl disable --now xrdp"),
            "631":  ("CUPS",   "MEDIUM", "Print server — unnecessary if you do not print from this machine", "apt purge cups", "systemctl mask cups"),
            "5353": ("mDNS",   "LOW",    "Device discovery — broadcasts your machine name on the local network", None, "systemctl disable --now avahi-daemon"),
        }
        seen = set()
        count = 0
        for line in text.strip().splitlines():
            if "LISTEN" not in line and "UNCONN" not in line:
                continue
            m = re.search(r":(\d+)\s+\S+:\*", line)
            if not m:
                continue
            port = m.group(1)
            if port in seen:
                continue
            seen.add(port)
            pm   = re.search(r'users:\(\("([^"]+)"', line)
            proc = pm.group(1) if pm else "unknown"
            count += 1

            if port in RISKY:
                svc, risk, reason, rem, dis = RISKY[port]
                self.findings.add_finding(
                    f"{proc}:{port}", "NETWORK", risk,
                    f"Port {port} ({svc}) — {reason}", rem, dis
                )
            else:
                # Unknown port — add as INFO so user can see it was checked
                self.findings.add_finding(
                    f"{proc}:{port}", "NETWORK", "INFO",
                    f"Port {port} is open — review whether this service "
                    f"needs to be accessible from the network"
                )

        if count == 0:
            self.findings.add_finding(
                "No open ports detected", "NETWORK", "INFO",
                "✔ No listening ports found."
            )
        SESSION.log_scan(L("btn_network"), len([
            r for r in range(self.findings.table.rowCount())
            if self.findings.table.item(r,1) and
               self.findings.table.item(r,1).text() == "NETWORK" and
               self.findings.table.item(r,2) and
               "INFO" not in self.findings.table.item(r,2).text()
        ]))

    # ── Scan: risky services ──────────────────────────────────────────────
    def _scan_services(self):
        self._pre_scan(L("btn_services"), "scan", "services")
        self._do_scan_services()

    def _do_scan_services(self):
        # List of (name, type, risk, detail, remove_cmd, disable_cmd)
        RISKY_SVCS = [
            ("telnet",       "SERVICE","HIGH",  "Unencrypted remote shell — everything you type is visible on the network",                  "apt purge telnet",       None),
            ("ftp",          "SERVICE","HIGH",  "Unencrypted file transfer — credentials sent in plain text",                                 "apt purge ftp",          None),
            ("xrdp",         "SERVICE","MEDIUM","Remote Desktop server — port 3389 is one of the most attacked ports on the internet",        "apt purge xrdp",         "systemctl disable --now xrdp"),
            ("cups",         "SERVICE","MEDIUM","Print server — unnecessary on machines that do not print",                                   "apt purge cups",         "systemctl mask cups"),
            ("avahi-daemon", "SERVICE","LOW",   "mDNS — broadcasts your machine name and services to your local network",                    "apt purge avahi-daemon", "systemctl disable --now avahi-daemon"),
            ("rsh-server",   "SERVICE","HIGH",  "Legacy unencrypted remote shell — completely obsolete, replaced by SSH decades ago",         "apt purge rsh-server",   None),
            ("rpcbind",      "SERVICE","MEDIUM","NFS portmapper — only needed if you are actively sharing files over NFS",                    None,                     "systemctl disable --now rpcbind"),
        ]
        self.terminal.append_cmd("# Checking for risky services...")
        found = 0
        for item in RISKY_SVCS:
            name = item[0]
            if pkg_installed(name):
                self.findings.add_finding(*item)
                self.terminal.append_warn(f"FOUND: {name} — {item[3]}")
                found += 1
            else:
                # Show "not found" in findings as green INFO so user knows it was checked
                self.findings.add_finding(
                    name, "SERVICE", "INFO",
                    f"✔ Not installed — no action needed"
                )
                self.terminal.append_ok(f"{name} — not installed")

        SESSION.log_scan(L("btn_services"), found)
        self._post_scan_check()

    # ── Scan: all installed (legacy, kept for internal use) ──────────────
    def _scan_installed(self):
        self._pre_scan(L("btn_installed"), "scan", "installed")
        if PKG_MGR == "apt":
            cmd = ["dpkg-query", "-W", "--showformat=${Package} ${Version}\n"]
        elif PKG_MGR == "dnf":
            cmd = ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\n"]
        else:
            cmd = ["pacman", "-Q"]
        self._run_cmd(cmd, "Installed package list")

    # ── Scan: OS pre-installed (not in apt-mark showmanual) ───────────────
    def _scan_os_installed(self):
        """List packages that came with the OS — not explicitly installed by the user.
        These are the difference between all packages and apt-mark showmanual output."""
        self._pre_scan(L("btn_os_installed"), "scan", "os_installed")
        if PKG_MGR != "apt":
            self.terminal.append_warn("OS vs user split requires apt (not available on this system).")
            return

        def _parse_os(text):
            """Cross-reference dpkg list with manual installs to find OS baseline."""
            try:
                manual_r = subprocess.run(
                    ["apt-mark", "showmanual"],
                    capture_output=True, text=True, timeout=10
                )
                manual = set(manual_r.stdout.strip().splitlines())
            except Exception as e:
                self.terminal.append_warn(f"apt-mark failed: {e}")
                manual = set()

            count = 0
            self.findings.begin_bulk_update()
            try:
                for line in text.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    pkg, ver = parts[0], parts[1]
                    if pkg not in manual:
                        self.findings.add_finding(
                            pkg, "LEFTOVER", "INFO",
                            f"Pre-installed by OS (version {ver}) — not manually installed"
                        )
                        count += 1
            finally:
                self.findings.end_bulk_update()
            SESSION.log_scan(L("btn_os_installed"), count)

        cmd = ["dpkg-query", "-W", "--showformat=${Package} ${Version}\n"]
        self.terminal.append_info("Gathering OS pre-installed package inventory...")
        self._run_cmd(
            cmd,
            "OS pre-installed packages",
            on_output=_parse_os,
            show_output=False
        )

    # ── Scan: user installed (apt-mark showmanual) ────────────────────────
    def _scan_user_installed(self):
        """List packages the user deliberately installed — from apt-mark showmanual.
        Each result has a REMOVE button so the user can clean up intentionally."""
        self._pre_scan(L("btn_user_installed"), "scan", "user_installed")
        if PKG_MGR != "apt":
            self.terminal.append_warn("User-installed scan requires apt (not available on this system).")
            return

        def _parse_user(text):
            count = 0
            self.findings.begin_bulk_update()
            try:
                for line in text.strip().splitlines():
                    pkg = line.strip()
                    if not pkg or not valid_pkg(pkg):
                        continue
                    self.findings.add_finding(
                        pkg, "LEFTOVER", "INFO",
                        "Deliberately installed by you — safe to keep, safe to remove if no longer needed",
                        " ".join(pkg_remove(pkg))
                    )
                    count += 1
            finally:
                self.findings.end_bulk_update()
            SESSION.log_scan(L("btn_user_installed"), count)

        self.terminal.append_info("Gathering user-installed package inventory...")
        self._run_cmd(
            ["apt-mark", "showmanual"],
            "User-installed packages",
            on_output=_parse_user,
            show_output=False
        )

    # ── Scan: full scan (all of the above) ────────────────────────────────
    def _run_full_scan(self):
        self._pre_scan("Full System Scan", "scan", "fullscan")
        self._do_scan_unused()
        # Stagger the scans slightly so they don't all start simultaneously
        QTimer.singleShot(1000,  self._do_scan_network)
        QTimer.singleShot(2000,  self._do_scan_services)

    # ── Security checks ───────────────────────────────────────────────────
    def _quick_checks(self):
        self._pre_scan(L("btn_quick"), "checks", "quick")
        run_quick_checks(self.terminal, self.findings)
        self._post_scan_check()

    def _run_lynis(self):
        """Run Lynis audit — switch to the Lynis page to show results."""
        self._pre_scan(L("btn_lynis"), "checks", "lynis")
        self.stack.setCurrentIndex(2)  # Page 2 = LynisPanel
        self.lynis_panel.run_lynis(on_complete=self._post_scan_check)

    def _guided_wizard(self):
        """Open the step-by-step fix wizard dialog."""
        GuidedWizard(self.terminal, self).exec()
        self._mark_section_action_done("checks", "wizard")

    # ── CVE checks ────────────────────────────────────────────────────────
    def _scan_cve(self):
        """Run CVE check — switch to CVE page to show results."""
        self._pre_scan(L("btn_cve"), "cve", "cve")
        self.stack.setCurrentIndex(1)  # Page 1 = CvePanel
        self.cve_panel.scan_cve(on_complete=self._post_scan_check)

    def _scan_upgrades(self):
        """Check for available updates — switch to CVE page."""
        self._pre_scan(L("btn_upgrades"), "cve", "upgrades")
        self.stack.setCurrentIndex(1)  # Page 1 = CvePanel
        self.cve_panel.scan_upgrades(on_complete=self._post_scan_check)

    # ── Tools and undo ────────────────────────────────────────────────────
    def _show_tools(self):
        """Switch to the tools page."""
        self.stack.setCurrentIndex(3)  # Page 3 = ToolsPanel
        self._mark_section_action_done("tools", "tools")

    def _show_undo(self):
        """Switch to the undo page."""
        self.stack.setCurrentIndex(4)  # Page 4 = UndoPanel
        self._mark_section_action_done("undo", "undo")


# ── Profile selection dialog ──────────────────────────────────────────────────
class ProfileDialog(QDialog):
    """Shown after startup detection — lets user confirm or change the
    automatically detected system profile."""

    def __init__(self, detected_key, confidence, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm Your System Profile")
        self.setMinimumWidth(540)
        self.selected = detected_key

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel("System Profile Detection")
        title.setObjectName("heading")
        layout.addWidget(title)

        detected_label = PROFILES.get(detected_key, {}).get("label", "Unknown")
        conf_colour = (T["OK"] if confidence > 60 else
                       T["WARN"] if confidence > 30 else T["TEXT_DIM"])
        msg = QLabel(
            f"Based on what is currently running, this looks like a:\n\n"
            f"  <b>{detected_label}</b>  "
            f"<span style='color:{conf_colour};font-size:{fs(-2)}px;'>"
            f"({confidence}% confident)</span>\n\n"
            f"This affects what the scanner flags as normal versus suspicious.\n"
            f"Is that correct, or would you like to choose manually?"
        )
        msg.setWordWrap(True)
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setStyleSheet(f"font-size:{fs()}px;")
        layout.addWidget(msg)

        self.btn_group = QButtonGroup(self)
        for key, info in PROFILES.items():
            rb = QRadioButton(info["label"])
            rb.setChecked(key == detected_key)
            rb.clicked.connect(lambda _, k=key: setattr(self, "selected", k))
            self.btn_group.addButton(rb)
            layout.addWidget(rb)

        self.remember = QCheckBox("Remember this choice for future sessions")
        self.remember.setChecked(True)
        layout.addWidget(self.remember)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ── First-run startup wizard ──────────────────────────────────────────────────
class StartupWizard(QDialog):
    """Shown on first run only. Walks the user through:
    Page 1: Welcome and what the app does
    Page 2: Simple vs Expert mode, Online vs Offline
    Page 3: System profile selection
    Page 4: Summary and ready to start"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to Linux Audit Dashboard")
        self.setMinimumSize(700, 600)
        self.setModal(True)
        # Results that the main window reads after the wizard closes
        self.mode    = "simple"
        self.online  = True
        self.profile = "laptop"

        layout = QVBoxLayout(self)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        nav = QHBoxLayout()
        self.back_btn = QPushButton("← Back")
        self.back_btn.setObjectName("neutral")
        self.back_btn.setFixedHeight(38)
        self.back_btn.clicked.connect(self._go_back)
        self.back_btn.setVisible(False)

        self.progress_lbl = QLabel("Step 1 of 4")
        self.progress_lbl.setObjectName("status")
        self.progress_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.next_btn = QPushButton("Next →")
        self.next_btn.setObjectName("ok")
        self.next_btn.setFixedHeight(38)
        self.next_btn.clicked.connect(self._go_next)

        nav.addWidget(self.back_btn)
        nav.addStretch()
        nav.addWidget(self.progress_lbl)
        nav.addStretch()
        nav.addWidget(self.next_btn)
        layout.addLayout(nav)

        self._build_pages()

    def _page_wrapper(self, title_text, subtitle=""):
        """Build a standard page container with a title."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(16)
        title = QLabel(title_text)
        title.setStyleSheet(
            f"color:{T['ACCENT']};font-size:{fs(4)}px;"
            f"font-weight:bold;letter-spacing:2px;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs()}px;")
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub.setWordWrap(True)
            layout.addWidget(sub)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)
        return w, layout

    def _build_pages(self):
        """Build all four wizard pages and add them to the stack."""

        # ── Page 1: Welcome ──
        p1, l1 = self._page_wrapper("⬡  LINUX AUDIT DASHBOARD v4.2")
        intro = QLabel(
            "This tool gives your Linux system a security health check.\n\n"
            "It scans for:\n"
            "  •  Leftover software that is no longer needed\n"
            "  •  Open network ports that could be risky\n"
            "  •  Security configuration — firewall, SSH, kernel settings\n"
            "  •  Known CVE vulnerabilities in your installed software\n\n"
            "Everything is explained in plain English before any action is taken.\n\n"
            "Nothing on your system is changed without your explicit confirmation.\n"
            "You will always see exactly what command will run before it does.\n\n"
            "This is not a magic fix — it gives you information and options.\n"
            "You decide what to act on."
        )
        intro.setStyleSheet(
            f"color:{T['TEXT_MAIN']};font-size:{fs()}px;line-height:1.6;"
        )
        intro.setWordWrap(True)
        l1.addWidget(intro)
        l1.addStretch()
        self.stack.addWidget(p1)

        # ── Page 2: Mode and connectivity ──
        p2, l2 = self._page_wrapper(
            "Choose Your Preferences",
            "These can be changed at any time from the toolbar"
        )
        mode_box = QGroupBox("Display Mode")
        ml = QVBoxLayout(mode_box)
        self.simple_rb = QRadioButton(
            "Simple Mode — Plain English, essential findings only.\n"
            "    Hides technical detail and low-priority items.\n"
            "    Recommended for most users."
        )
        self.expert_rb = QRadioButton(
            "Expert Mode — Full technical detail.\n"
            "    Shows all findings including low priority.\n"
            "    CVE numbers, port details, kernel flags."
        )
        self.simple_rb.setChecked(True)
        ml.addWidget(self.simple_rb)
        ml.addWidget(self.expert_rb)
        l2.addWidget(mode_box)

        conn_box = QGroupBox("Connectivity")
        cl = QVBoxLayout(conn_box)
        self.online_rb  = QRadioButton(
            "Online Mode — CVE vulnerability checks enabled.\n"
            "    Queries Ubuntu's live security database.\n"
            "    Recommended."
        )
        self.offline_rb = QRadioButton(
            "Offline Mode — Local scans only.\n"
            "    No internet connection needed.\n"
            "    CVE checks will be disabled."
        )
        self.online_rb.setChecked(True)
        cl.addWidget(self.online_rb)
        cl.addWidget(self.offline_rb)
        l2.addWidget(conn_box)
        l2.addStretch()
        self.stack.addWidget(p2)

        # ── Page 3: System profile ──
        p3, l3 = self._page_wrapper(
            "What kind of machine is this?",
            "This helps the scanner know what is normal for your setup.\n"
            "A gaming rig is different from a web server."
        )
        self.profile_rbs = {}
        self.profile_grp = QButtonGroup(self)
        descs = {
            "gaming":     "Steam, game servers, Sunshine streaming — gaming ports and processes are expected",
            "docker":     "Docker daemon, container runtimes — container activity is expected",
            "hypervisor": "QEMU, KVM, Proxmox — virtualisation activity is expected",
            "webserver":  "Apache, Nginx, PHP — web server ports and processes are expected",
            "fileserver": "Samba, NFS — file sharing ports are expected",
            "headless":   "No desktop — SSH only, no display",
            "laptop":     "Personal daily-use machine with battery",
            "workstation":"Work desktop with office software (Teams, Slack, etc.)",
            "mixed":      "General purpose — flag everything and I will decide",
        }
        for key, info in PROFILES.items():
            rb = QRadioButton(f"  {info['label']}")
            rb.setToolTip(descs.get(key, ""))
            rb.clicked.connect(lambda _, k=key: setattr(self, "profile", k))
            self.profile_grp.addButton(rb)
            self.profile_rbs[key] = rb
            l3.addWidget(rb)
        self.profile_rbs["laptop"].setChecked(True)
        self.profile = "laptop"
        l3.addStretch()
        self.stack.addWidget(p3)

        # ── Page 4: Ready ──
        p4, l4 = self._page_wrapper("You are all set!", "")
        self.summary_lbl = QLabel("")
        self.summary_lbl.setStyleSheet(
            f"color:{T['TEXT_MAIN']};font-size:{fs()}px;"
        )
        self.summary_lbl.setWordWrap(True)
        l4.addWidget(self.summary_lbl)

        tip = QLabel(
            "\nTips for getting started:\n\n"
            "  •  Click 'RUN FULL SCAN' on the left sidebar to begin\n"
            "  •  Double-click any finding for a plain English explanation\n"
            "  •  Nothing changes until you click REMOVE or DISABLE and confirm\n"
            "  •  The face at the top improves as you fix issues\n"
            "  •  Use the ? button on any finding to understand it better"
        )
        tip.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        tip.setWordWrap(True)
        l4.addWidget(tip)
        l4.addStretch()
        self.stack.addWidget(p4)

    def _go_next(self):
        idx = self.stack.currentIndex()
        if idx == 3:
            self.accept()
            return
        if idx == 1:
            self.mode   = "simple" if self.simple_rb.isChecked() else "expert"
            self.online = self.online_rb.isChecked()
        if idx == 2:
            # Update the summary on page 4
            pl = PROFILES.get(self.profile, {}).get("label", "Unknown")
            self.summary_lbl.setText(
                f"Profile:         {pl}\n"
                f"Display Mode:    {'Simple — plain English, essential findings only' if self.mode == 'simple' else 'Expert — full technical detail'}\n"
                f"Connectivity:    {'Online — CVE vulnerability checks enabled' if self.online else 'Offline — local scans only'}\n\n"
                f"Click 'Start Scanning' to begin."
            )
        self.stack.setCurrentIndex(idx + 1)
        self.back_btn.setVisible(True)
        self.progress_lbl.setText(f"Step {idx + 2} of 4")
        self.next_btn.setText("Start Scanning →" if idx == 2 else "Next →")

    def _go_back(self):
        idx = self.stack.currentIndex()
        if idx <= 0:
            return
        self.stack.setCurrentIndex(idx - 1)
        self.progress_lbl.setText(f"Step {idx} of 4")
        self.back_btn.setVisible(idx > 1)
        self.next_btn.setText("Next →")


# ── Session summary dialog ────────────────────────────────────────────────────
class SessionSummaryDialog(QDialog):
    """Popup showing a plain English summary of everything done this session.
    Triggered by the 'SESSION SUMMARY' toolbar button."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Session Summary — What Have I Done?")
        self.setMinimumSize(560, 480)
        layout = QVBoxLayout(self)

        title = QLabel("📋  What's Been Done?")
        title.setObjectName("heading")
        layout.addWidget(title)

        info = QLabel(
            "A plain English breakdown of everything that happened this session."
        )
        info.setStyleSheet(f"color:{T['TEXT_DIM']};font-size:{fs(-1)}px;")
        layout.addWidget(info)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(QFont("Courier New", fs()))
        # Build and display the summary from the SESSION tracker
        self.text.setPlainText(SESSION.build_summary())
        layout.addWidget(self.text)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.close)
        layout.addWidget(btns)


# ── HTML report generator ─────────────────────────────────────────────────────
def generate_report(findings_widget, profile_key, mode="executive"):
    """Generate a complete HTML security report.
    Executive mode: plain English, key stats, readable by anyone.
    Technical mode: all raw data, CVE numbers, full findings list."""
    score = RISK.score()
    label, _ = RISK.label()
    profile_label = PROFILES.get(profile_key, {}).get("label", "Unknown")
    try:
        hostname = subprocess.run(
            ["hostname"], capture_output=True, text=True, timeout=3
        ).stdout.strip()
    except Exception:
        hostname = "Unknown"
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sc = "#3fb950" if score < 20 else ("#f0a500" if score < 50 else "#ff4444")
    h  = RISK.findings.count("HIGH")
    m  = RISK.findings.count("MEDIUM")
    l  = RISK.findings.count("LOW")

    tbl = findings_widget.table
    rows = ""
    for r in range(tbl.rowCount()):
        n  = html.escape(tbl.item(r,0).text() if tbl.item(r,0) else "")
        ft = html.escape(tbl.item(r,1).text() if tbl.item(r,1) else "")
        ri = html.escape(tbl.item(r,2).text() if tbl.item(r,2) else "")
        tg = html.escape(tbl.item(r,3).text() if tbl.item(r,3) else "")
        dt = html.escape(tbl.item(r,4).text() if tbl.item(r,4) else "")
        rc = "#ff4444" if "HIGH" in ri else ("#f0a500" if "MEDIUM" in ri else "#3fb950")
        rows += (
            f"<tr><td>{n}</td><td>{ft}</td>"
            f"<td style='color:{rc};font-weight:bold'>{ri}</td>"
            f"<td>{tg}</td><td>{dt}</td></tr>\n"
        )

    if mode == "executive":
        words = (
            "Your system is in great shape" if score < 20 else
            "Your system is mostly healthy with a few items to look at" if score < 50 else
            "Your system has some security concerns worth addressing" if score < 75 else
            "Your system has serious security issues that need urgent attention"
        )
        cheeky = [
            "Not bad at all 😎", "Could be worse!", "You've been warned 😬",
            "Houston, we have a problem 🚨"
        ][0 if score<20 else 1 if score<50 else 2 if score<75 else 3]
        exec_section = f"""
        <div style="background:#1a2a1a;border:1px solid #3fb950;border-radius:8px;padding:16px;margin:16px 0;">
            <h2 style="color:#3fb950;margin:0 0 8px 0;">In Plain English</h2>
            <p style="font-size:16px;margin:0;">{words}. {cheeky}</p>
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0;">
            <div style="background:#21262d;border-radius:6px;padding:12px;text-align:center;">
                <div style="color:#ff4444;font-size:28px;font-weight:bold;">{h}</div>
                <div style="color:#8b949e;">High Priority</div>
                <div style="color:#e6edf3;font-size:11px;">Fix these first</div>
            </div>
            <div style="background:#21262d;border-radius:6px;padding:12px;text-align:center;">
                <div style="color:#f0a500;font-size:28px;font-weight:bold;">{m}</div>
                <div style="color:#8b949e;">Medium Priority</div>
            </div>
            <div style="background:#21262d;border-radius:6px;padding:12px;text-align:center;">
                <div style="color:#3fb950;font-size:28px;font-weight:bold;">{l}</div>
                <div style="color:#8b949e;">Low Priority</div>
            </div>
        </div>"""
    else:
        exec_section = "<p style='color:#8b949e;'>Technical report — all findings listed below.</p>"

    undo_rows = "".join(
        f"<tr>"
        f"<td>{html.escape(e.get('time',''))}</td>"
        f"<td>{html.escape(e.get('action',''))}</td>"
        f"<td>{html.escape(e.get('cmd',''))}</td>"
        f"<td style='color:{'#ff4444' if e.get('risk_level')=='HIGH' else '#f0a500' if e.get('risk_level')=='MEDIUM' else '#3fb950'};'>"
        f"{e.get('risk_level','')}</td>"
        f"<td>{html.escape(e.get('undo_cmd',''))}</td>"
        f"</tr>"
        for e in UNDO_LOG
    )

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Linux Audit Report — {html.escape(hostname)}</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#e6edf3;padding:24px;max-width:1100px;margin:0 auto;}}
h1{{color:#00d9ff;}} h2{{color:#00d9ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:24px;}}
.score{{font-size:2.5em;font-weight:bold;color:{sc};}}
table{{border-collapse:collapse;width:100%;margin-top:12px;}}
th{{background:#21262d;color:#8b949e;padding:8px;text-align:left;font-size:11px;letter-spacing:1px;}}
td{{padding:8px;border-bottom:1px solid #30363d;font-size:12px;}}
tr:hover{{background:#161b22;}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:20px;}}
footer{{color:#8b949e;font-size:11px;text-align:center;margin-top:40px;border-top:1px solid #30363d;padding-top:16px;}}
</style>
</head><body>
<h1>⬡ Linux Security Audit Report</h1>
<div class="meta">
Hostname: <b>{html.escape(hostname)}</b> |
Profile: {html.escape(profile_label)} |
Generated: {ts} |
Mode: {"Executive" if mode == "executive" else "Technical"}
</div>
<h2>Risk Score</h2>
<div class="score">{score} / 100</div>
<div style="color:#8b949e;font-size:14px;margin-top:4px;">{label}</div>
{exec_section}
<h2>All Findings ({tbl.rowCount()})</h2>
<table>
<tr><th>NAME</th><th>TYPE</th><th>RISK</th><th>TAG</th><th>DETAIL</th></tr>
{rows}
</table>
<h2>Actions Taken This Session</h2>
<table>
<tr><th>TIME</th><th>ACTION</th><th>COMMAND</th><th>RISK LEVEL</th><th>UNDO COMMAND</th></tr>
{undo_rows if undo_rows else "<tr><td colspan=5 style='color:#8b949e;'>No actions taken this session.</td></tr>"}
</table>
<footer>Linux Audit Dashboard v4.2 | {L('built_by')} | github.com/playdoggs/linux-audit-dashboard</footer>
</body></html>"""


# ── Main application window ───────────────────────────────────────────────────
class AuditDashboard(QMainWindow):
    """The main application window. Assembles all panels and wires up signals.
    Layout:
    ┌─ Toolbar (mode / lang / theme / session summary / report / show code) ─┐
    ├─ Risk score panel (face + progress bar + profile label) ────────────────┤
    ├─ Sidebar (240px) ─┬─ Tab widget (findings / cve / lynis / tools / undo)─┤
    │                   ├─ ─────────────── splitter ─────────────────────────┤
    │                   └─ Terminal output panel ─────────────────────────────┤
    └───────────────────────────────────────────────────────────────────────── ┘
    """

    def __init__(self, wizard_result=None):
        super().__init__()
        self.setWindowTitle("Linux Audit Dashboard v4.2")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)

        # Read saved preferences
        cfg           = load_config()
        startup_theme = get_startup_theme(cfg)
        self.theme_locked = config_bool(
            cfg.get("prefs", "theme_locked", fallback="false")
        )
        saved_lang    = cfg.get("prefs", "language",  fallback="EN")
        saved_profile = cfg.get("prefs", "profile",   fallback=None)

        # Apply saved theme and language before building the UI.
        # Must rebuild BOTH stylesheet AND palette — Light mode needs the palette
        # updated or Qt's Fusion base colours stay dark (including frame/bevel roles).
        global LANG
        LANG = saved_lang
        apply_theme(startup_theme)
        _app = QApplication.instance()
        _app.setPalette(build_palette())
        _app.setStyleSheet(make_style())

        # Read wizard result if this is the first run
        self.expert_mode = True
        self.online_mode = True
        self.profile_key = "mixed"
        if wizard_result:
            self.expert_mode = (wizard_result.mode == "expert")
            self.online_mode = wizard_result.online
            self.profile_key = wizard_result.profile

        # ── Build the central widget layout ──
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────────
        tbw = QWidget()
        tbw.setObjectName("toolbar_bar")   # styled via make_style() so theme changes apply
        tbw.setMinimumHeight(84)
        tb = QVBoxLayout(tbw)
        tb.setContentsMargins(10, 6, 10, 6)
        tb.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        title_lbl = QLabel(L("title"))
        title_lbl.setObjectName("app_title")   # styled via make_style()
        title_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        title_lbl.setMinimumWidth(280)
        top_row.addWidget(title_lbl, 1)
        top_row.addStretch()

        # Mode / Language / Theme dropdowns
        for label2, items2, width2, attr2, handler2 in [
            ("Mode:",  [L("mode_simple"), L("mode_expert")], 130, "mode_combo", self._toggle_mode),
            ("Lang:",  list(LANGS.keys()),                    80, "lang_combo",  self._change_lang),
            ("Theme:", list(THEMES.keys()),                  115, "theme_combo", self._change_theme),
        ]:
            ll = QLabel(label2)
            ll.setObjectName("status")
            top_row.addWidget(ll)
            cb = QComboBox()
            cb.addItems(items2)
            cb.setFixedWidth(width2)
            setattr(self, attr2, cb)
            cb.currentTextChanged.connect(handler2)
            top_row.addWidget(cb)

        self.theme_lock_btn = QPushButton()
        self.theme_lock_btn.setObjectName("neutral")
        self.theme_lock_btn.setCheckable(True)
        self.theme_lock_btn.setChecked(self.theme_locked)
        self.theme_lock_btn.setFixedHeight(30)
        self.theme_lock_btn.clicked.connect(self._toggle_theme_lock)
        top_row.addWidget(self.theme_lock_btn)
        self._update_theme_lock_button()
        tb.addLayout(top_row)

        actions_row = QHBoxLayout()
        actions_row.setContentsMargins(0, 0, 0, 0)
        actions_row.setSpacing(8)

        # Set combos to saved values — block signals to avoid premature handlers
        self.mode_combo.blockSignals(True)
        self.mode_combo.setCurrentText(
            L("mode_expert") if self.expert_mode else L("mode_simple")
        )
        self.mode_combo.blockSignals(False)
        self.lang_combo.setCurrentText(saved_lang)
        self.theme_combo.blockSignals(True)
        self.theme_combo.setCurrentText(startup_theme)
        self.theme_combo.blockSignals(False)

        # Toolbar action buttons
        for lbl3, tip3, handler3 in [
            ("📋  What's Been Done?", "Plain English summary of everything done this session", self._show_session_summary),
            ("👤  CHANGE PROFILE",   "Re-detect or manually select your system profile",       self._detect_profile),
            ("📄  REPORT",           "Generate a security report as an HTML file",              self._generate_report),
            ("{ }  SHOW CODE",       "See every command this app can run — full transparency",  self._show_code),
            ("🪲  DEV LOG",          "Show the application error/debug log in the terminal",    self._show_dev_log),
        ]:
            b = QPushButton(lbl3)
            b.setObjectName("neutral")
            b.setFixedHeight(30)
            b.setToolTip(tip3)
            b.clicked.connect(handler3)
            actions_row.addWidget(b)
        actions_row.addStretch()
        tb.addLayout(actions_row)
        root.addWidget(tbw)

        # ── Risk score panel ──────────────────────────────────────────────
        rpw = QWidget()
        rpw.setObjectName("risk_panel_bar")  # styled via make_style() so theme changes apply
        rl = QHBoxLayout(rpw)
        rl.setContentsMargins(0, 0, 0, 0)
        self.risk_panel = RiskScorePanel()
        rl.addWidget(self.risk_panel)
        root.addWidget(rpw)

        # ── Main body: sidebar + content area ────────────────────────────
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        root.addWidget(body)

        # Build the shared panels
        self.terminal  = TerminalPanel()
        self.findings  = FindingsTable(self.terminal)
        self.findings.score_changed.connect(self.risk_panel.update_score)
        self.findings.expert_mode = self.expert_mode

        lynis_panel = LynisPanel(self.terminal, self.findings)
        cve_panel   = CvePanel(self.terminal, self.findings)
        tools_panel = ToolsPanel(self.terminal)
        undo_panel  = UndoPanel(self.terminal)

        # Register the undo panel so FindingsTable can update it live
        QApplication.instance().undo_panel_ref = undo_panel

        # ── Stack widget (no visible tab bar — sidebar controls page) ────
        # Page indices: 0=findings, 1=cve, 2=lynis, 3=tools, 4=undo
        self.stack = QStackedWidget()
        self.stack.addWidget(self.findings)
        self.stack.addWidget(cve_panel)
        self.stack.addWidget(lynis_panel)
        self.stack.addWidget(tools_panel)
        self.stack.addWidget(undo_panel)

        # ── Vertical splitter: stack on top, terminal on bottom ───────────
        self.vsplit = CueSplitter(Qt.Orientation.Vertical)
        self.vsplit.setHandleWidth(12)
        self.vsplit.setToolTip("Drag here to resize panels")
        self.vsplit.addWidget(self.stack)
        self.vsplit.addWidget(self.terminal)
        self.vsplit.setSizes([580, 260])

        # ── Sidebar (built last so it has references to all panels) ───────
        self.sidebar = SideBar(
            self.terminal, self.findings,
            lynis_panel, cve_panel, tools_panel, undo_panel,
            self.stack, self.online_mode
        )
        body_layout.addWidget(self.sidebar)
        body_layout.addWidget(self.vsplit, 1)

        # ── Status bar ────────────────────────────────────────────────────
        sb = QStatusBar()
        self.setStatusBar(sb)
        sb.showMessage(
            "Ready  |  Ctrl+R = Full Scan  |  Ctrl+1-5 = Individual Scans  |  "
            "Double-click any finding for a plain English explanation  |  "
            "Drag the bar between panels to resize"
        )

        # ── Set up profile ────────────────────────────────────────────────
        # Always detect on startup so the profile stays current.
        # The saved profile is shown as the default selection in the dialog.
        if not wizard_result:
            QTimer.singleShot(400, self._detect_profile)
        else:
            self.risk_panel.set_profile(self.profile_key)
            self.findings.profile_key = self.profile_key

        # Welcome message in terminal
        self.terminal.append(
            f"Linux Audit Dashboard v4.2 ready.\n"
            f"Profile: {PROFILES.get(self.profile_key,{}).get('label','Unknown')}  |  "
            f"Mode: {'Expert' if self.expert_mode else 'Simple'}  |  "
            f"{'Online' if self.online_mode else 'Offline'}",
            T["ACCENT"]
        )
        self.terminal.append_info(
            "Use the sidebar on the left to run scans. "
            "Nothing changes on your system until you confirm an action."
        )

    def _detect_profile(self):
        """Auto-detect the system profile and offer confirmation dialog."""
        detected, conf = detect_profile()
        dlg = ProfileDialog(detected, conf, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.profile_key = dlg.selected
            if dlg.remember.isChecked():
                save_config("prefs", "profile", self.profile_key)
        else:
            self.profile_key = detected
        self.risk_panel.set_profile(self.profile_key, conf)
        self.findings.profile_key = self.profile_key
        self.terminal.append_ok(
            f"Profile: {PROFILES.get(self.profile_key,{}).get('label','Unknown')}"
        )

    def _toggle_mode(self, text):
        """Switch between Simple and Expert mode.
        Guard against firing before self.findings is ready."""
        if not hasattr(self, "findings"):
            return
        self.expert_mode = (text == L("mode_expert"))
        self.findings.expert_mode = self.expert_mode
        save_config("prefs", "mode", "expert" if self.expert_mode else "simple")
        self.terminal.append_ok(
            "Expert mode — full technical detail shown" if self.expert_mode
            else "Simple mode — plain English, essential findings only"
        )

    def _change_theme(self, name):
        """Switch the colour theme — updates palette and stylesheet.

        Only app.setPalette + app.setStyleSheet are needed.  Any widget-level
        setStyleSheet call with a bare rule (no selector) cascades to ALL child
        widgets and *overrides* the global stylesheet — that is the bug that
        caused section buttons, section sub-labels and the sidebar to stay stuck
        on the startup theme even after switching.  All persistent widgets are
        now styled via objectNames in make_style() so no widget-level overrides
        are needed here.
        """
        apply_theme(name)
        app = QApplication.instance()
        app.setPalette(build_palette())
        app.setStyleSheet(make_style())
        # Refresh the risk bar chunk colour — it only updates normally when the
        # risk score changes, so force a redraw on theme change.
        if hasattr(self, "risk_panel"):
            self.risk_panel.update_score()
        if hasattr(self, "findings"):
            self.findings.refresh_theme_styles()
        if self.theme_locked:
            save_config("prefs", "theme_locked", "true")
            save_config("prefs", "locked_theme", name)
        else:
            save_config("prefs", "theme_locked", "false")

    def _update_theme_lock_button(self):
        """Refresh lock button label and tooltip from current state."""
        if not hasattr(self, "theme_lock_btn"):
            return
        if self.theme_locked:
            self.theme_lock_btn.setText("🔒 Theme Locked")
            self.theme_lock_btn.setToolTip(
                "Locked: this theme will be used on startup.\nClick to unlock (startup returns to Light mode)."
            )
        else:
            self.theme_lock_btn.setText("🔓 Lock Theme")
            self.theme_lock_btn.setToolTip(
                "Unlocked: app starts in Light mode.\nClick to lock the current theme for startup."
            )

    def _toggle_theme_lock(self, checked):
        """Lock/unlock startup theme persistence."""
        self.theme_locked = bool(checked)
        if self.theme_locked:
            save_config("prefs", "theme_locked", "true")
            save_config("prefs", "locked_theme", self.theme_combo.currentText())
            self.terminal.append_ok(
                f"Theme locked: startup will use {self.theme_combo.currentText()}."
            )
        else:
            save_config("prefs", "theme_locked", "false")
            self.terminal.append_info(
                "Theme unlocked: startup will default to Light mode."
            )
        self._update_theme_lock_button()

    def _change_lang(self, lang):
        """Change the display language. Requires restart for full effect."""
        global LANG
        LANG = lang
        save_config("prefs", "language", lang)
        QMessageBox.information(
            self, "Language Changed",
            f"Language set to {lang}.\n"
            f"Restart the app to apply all labels fully."
        )

    def _show_session_summary(self):
        """Show the 'What Have I Done?' session summary popup."""
        SessionSummaryDialog(self).exec()

    def _generate_report(self):
        """Generate and save an HTML report — Executive or Technical format."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Generate Report")
        dlg.setMinimumWidth(420)
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel("Choose report style:"))
        exec_rb = QRadioButton(
            "👤  Executive — Plain English summary with key stats\n"
            "    Good for sharing with non-technical people"
        )
        exec_rb.setChecked(True)
        tech_rb = QRadioButton(
            "🔧  Technical — Full CVE numbers, port details, raw data\n"
            "    Good for IT professionals or detailed records"
        )
        layout.addWidget(exec_rb)
        layout.addWidget(tech_rb)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        mode = "executive" if exec_rb.isChecked() else "technical"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report",
            f"audit-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.html",
            "HTML Files (*.html)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(generate_report(self.findings, self.profile_key, mode))
                QMessageBox.information(
                    self, "Report Saved",
                    f"Report saved:\n{path}\n\nOpen in any web browser to view."
                )
            except Exception as e:
                QMessageBox.critical(self, "Save Failed", f"Could not save report:\n{e}")

    def _show_code(self):
        """Show every command this app can run — full transparency."""
        dlg = QDialog(self)
        dlg.setWindowTitle("All Commands This App Can Run")
        dlg.resize(820, 620)
        layout = QVBoxLayout(dlg)
        hdr = QLabel("FULL COMMAND REFERENCE — COMPLETE TRANSPARENCY")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)
        info = QLabel(
            "Every command this app can run is listed here.\n"
            "Nothing runs without your explicit confirmation first.\n"
            "You can copy any of these and run them manually in a terminal."
        )
        info.setObjectName("status")
        info.setWordWrap(True)
        layout.addWidget(info)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setFont(QFont("Courier New", fs()))
        te.setPlainText("""SCAN COMMANDS (read-only — safe to run any time):
  deborphan                               Find packages with no dependents
  ss -tunlp                               Show all open network ports
  dpkg -l <package>                       Check if a package is installed
  dpkg-query -W --showformat=...          List all installed packages
  ps aux                                  List all running processes
  hostname                                Get machine hostname
  uname -r                                Get kernel version

CVE CHECKS (read-only, requires internet):
  https://ubuntu.com/security/cves.json?package=<n>&limit=5
  apt list --upgradable                   Show packages with newer versions

SECURITY CHECKS (read-only):
  grep -i PermitRootLogin /etc/ssh/sshd_config
  grep -i PasswordAuthentication /etc/ssh/sshd_config
  systemctl is-active ufw
  which fail2ban-server
  sysctl fs.suid_dumpable
  sysctl kernel.randomize_va_space
  ls -la /etc/passwd

LYNIS AUDIT (read-only scan — takes ~60s):
  sudo lynis audit system --quick

FIX COMMANDS (require confirmation dialog before running):
  sudo apt purge <package>                Remove a package completely
  sudo apt install <package>              Install a package
  sudo systemctl disable --now <service> Stop and disable a service
  sudo systemctl mask <service>           Prevent a service from starting
  sudo ufw default deny incoming          Set UFW to deny all incoming
  sudo ufw default allow outgoing         Set UFW to allow all outgoing
  sudo ufw allow ssh                      Allow SSH through the firewall
  sudo ufw enable                         Enable the UFW firewall

UNDO COMMANDS (require confirmation dialog before running):
  sudo apt install <package>              Reinstall a removed package
  sudo systemctl enable --now <service>   Re-enable a disabled service
  sudo systemctl unmask <service>         Remove a mask from a service
  sudo ufw disable                        Disable the firewall (if you enabled it)""")
        layout.addWidget(te)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.close)
        layout.addWidget(btns)
        dlg.exec()

    def _show_dev_log(self):
        """Show the last 200 lines of the application error log in the terminal.
        Useful when developing or diagnosing issues."""
        self.terminal.append_info(f"── Dev Log: {LOG_FILE} ──")
        try:
            if LOG_FILE.exists():
                lines = LOG_FILE.read_text(errors="replace").splitlines()
                recent = lines[-200:] if len(lines) > 200 else lines
                if recent:
                    self.terminal.append("\n".join(recent), T["TEXT_DIM"])
                else:
                    self.terminal.append_ok("Log file is empty — no errors recorded.")
            else:
                self.terminal.append_ok("No log file yet — no errors have been recorded.")
        except Exception as e:
            self.terminal.append_err(f"Could not read log file: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    """Application entry point. Sets up Qt, shows the startup wizard
    on first run, then opens the main window."""

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.undo_panel_ref = None  # Will be set once the main window is built

    # Load startup theme FIRST (Light by default unless theme lock is enabled)
    cfg          = load_config()
    startup_theme = get_startup_theme(cfg)
    apply_theme(startup_theme)

    # Set up the Qt palette (affects base widget colours that stylesheets don't)
    app.setPalette(build_palette())
    app.setStyleSheet(make_style())

    # Show the startup wizard only on first run (no config file yet)
    wizard_result = None
    first_run     = not cfg.has_section("prefs")
    if first_run:
        wiz = StartupWizard()
        wiz.exec()
        wizard_result = wiz
        # Mark as no longer first run
        save_config("prefs", "theme_locked", "false")
        save_config("prefs", "locked_theme", "Light")
        save_config("prefs", "language", "EN")

    win = AuditDashboard(wizard_result=wizard_result if first_run else None)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
