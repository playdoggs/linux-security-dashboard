#!/usr/bin/env python3
"""
Linux Security Audit Dashboard v3
Full-featured security audit tool for Linux systems.
"""

import sys
import os
import re
import json
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QLabel,
    QSplitter, QTabWidget, QHeaderView, QMessageBox, QFrame, QProgressBar,
    QDialog, QDialogButtonBox, QScrollArea, QComboBox, QToolTip,
    QStatusBar, QGroupBox, QCheckBox, QFileDialog, QListWidget,
    QListWidgetItem, QStackedWidget, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPoint
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QCursor

# ── Themes ────────────────────────────────────────────────────────────────────
THEMES = {
    "Dark": {
        "BG_DARK": "#0d1117", "BG_MID": "#161b22", "BG_CARD": "#21262d",
        "ACCENT": "#00d9ff", "WARN": "#f0a500", "DANGER": "#ff4444",
        "OK": "#3fb950", "TEXT_MAIN": "#e6edf3", "TEXT_DIM": "#8b949e",
        "BORDER": "#30363d",
    },
    "Hacker": {
        "BG_DARK": "#000000", "BG_MID": "#0a0a0a", "BG_CARD": "#111111",
        "ACCENT": "#00ff41", "WARN": "#ffff00", "DANGER": "#ff0000",
        "OK": "#00ff41", "TEXT_MAIN": "#00ff41", "TEXT_DIM": "#005f1a",
        "BORDER": "#003b10",
    },
    "Solarized": {
        "BG_DARK": "#002b36", "BG_MID": "#073642", "BG_CARD": "#073642",
        "ACCENT": "#268bd2", "WARN": "#cb4b16", "DANGER": "#dc322f",
        "OK": "#859900", "TEXT_MAIN": "#839496", "TEXT_DIM": "#586e75",
        "BORDER": "#073642",
    },
    "Light": {
        "BG_DARK": "#ffffff", "BG_MID": "#f6f8fa", "BG_CARD": "#eaeef2",
        "ACCENT": "#0969da", "WARN": "#9a6700", "DANGER": "#cf222e",
        "OK": "#1a7f37", "TEXT_MAIN": "#24292f", "TEXT_DIM": "#57606a",
        "BORDER": "#d0d7de",
    },
}

# Active theme (mutable)
T = dict(THEMES["Dark"])


def apply_theme(name):
    global T
    T.update(THEMES.get(name, THEMES["Dark"]))


def make_style():
    return f"""
QMainWindow, QWidget {{
    background-color: {T['BG_DARK']};
    color: {T['TEXT_MAIN']};
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 13px;
}}
QTabWidget::pane {{
    border: 1px solid {T['BORDER']};
    background: {T['BG_MID']};
    border-radius: 6px;
}}
QTabBar::tab {{
    background: {T['BG_CARD']};
    color: {T['TEXT_DIM']};
    padding: 8px 14px;
    border: 1px solid {T['BORDER']};
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    margin-right: 2px;
    font-size: 11px;
    letter-spacing: 1px;
}}
QTabBar::tab:selected {{
    background: {T['BG_MID']};
    color: {T['ACCENT']};
    border-bottom: 2px solid {T['ACCENT']};
}}
QPushButton {{
    background: {T['BG_CARD']};
    color: {T['ACCENT']};
    border: 1px solid {T['ACCENT']};
    border-radius: 4px;
    padding: 6px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
}}
QPushButton:hover {{ background: {T['ACCENT']}; color: {T['BG_DARK']}; }}
QPushButton:disabled {{ color: {T['TEXT_DIM']}; border-color: {T['BORDER']}; }}
QPushButton#danger {{ color: {T['DANGER']}; border-color: {T['DANGER']}; }}
QPushButton#danger:hover {{ background: {T['DANGER']}; color: white; }}
QPushButton#warn {{ color: {T['WARN']}; border-color: {T['WARN']}; }}
QPushButton#warn:hover {{ background: {T['WARN']}; color: {T['BG_DARK']}; }}
QPushButton#ok {{ color: {T['OK']}; border-color: {T['OK']}; }}
QPushButton#ok:hover {{ background: {T['OK']}; color: {T['BG_DARK']}; }}
QPushButton#neutral {{ color: {T['TEXT_DIM']}; border-color: {T['BORDER']}; }}
QPushButton#neutral:hover {{ background: {T['BG_CARD']}; color: {T['TEXT_MAIN']}; }}
QTextEdit, QListWidget {{
    background: {T['BG_DARK']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 12px;
    padding: 6px;
}}
QTableWidget {{
    background: {T['BG_MID']};
    gridline-color: {T['BORDER']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    font-size: 12px;
}}
QTableWidget::item {{ padding: 5px 8px; border-bottom: 1px solid {T['BORDER']}; }}
QTableWidget::item:selected {{ background: {T['ACCENT']}; color: {T['BG_DARK']}; }}
QHeaderView::section {{
    background: {T['BG_CARD']};
    color: {T['TEXT_DIM']};
    border: none;
    border-right: 1px solid {T['BORDER']};
    border-bottom: 1px solid {T['BORDER']};
    padding: 6px 8px;
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QScrollBar:vertical {{ background: {T['BG_MID']}; width: 10px; border-radius: 5px; }}
QScrollBar::handle:vertical {{ background: {T['BORDER']}; border-radius: 5px; min-height: 20px; }}
QScrollBar:horizontal {{ background: {T['BG_MID']}; height: 10px; border-radius: 5px; }}
QScrollBar::handle:horizontal {{ background: {T['BORDER']}; border-radius: 5px; }}
QSplitter::handle {{
    background: {T['ACCENT']};
    margin: 2px;
}}
QSplitter::handle:horizontal {{ width: 4px; border-radius: 2px; }}
QSplitter::handle:vertical {{ height: 4px; border-radius: 2px; }}
QLabel#heading {{ color: {T['ACCENT']}; font-size: 11px; letter-spacing: 2px; padding: 4px 0; font-weight: bold; }}
QLabel#status {{ color: {T['TEXT_DIM']}; font-size: 11px; padding: 2px 6px; }}
QLabel#explain {{ color: {T['TEXT_MAIN']}; font-size: 12px; padding: 4px; line-height: 1.5; }}
QProgressBar {{
    border: 1px solid {T['BORDER']};
    border-radius: 6px;
    background: {T['BG_CARD']};
    height: 22px;
    text-align: center;
    font-size: 12px;
    font-weight: bold;
    color: {T['TEXT_MAIN']};
}}
QProgressBar::chunk {{ border-radius: 5px; }}
QComboBox {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}
QComboBox::drop-down {{ border: none; }}
QComboBox QAbstractItemView {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['BORDER']};
    selection-background-color: {T['ACCENT']};
    selection-color: {T['BG_DARK']};
}}
QGroupBox {{
    border: 1px solid {T['BORDER']};
    border-radius: 6px;
    margin-top: 12px;
    font-size: 11px;
    color: {T['TEXT_DIM']};
    padding: 8px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {T['ACCENT']};
}}
QToolTip {{
    background: {T['BG_CARD']};
    color: {T['TEXT_MAIN']};
    border: 1px solid {T['ACCENT']};
    padding: 6px;
    font-size: 12px;
    border-radius: 4px;
}}
QDialog {{
    background: {T['BG_MID']};
    color: {T['TEXT_MAIN']};
}}
QStatusBar {{
    background: {T['BG_CARD']};
    color: {T['TEXT_DIM']};
    font-size: 11px;
    border-top: 1px solid {T['BORDER']};
}}
"""


# ── System profile detection ──────────────────────────────────────────────────
PROFILES = {
    "gaming":     {"label": "🎮 Gaming Rig",      "normal_procs": ["steam","sunshine","steamwebhelper","gameoverlayui"], "normal_ports": ["27036","27015","47984","47989","47990","48010"]},
    "docker":     {"label": "🐳 Docker Host",     "normal_procs": ["dockerd","containerd"],           "normal_ports": ["2376","2377"]},
    "hypervisor": {"label": "🖥  Hypervisor",      "normal_procs": ["qemu","pveproxy","lxc"],          "normal_ports": ["8006","5900"]},
    "webserver":  {"label": "🌐 Web Server",       "normal_procs": ["apache2","nginx","php-fpm"],      "normal_ports": ["80","443","8080"]},
    "fileserver": {"label": "📁 File Server",      "normal_procs": ["smbd","nmbd","nfsd"],             "normal_ports": ["139","445","2049"]},
    "headless":   {"label": "⚙️  Headless Server", "normal_procs": ["sshd","systemd"],                "normal_ports": ["22"]},
    "workstation":{"label": "💼 Work Laptop",      "normal_procs": ["teams","zoom","slack","chrome"],  "normal_ports": []},
    "mixed":      {"label": "🔀 Mixed Use",        "normal_procs": [],                                 "normal_ports": []},
}

def detect_profile():
    """Auto-detect system profile from running processes and installed packages."""
    signals = {}
    try:
        procs = subprocess.run(["ps","aux"], capture_output=True, text=True).stdout.lower()
        pkgs  = subprocess.run(["dpkg-query","-W","--showformat=${Package}\n"], capture_output=True, text=True).stdout.lower()
        combined = procs + pkgs

        signals["gaming"]      = sum(1 for x in ["steam","sunshine","lutris","wine","gamemode"] if x in combined)
        signals["docker"]      = sum(1 for x in ["docker","containerd","portainer"] if x in combined)
        signals["hypervisor"]  = sum(1 for x in ["proxmox","qemu","kvm","pveproxy","lxc"] if x in combined)
        signals["webserver"]   = sum(1 for x in ["apache2","nginx","php","wordpress"] if x in combined)
        signals["fileserver"]  = sum(1 for x in ["samba","smbd","nfs","vsftpd"] if x in combined)
        signals["workstation"] = sum(1 for x in ["teams","zoom","slack","libreoffice","thunderbird"] if x in combined)
        signals["headless"]    = 1 if "DISPLAY" not in os.environ else 0
    except Exception:
        pass

    best = max(signals, key=signals.get) if signals else "mixed"
    if signals.get(best, 0) == 0:
        best = "mixed"
    return best


# ── Glossary ──────────────────────────────────────────────────────────────────
GLOSSARY = {
    "ASLR":        "Address Space Layout Randomisation — randomises where programs sit in memory, making exploits harder.",
    "mDNS":        "Multicast DNS — how devices announce themselves on a local network (like Bonjour/Avahi). Not needed on hardened servers.",
    "CVE":         "Common Vulnerabilities and Exposures — a numbered list of known security bugs in software.",
    "UFW":         "Uncomplicated Firewall — controls what network traffic is allowed in/out of your machine.",
    "Fail2ban":    "Watches login logs and temporarily bans IPs that fail too many times. Stops brute-force attacks.",
    "Core dump":   "When a program crashes, it can write its memory to disk. That memory might contain passwords or keys.",
    "Orphan":      "A package with no other software depending on it. Safe to remove but worth checking first.",
    "RDP":         "Remote Desktop Protocol — lets you see another computer's desktop remotely. Port 3389 is heavily attacked.",
    "XRDP":        "Open-source RDP server for Linux. Useful but a common attack target — prefer SSH if possible.",
    "CUPS":        "Common Unix Printing System — the print server. No use on a machine that doesn't print.",
    "Lynis":       "A free security auditing tool that checks your OS configuration against known best practices.",
    "SSH":         "Secure Shell — encrypted remote terminal access. The safe alternative to Telnet.",
    "Telnet":      "Old remote shell protocol with no encryption. Anything you type can be intercepted.",
    "Sysctl":      "Kernel runtime settings — controls low-level OS behaviour like memory layout and network stack.",
    "Hardening":   "The process of reducing attack surface by disabling unused services and tightening configuration.",
}

# ── Plain-English explanations for findings ───────────────────────────────────
EXPLANATIONS = {
    "UFW firewall enabled": {
        "what":   "UFW is your machine's front door lock. Right now the door is unlocked.",
        "why":    "Without a firewall, any service listening on a port is reachable by anything on your network — or internet if you're port-forwarded.",
        "ignore": "If you're behind a router with NAT and never expose services, low risk. But it's a 30-second fix.",
        "fix":    "Enable UFW, set a default deny rule, then allow only what you need (SSH, game ports, etc.).",
    },
    "Fail2ban installed": {
        "what":   "Fail2ban watches your login logs and bans IPs that fail too many times.",
        "why":    "Without it, an attacker can try thousands of passwords against your SSH with no consequence.",
        "ignore": "If SSH is key-only (no password auth) the risk is lower — but still worth having.",
        "fix":    "Install fail2ban and it works automatically out of the box with sane defaults.",
    },
    "Unattended upgrades enabled": {
        "what":   "Automatically installs security patches in the background.",
        "why":    "Most attacks exploit known, already-patched vulnerabilities. Keeping up with patches closes those doors.",
        "ignore": "You can do it manually, but most people forget. Auto-updates for security-only patches is low risk.",
        "fix":    "Install the package — it runs as a background service and only applies security updates by default.",
    },
    "Core dumps restricted": {
        "what":   "When a program crashes it can write its memory contents to disk.",
        "why":    "That memory snapshot can contain passwords, encryption keys, or session tokens sitting in RAM.",
        "ignore": "Low risk on a desktop unless you run sensitive services, but it's a one-line sysctl fix.",
        "fix":    "Set fs.suid_dumpable=0 in sysctl.conf — prevents privileged programs from dumping memory.",
    },
    "SSH PermitRootLogin disabled": {
        "what":   "Controls whether the root account can log in directly over SSH.",
        "why":    "Root has unlimited power. If an attacker guesses/steals root credentials, game over.",
        "ignore": "Don't ignore this — always log in as a normal user and use sudo.",
        "fix":    "Set PermitRootLogin no in /etc/ssh/sshd_config and restart SSH.",
    },
    "SSH PasswordAuthentication": {
        "what":   "Controls whether SSH accepts password logins (vs key-based only).",
        "why":    "Passwords can be brute-forced. SSH keys cannot — they're mathematically too large to guess.",
        "ignore": "If you use passwords for SSH, change to keys first before disabling this.",
        "fix":    "Set PasswordAuthentication no in /etc/ssh/sshd_config once you have SSH keys set up.",
    },
}

# ── Undo log ──────────────────────────────────────────────────────────────────
UNDO_LOG = []   # list of {"time","action","cmd","undo_cmd"}

UNDO_MAP = {
    "apt purge":                    "apt install",
    "systemctl disable --now":      "systemctl enable --now",
    "systemctl mask":               "systemctl unmask",
    "apt-get purge":                "apt-get install",
    "ufw enable":                   "ufw disable",
    "apt install":                  "apt remove",
}

def make_undo_cmd(cmd):
    for trigger, reverse in UNDO_MAP.items():
        if trigger in cmd:
            pkg = cmd.split()[-1]
            return f"{reverse} {pkg}"
    return None


# ── Risk tracker ──────────────────────────────────────────────────────────────
class RiskTracker:
    def __init__(self):
        self.findings = []

    def add(self, risk):
        self.findings.append(risk)

    def clear(self):
        self.findings = []

    def score(self):
        w = {"HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        return min(100, sum(w.get(f, 0) for f in self.findings))

    def label(self):
        s = self.score()
        if s == 0:   return "CLEAN",    T["OK"]
        if s < 20:   return "LOW",      T["OK"]
        if s < 50:   return "MODERATE", T["WARN"]
        if s < 75:   return "HIGH",     T["DANGER"]
        return "CRITICAL", T["DANGER"]


RISK = RiskTracker()


# ── Worker threads ────────────────────────────────────────────────────────────
class CommandWorker(QThread):
    output_ready = pyqtSignal(str)
    error_ready  = pyqtSignal(str)
    finished_ok  = pyqtSignal()

    def __init__(self, cmd, sudo=False, timeout=60):
        super().__init__()
        self.cmd = cmd; self.sudo = sudo; self.timeout = timeout

    def run(self):
        try:
            full = (["sudo"] + self.cmd) if self.sudo else self.cmd
            p = subprocess.run(full, capture_output=True, text=True, timeout=self.timeout)
            if p.stdout: self.output_ready.emit(p.stdout)
            if p.stderr: self.error_ready.emit(p.stderr)
            self.finished_ok.emit()
        except subprocess.TimeoutExpired:
            self.error_ready.emit("Timed out.")
        except Exception as e:
            self.error_ready.emit(str(e))


class HttpWorker(QThread):
    result_ready = pyqtSignal(str, object)
    finished_ok  = pyqtSignal()

    def __init__(self, packages):
        super().__init__()
        self.packages = packages

    def run(self):
        base = "https://ubuntu.com/security/cves.json?package={}&limit=5"
        for name, version in self.packages:
            try:
                url = base.format(urllib.parse.quote(name))
                req = urllib.request.Request(url, headers={"User-Agent": "linux-audit/3.0"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    data = json.loads(r.read())
                self.result_ready.emit(name, (version, data))
            except Exception:
                self.result_ready.emit(name, None)
        self.finished_ok.emit()


# ── ANSI stripper ─────────────────────────────────────────────────────────────
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m|\[[\d;]+m')

def strip_ansi(text):
    return ANSI_RE.sub("", text)


# ── Terminal panel ────────────────────────────────────────────────────────────
class TerminalPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        hdr_row = QHBoxLayout()
        hdr = QLabel("TERMINAL OUTPUT")
        hdr.setObjectName("heading")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        clr = QPushButton("CLEAR")
        clr.setObjectName("neutral")
        clr.setFixedHeight(24)
        clr.clicked.connect(self._clear)
        hdr_row.addWidget(clr)
        layout.addLayout(hdr_row)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Run a scan to see output here...")
        layout.addWidget(self.output)

    def _clear(self):
        self.output.clear()

    def append(self, text, colour=None):
        text = strip_ansi(text)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(colour or T["TEXT_MAIN"]))
        cursor.setCharFormat(fmt)
        cursor.insertText(text + "\n")
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def append_cmd(self, cmd):
        self.append(f"\n$ {cmd}", T["ACCENT"])

    def append_err(self, text):
        self.append(strip_ansi(text), T["DANGER"])


# ── Risk score panel ──────────────────────────────────────────────────────────
class RiskScorePanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(56)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)

        lbl = QLabel("SYSTEM RISK")
        lbl.setObjectName("heading")
        lbl.setFixedWidth(120)
        layout.addWidget(lbl)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setFormat("0 / 100  —  CLEAN")
        layout.addWidget(self.bar)

        self.profile_lbl = QLabel("Profile: detecting...")
        self.profile_lbl.setObjectName("status")
        self.profile_lbl.setFixedWidth(220)
        layout.addWidget(self.profile_lbl)

        self.detail = QLabel("")
        self.detail.setObjectName("status")
        self.detail.setFixedWidth(180)
        layout.addWidget(self.detail)

    def update_score(self):
        score = RISK.score()
        label, colour = RISK.label()
        self.bar.setValue(score)
        self.bar.setFormat(f"{score} / 100  —  {label}")
        self.bar.setStyleSheet(f"QProgressBar::chunk {{ background: {colour}; border-radius: 5px; }}")
        h = sum(1 for f in RISK.findings if f == "HIGH")
        m = sum(1 for f in RISK.findings if f == "MEDIUM")
        l = sum(1 for f in RISK.findings if f == "LOW")
        self.detail.setText(f"H:{h}  M:{m}  L:{l}")

    def set_profile(self, profile_key):
        label = PROFILES.get(profile_key, {}).get("label", "Unknown")
        self.profile_lbl.setText(f"Profile: {label}")


# ── Profile detection dialog ──────────────────────────────────────────────────
class ProfileDialog(QDialog):
    def __init__(self, detected_key, parent=None):
        super().__init__(parent)
        self.setWindowTitle("System Profile Detection")
        self.setMinimumWidth(480)
        self.selected = detected_key

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        detected_label = PROFILES.get(detected_key, {}).get("label", "Unknown")

        title = QLabel("System Profile Detected")
        title.setObjectName("heading")
        layout.addWidget(title)

        msg = QLabel(
            f"Based on what's running, this looks like a:\n\n"
            f"  <b>{detected_label}</b>\n\n"
            f"The profile affects what gets flagged as 'normal' vs 'suspicious'.\n"
            f"Is that correct, or would you like to pick manually?"
        )
        msg.setWordWrap(True)
        msg.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(msg)

        self.btn_group = QButtonGroup(self)
        for key, info in PROFILES.items():
            rb = QRadioButton(info["label"])
            rb.setChecked(key == detected_key)
            rb.clicked.connect(lambda _, k=key: setattr(self, "selected", k))
            self.btn_group.addButton(rb)
            layout.addWidget(rb)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ── Show Code dialog ──────────────────────────────────────────────────────────
class ShowCodeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Underlying Commands — Show Code")
        self.resize(780, 600)
        layout = QVBoxLayout(self)

        hdr = QLabel("ALL COMMANDS THIS APP CAN RUN")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel(
            "These are the exact shell commands the app runs when you click buttons.\n"
            "You can copy any of these and run them manually in a terminal."
        )
        info.setWordWrap(True)
        info.setObjectName("status")
        layout.addWidget(info)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(QFont("Courier New", 11))
        layout.addWidget(self.text)

        COMMANDS = """
═══════════════════════════════════════════════════════
  LINUX SECURITY AUDIT DASHBOARD v3 — COMMAND REFERENCE
═══════════════════════════════════════════════════════

── SCAN: Orphaned Packages ──────────────────────────
deborphan
  Lists packages with no other packages depending on them.
  Safe to review and remove.

sudo apt-get purge <package>
  Removes a package AND its config files.

── SCAN: Network Listeners ──────────────────────────
ss -tunlp
  Shows all open TCP/UDP ports, what process owns them,
  and whether they're listening to localhost or all interfaces.
  t=TCP  u=UDP  n=numeric  l=listening  p=process

── SCAN: Risky Services ─────────────────────────────
dpkg -l <package>
  Checks if a package is installed. 'ii' in output = installed.

sudo apt purge telnet
sudo apt purge ftp
sudo apt purge xrdp
sudo apt purge cups
sudo apt purge avahi-daemon
  Removes specific insecure or unnecessary services.

sudo systemctl disable --now <service>
  Stops a service immediately and prevents it starting on boot.

sudo systemctl mask <service>
  'Nuclear option' — prevents ANY process from starting this service.

── SCAN: Installed Packages ─────────────────────────
dpkg-query -W --showformat='${Package} ${Version}\n'
  Lists every installed package and its version.

── CVE: Version Checking ────────────────────────────
dpkg-query -W -f='${Version}' <package>
  Gets the installed version of a specific package.

https://ubuntu.com/security/cves.json?package=<name>&limit=5
  Ubuntu Security CVE API — returns known CVEs for a package.

apt list --upgradable
  Shows packages that have newer versions available.

sudo apt-get upgrade -y
  Upgrades all packages to their latest available versions.

sudo apt-get upgrade <package>
  Upgrades a single specific package.

── HARDENING: Lynis ─────────────────────────────────
sudo apt install lynis -y
  Installs the Lynis security auditing tool.

sudo lynis audit system --quick
  Runs a full system security audit. Takes ~60 seconds.
  Output goes to /var/log/lynis.log and /var/log/lynis-report.dat

── HARDENING: Quick Checks ──────────────────────────
grep -i PermitRootLogin /etc/ssh/sshd_config
  Checks if root SSH login is disabled.

grep -i PasswordAuthentication /etc/ssh/sshd_config
  Checks if password-based SSH is enabled (vs key-only).

ufw status
  Shows if the UFW firewall is active.

sudo ufw enable
  Enables the UFW firewall.

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
  Recommended UFW setup — deny all in, allow SSH.

which fail2ban-server
  Checks if fail2ban is installed.

sudo apt install fail2ban
  Installs fail2ban — auto-bans IPs with too many failed logins.

sudo apt install unattended-upgrades
  Installs automatic security update service.

ls -la /etc/passwd
  Checks permissions on the password file (should be 644).

sysctl fs.suid_dumpable
  Checks if core dumps are restricted (should be 0).

sysctl kernel.randomize_va_space
  Checks if ASLR is enabled (should be 2).

echo 'fs.suid_dumpable=0' | sudo tee -a /etc/sysctl.conf
  Disables core dumps for setuid programs.

echo 'kernel.randomize_va_space=2' | sudo tee -a /etc/sysctl.conf
  Enables full ASLR.

sudo sysctl -p
  Applies sysctl changes immediately without rebooting.

── UNDO OPERATIONS ──────────────────────────────────
sudo apt install <package>
  Reinstalls a previously removed package.

sudo systemctl enable --now <service>
  Re-enables a previously disabled service.

sudo systemctl unmask <service>
  Removes a mask from a previously masked service.

═══════════════════════════════════════════════════════
"""
        self.text.setPlainText(COMMANDS)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.close)
        layout.addWidget(btns)


# ── Explain dialog ────────────────────────────────────────────────────────────
class ExplainDialog(QDialog):
    def __init__(self, name, ftype, risk, detail, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Explain: {name}")
        self.setMinimumWidth(500)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel(f"⬡  {name}")
        title.setStyleSheet(f"color: {T['ACCENT']}; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        risk_colours = {"HIGH": T["DANGER"], "MEDIUM": T["WARN"], "LOW": T["OK"], "INFO": T["ACCENT"]}
        risk_lbl = QLabel(f"Risk Level: {risk}   |   Type: {ftype}")
        risk_lbl.setStyleSheet(f"color: {risk_colours.get(risk, T['TEXT_DIM'])}; font-weight: bold;")
        layout.addWidget(risk_lbl)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        # Look up explanation
        exp = EXPLANATIONS.get(name, {})
        if exp:
            for section, content in [
                ("📌 What is this?",    exp.get("what", "")),
                ("⚠️  Why does it matter?", exp.get("why", "")),
                ("🤔 What if I ignore it?", exp.get("ignore", "")),
                ("🔧 How to fix it:",   exp.get("fix", "")),
            ]:
                if content:
                    sec_lbl = QLabel(section)
                    sec_lbl.setStyleSheet(f"color: {T['ACCENT']}; font-weight: bold; font-size: 12px;")
                    layout.addWidget(sec_lbl)
                    content_lbl = QLabel(content)
                    content_lbl.setObjectName("explain")
                    content_lbl.setWordWrap(True)
                    content_lbl.setStyleSheet(f"color: {T['TEXT_MAIN']}; padding-left: 12px;")
                    layout.addWidget(content_lbl)
        else:
            # Generic explanation from detail
            gen = QLabel(
                f"Finding: {detail}\n\n"
                f"Type '{ftype}' findings are identified during system scans.\n"
                f"Risk '{risk}' means: "
                + {"HIGH": "take action soon — this is a real security concern.",
                   "MEDIUM": "worth addressing — reduces your attack surface.",
                   "LOW": "minor concern — safe to review at your convenience.",
                   "INFO": "informational — no immediate action needed."}.get(risk, "review when convenient.")
            )
            gen.setObjectName("explain")
            gen.setWordWrap(True)
            layout.addWidget(gen)

        # Glossary terms
        found_terms = {k: v for k, v in GLOSSARY.items() if k.lower() in (name + detail).lower()}
        if found_terms:
            sep2 = QFrame(); sep2.setFrameShape(QFrame.Shape.HLine)
            layout.addWidget(sep2)
            gloss_hdr = QLabel("📖 Glossary")
            gloss_hdr.setStyleSheet(f"color: {T['ACCENT']}; font-weight: bold;")
            layout.addWidget(gloss_hdr)
            for term, defn in found_terms.items():
                t_lbl = QLabel(f"<b>{term}</b>: {defn}")
                t_lbl.setObjectName("explain")
                t_lbl.setWordWrap(True)
                t_lbl.setStyleSheet(f"color: {T['TEXT_DIM']}; padding-left: 12px;")
                layout.addWidget(t_lbl)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.close)
        layout.addWidget(btns)


# ── Pre-action confirmation dialog ────────────────────────────────────────────
class PreActionDialog(QDialog):
    def __init__(self, action_type, name, cmd, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Confirm: {action_type.title()} '{name}'")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel(f"⚠️  About to {action_type}: {name}")
        title.setStyleSheet(f"color: {T['WARN']}; font-size: 13px; font-weight: bold;")
        layout.addWidget(title)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        cmd_lbl = QLabel("Command that will run:")
        cmd_lbl.setStyleSheet(f"color: {T['TEXT_DIM']}; font-size: 11px;")
        layout.addWidget(cmd_lbl)

        cmd_box = QTextEdit()
        cmd_box.setPlainText(f"sudo {cmd}")
        cmd_box.setReadOnly(True)
        cmd_box.setMaximumHeight(60)
        cmd_box.setStyleSheet(f"background: {T['BG_DARK']}; color: {T['ACCENT']}; font-family: monospace;")
        layout.addWidget(cmd_box)

        impact_lbl = QLabel("What this will do:")
        impact_lbl.setStyleSheet(f"color: {T['TEXT_DIM']}; font-size: 11px;")
        layout.addWidget(impact_lbl)

        impacts = {
            "remove":  f"'{name}' will be uninstalled and its config files removed from this system.",
            "disable": f"'{name}' service will be stopped now and will NOT start on next boot.",
            "upgrade": f"'{name}' will be upgraded to the latest available version.",
        }
        impact = QLabel(impacts.get(action_type, f"Will run: sudo {cmd}"))
        impact.setWordWrap(True)
        impact.setStyleSheet(f"color: {T['TEXT_MAIN']}; padding: 6px; background: {T['BG_CARD']}; border-radius: 4px;")
        layout.addWidget(impact)

        # Undo note
        undo = make_undo_cmd(cmd)
        if undo:
            undo_lbl = QLabel(f"↩  To undo: sudo {undo}")
            undo_lbl.setStyleSheet(f"color: {T['TEXT_DIM']}; font-size: 11px; font-style: italic;")
            layout.addWidget(undo_lbl)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Yes, proceed")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ── Findings table ────────────────────────────────────────────────────────────
class FindingsTable(QTableWidget):
    score_changed = pyqtSignal()

    def __init__(self, terminal, profile_key="mixed"):
        super().__init__()
        self.terminal = terminal
        self.profile_key = profile_key
        self._workers = []

        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["NAME", "TYPE", "RISK", "TAG", "DETAIL", "ACTIONS"])
        hh = self.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setStyleSheet(f"alternate-background-color: {T['BG_DARK']};")
        self.cellDoubleClicked.connect(self._on_double_click)

    def _get_tag(self, name, ftype):
        profile = PROFILES.get(self.profile_key, {})
        normal_procs = profile.get("normal_procs", [])
        normal_ports = profile.get("normal_ports", [])
        name_lower = name.lower()

        # Check if it's a normal process for this profile
        for proc in normal_procs:
            if proc in name_lower:
                return "NORMAL", T["OK"]

        # Check if it's a normal port for this profile
        port_m = re.search(r':(\d+)$', name)
        if port_m and port_m.group(1) in normal_ports:
            return "NORMAL", T["OK"]

        if ftype == "ORPHAN":       return "ORPHAN",  T["TEXT_DIM"]
        if ftype == "NETWORK":      return "NETWORK", T["WARN"]
        if ftype == "SERVICE":      return "SERVICE", T["WARN"]
        if ftype == "CVE":          return "CVE",     T["DANGER"]
        if ftype == "HARDENING":    return "HARDEN",  T["WARN"]
        if ftype == "OUTDATED":     return "UPDATE",  T["TEXT_DIM"]
        return "REVIEW", T["TEXT_DIM"]

    def add_finding(self, name, ftype, risk, detail, cmd_remove=None, cmd_disable=None):
        RISK.add(risk)
        self.score_changed.emit()
        row = self.rowCount()
        self.insertRow(row)

        risk_colours = {"HIGH": T["DANGER"], "MEDIUM": T["WARN"], "LOW": T["OK"], "INFO": T["ACCENT"]}
        rc = risk_colours.get(risk, T["TEXT_MAIN"])
        tag, tag_colour = self._get_tag(name, ftype)

        # Store data for double-click explain
        self.setItem(row, 0, self._item(name))
        self.setItem(row, 1, self._item(ftype))

        risk_item = self._item(risk)
        risk_item.setForeground(QColor(rc))
        risk_item.setFont(QFont("", -1, QFont.Weight.Bold))
        self.setItem(row, 2, risk_item)

        tag_item = self._item(tag)
        tag_item.setForeground(QColor(tag_colour))
        self.setItem(row, 3, tag_item)

        self.setItem(row, 4, self._item(detail))

        # Actions cell
        cell = QWidget()
        cell.setStyleSheet("background: transparent;")
        bl = QHBoxLayout(cell)
        bl.setContentsMargins(3, 2, 3, 2)
        bl.setSpacing(3)

        exp_btn = QPushButton("?")
        exp_btn.setObjectName("neutral")
        exp_btn.setFixedSize(26, 24)
        exp_btn.setToolTip("Explain this finding in plain English")
        exp_btn.clicked.connect(lambda _, n=name, ft=ftype, r=risk, d=detail: self._explain(n, ft, r, d))
        bl.addWidget(exp_btn)

        if cmd_remove:
            rb = QPushButton("REMOVE")
            rb.setObjectName("danger")
            rb.setFixedHeight(24)
            rb.clicked.connect(lambda _, c=cmd_remove, n=name: self._act(c, n, "remove"))
            bl.addWidget(rb)

        if cmd_disable:
            db = QPushButton("DISABLE")
            db.setObjectName("warn")
            db.setFixedHeight(24)
            db.clicked.connect(lambda _, c=cmd_disable, n=name: self._act(c, n, "disable"))
            bl.addWidget(db)

        bl.addStretch()
        self.setCellWidget(row, 5, cell)
        self.setRowHeight(row, 36)

    def _item(self, text):
        item = QTableWidgetItem(str(text))
        item.setForeground(QColor(T["TEXT_MAIN"]))
        return item

    def _explain(self, name, ftype, risk, detail):
        dlg = ExplainDialog(name, ftype, risk, detail, self)
        dlg.exec()

    def _on_double_click(self, row, col):
        name   = self.item(row, 0).text() if self.item(row, 0) else ""
        ftype  = self.item(row, 1).text() if self.item(row, 1) else ""
        risk   = self.item(row, 2).text() if self.item(row, 2) else ""
        detail = self.item(row, 4).text() if self.item(row, 4) else ""
        self._explain(name, ftype, risk, detail)

    def _act(self, cmd, name, action_type):
        dlg = PreActionDialog(action_type, name, cmd, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.terminal.append_cmd(f"sudo {cmd}")
            undo = make_undo_cmd(cmd)
            UNDO_LOG.append({
                "time":     datetime.datetime.now().strftime("%H:%M:%S"),
                "action":   f"{action_type} {name}",
                "cmd":      f"sudo {cmd}",
                "undo_cmd": f"sudo {undo}" if undo else "N/A",
            })
            w = CommandWorker(cmd.split(), sudo=True)
            w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
            w.error_ready.connect(self.terminal.append_err)
            w.finished_ok.connect(lambda: self._verify(cmd, name))
            self._workers.append(w)
            w.start()

    def _verify(self, cmd, name):
        """Quick post-action verification."""
        pkg = cmd.split()[-1]
        r = subprocess.run(["dpkg", "-l", pkg], capture_output=True, text=True)
        if "purge" in cmd or "remove" in cmd:
            if "ii" not in r.stdout:
                self.terminal.append(f"  ✓ Verified: '{pkg}' successfully removed.", T["OK"])
            else:
                self.terminal.append(f"  ✗ Verify failed: '{pkg}' still appears installed.", T["DANGER"])
        else:
            self.terminal.append(f"  ✓ Action complete: '{name}'", T["OK"])

    def clear_findings(self):
        self.setRowCount(0)
        RISK.clear()
        self.score_changed.emit()


# ── Scan tab ──────────────────────────────────────────────────────────────────
class ScanTab(QWidget):
    def __init__(self, terminal, findings):
        super().__init__()
        self.terminal = terminal
        self.findings = findings
        self._workers = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        hdr = QLabel("SCAN CONTROLS")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        scans = [
            ("🔍  ORPHANED PACKAGES",  self._scan_orphans,  "deborphan — unused packages"),
            ("📡  NETWORK LISTENERS",  self._scan_network,  "ss -tunlp — open ports & processes"),
            ("⚠️   RISKY SERVICES",    self._scan_services, "Known insecure services"),
            ("📦  ALL INSTALLED",      self._scan_installed,"Full package list"),
            ("🔒  RUN ALL SCANS",      self._run_all,       "Full audit in one click"),
        ]
        for label, handler, tip in scans:
            btn = QPushButton(label)
            btn.setToolTip(tip)
            btn.setFixedHeight(38)
            if "ALL" in label: btn.setObjectName("ok")
            btn.clicked.connect(handler)
            layout.addWidget(btn)

        layout.addStretch()
        self.status = QLabel("Ready.")
        self.status.setObjectName("status")
        layout.addWidget(self.status)

    def _run_cmd(self, cmd, label, cb=None):
        self.terminal.append_cmd(" ".join(cmd))
        self.status.setText(f"Running: {label}...")
        w = CommandWorker(cmd)
        w.output_ready.connect(lambda t: self.terminal.append(t))
        w.error_ready.connect(self.terminal.append_err)
        if cb: w.output_ready.connect(cb)
        w.finished_ok.connect(lambda: self.status.setText("Done."))
        self._workers.append(w)
        w.start()

    def _scan_orphans(self):
        self._run_cmd(["deborphan"], "Orphan scan", self._parse_orphans)

    def _parse_orphans(self, text):
        for line in text.strip().splitlines():
            pkg = line.strip()
            if not pkg: continue
            risk = "HIGH" if pkg in ("telnet","ftp") else "LOW"
            reason = "Insecure clear-text protocol — remove immediately" if risk == "HIGH" else "No dependents — safe to review and remove"
            self.findings.add_finding(pkg, "ORPHAN", risk, reason, f"apt-get purge {pkg}")

    def _scan_network(self):
        self._run_cmd(["ss","-tunlp"], "Network scan", self._parse_network)

    def _parse_network(self, text):
        risky = {
            "21":   ("FTP",    "HIGH",   "Clear-text file transfer — no encryption",    "apt purge ftp",   None),
            "23":   ("TELNET", "HIGH",   "Clear-text remote shell — easily intercepted","apt purge telnet",None),
            "3389": ("XRDP",   "MEDIUM", "Remote Desktop — heavily targeted by scanners","apt purge xrdp", "systemctl disable --now xrdp"),
            "631":  ("CUPS",   "MEDIUM", "Print server — unneeded attack surface",      "apt purge cups",  "systemctl mask cups"),
            "5353": ("mDNS",   "LOW",    "Device discovery broadcasts on local network",None,              "systemctl disable --now avahi-daemon"),
        }
        seen = set()
        for line in text.strip().splitlines():
            if "LISTEN" not in line and "UNCONN" not in line: continue
            m = re.search(r':(\d+)\s+\S+:\*', line)
            if not m: continue
            port = m.group(1)
            if port in seen: continue
            seen.add(port)
            pm = re.search(r'users:\(\("([^"]+)"', line)
            proc = pm.group(1) if pm else "unknown"
            if port in risky:
                svc, risk, reason, rem, dis = risky[port]
                self.findings.add_finding(f"{proc}:{port}", "NETWORK", risk, f"Port {port} — {reason}", rem, dis)

    def _scan_services(self):
        risky = [
            ("telnet",        "SERVICE","HIGH",  "Unencrypted remote shell — anyone on network can sniff traffic",       "apt purge telnet",       None),
            ("ftp",           "SERVICE","HIGH",  "Unencrypted file transfer — credentials sent in plain text",           "apt purge ftp",          None),
            ("xrdp",          "SERVICE","MEDIUM","Remote Desktop server — port 3389 is one of most scanned on internet", "apt purge xrdp",         "systemctl disable --now xrdp"),
            ("cups",          "SERVICE","MEDIUM","Print server — unnecessary on non-printing machines",                  "apt purge cups",         "systemctl mask cups"),
            ("avahi-daemon",  "SERVICE","LOW",   "mDNS broadcasts — announces your machine to the local network",        "apt purge avahi-daemon", "systemctl disable --now avahi-daemon"),
            ("rsh-server",    "SERVICE","HIGH",  "Legacy unencrypted remote shell — obsolete, insecure",                 "apt purge rsh-server",   None),
            ("rpcbind",       "SERVICE","MEDIUM","NFS portmapper — only needed for network file shares",                  None,                    "systemctl disable --now rpcbind"),
            ("nfs-kernel-server","SERVICE","MEDIUM","NFS file server — only needed if sharing files over network",        None,                    "systemctl disable --now nfs-kernel-server"),
        ]
        self.terminal.append_cmd("# Checking risky services...")
        for item in risky:
            name = item[0]
            r = subprocess.run(["dpkg","-l",name], capture_output=True, text=True)
            if "ii" in r.stdout:
                self.findings.add_finding(*item)
                self.terminal.append(f"  FOUND: {name}", T["WARN"])
            else:
                self.terminal.append(f"  OK:    {name} not installed", T["OK"])
        self.terminal.append("Service check complete.", T["ACCENT"])

    def _scan_installed(self):
        self._run_cmd(["dpkg-query","-W","--showformat=${Package} ${Version}\n"], "Installed packages")

    def _run_all(self):
        self.findings.clear_findings()
        self._scan_orphans()
        QTimer.singleShot(600,  self._scan_network)
        QTimer.singleShot(1200, self._scan_services)


# ── CVE tab ───────────────────────────────────────────────────────────────────
class CveTab(QWidget):
    def __init__(self, terminal, findings):
        super().__init__()
        self.terminal = terminal
        self.findings = findings
        self._workers = []

        HIGH_VALUE = [
            "openssh-server","openssh-client","openssl","sudo","bash","curl","wget",
            "python3","perl","apache2","nginx","samba","rsync","git","docker.io",
            "containerd","postgresql","mysql-server","sqlite3","firefox","libc6",
            "libssl3","libssl1.1","gpg","gnupg","apt",
        ]
        self.HIGH_VALUE = HIGH_VALUE

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        hdr = QLabel("CVE & VERSION CHECK")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel("Checks installed packages against Ubuntu's live CVE security tracker.\nRequires internet connection.")
        info.setStyleSheet(f"color: {T['TEXT_DIM']}; font-size: 11px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        for label, handler, obj in [
            ("🎯  SCAN HIGH-VALUE PACKAGES",  self._scan_fast,       "ok"),
            ("📋  CHECK APT UPGRADABLE LIST", self._scan_upgradable,  ""),
            ("🔄  RUN SECURITY UPGRADES",     self._run_upgrade,      "warn"),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(38)
            if obj: btn.setObjectName(obj)
            btn.clicked.connect(handler)
            layout.addWidget(btn)

        layout.addStretch()
        self.status = QLabel("Ready.")
        self.status.setObjectName("status")
        layout.addWidget(self.status)

        self.cve_table = QTableWidget()
        self.cve_table.setColumnCount(4)
        self.cve_table.setHorizontalHeaderLabels(["PACKAGE","INSTALLED VER","CVE COUNT","HIGHEST"])
        ch = self.cve_table.horizontalHeader()
        ch.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        ch.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        ch.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        ch.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.cve_table.verticalHeader().setVisible(False)
        self.cve_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cve_table.setAlternatingRowColors(True)
        layout.addWidget(self.cve_table)

    def _get_ver(self, pkg):
        r = subprocess.run(["dpkg-query","-W","-f=${Version}",pkg], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    def _scan_fast(self):
        self.cve_table.setRowCount(0)
        self.status.setText("Finding installed high-value packages...")
        targets = [(p, v) for p in self.HIGH_VALUE if (v := self._get_ver(p))]
        self.terminal.append_cmd(f"# CVE scan — {len(targets)} packages found")
        if not targets:
            self.status.setText("No high-value packages found.")
            return
        self.status.setText(f"Querying CVE tracker for {len(targets)} packages...")
        w = HttpWorker(targets)
        w.result_ready.connect(self._handle_cve)
        w.finished_ok.connect(lambda: self.status.setText("CVE scan complete."))
        self._workers.append(w)
        w.start()

    def _handle_cve(self, pkg, data):
        if data is None:
            self.terminal.append(f"  CVE lookup failed: {pkg}", T["WARN"])
            return
        version, cve_data = data
        cves = cve_data.get("cves", [])
        count = len(cves)
        sev_order = ["critical","high","medium","low","negligible"]
        highest = "none"
        for sev in sev_order:
            if any(c.get("cvss_severity","").lower() == sev for c in cves):
                highest = sev; break
        sc = {
            "critical": T["DANGER"],"high": T["DANGER"],
            "medium": T["WARN"],"low": T["OK"],"negligible": T["TEXT_DIM"],"none": T["TEXT_DIM"]
        }.get(highest, T["TEXT_DIM"])

        row = self.cve_table.rowCount()
        self.cve_table.insertRow(row)
        self.cve_table.setItem(row, 0, QTableWidgetItem(pkg))
        self.cve_table.setItem(row, 1, QTableWidgetItem(version))
        ci = QTableWidgetItem(str(count))
        if count > 0: ci.setForeground(QColor(T["WARN"] if count < 5 else T["DANGER"]))
        self.cve_table.setItem(row, 2, ci)
        si = QTableWidgetItem(highest.upper())
        si.setForeground(QColor(sc))
        self.cve_table.setItem(row, 3, si)
        self.cve_table.setRowHeight(row, 30)

        if highest in ("critical","high") and count > 0:
            self.findings.add_finding(
                pkg, "CVE", "HIGH" if highest == "critical" else "MEDIUM",
                f"{count} CVEs — highest: {highest.upper()} (installed: {version})",
                f"apt-get upgrade {pkg}"
            )

    def _scan_upgradable(self):
        self.terminal.append_cmd("apt list --upgradable")
        w = CommandWorker(["apt","list","--upgradable"])
        w.output_ready.connect(self._parse_upgradable)
        w.error_ready.connect(self.terminal.append_err)
        self._workers.append(w)
        w.start()

    def _parse_upgradable(self, text):
        lines = [l for l in text.splitlines() if "/" in l and "upgradable" not in l]
        self.terminal.append(f"  {len(lines)} packages have updates available.", T["WARN"])
        for line in lines[:30]:
            pkg = line.split("/")[0].strip()
            self.terminal.append(f"    → {line.strip()}", T["TEXT_DIM"])
            self.findings.add_finding(pkg, "OUTDATED", "LOW", "Update available — run apt upgrade", f"apt-get upgrade {pkg}")
        if len(lines) > 30:
            self.terminal.append(f"  ... and {len(lines)-30} more.", T["TEXT_DIM"])

    def _run_upgrade(self):
        dlg = PreActionDialog("upgrade", "all packages", "apt-get upgrade -y", self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.terminal.append_cmd("sudo apt-get upgrade -y")
            w = CommandWorker(["apt-get","upgrade","-y"], sudo=True, timeout=300)
            w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
            w.error_ready.connect(self.terminal.append_err)
            w.finished_ok.connect(lambda: self.terminal.append("Upgrade complete.", T["OK"]))
            self._workers.append(w)
            w.start()


# ── Hardening tab ─────────────────────────────────────────────────────────────
class HardeningTab(QWidget):
    def __init__(self, terminal, findings):
        super().__init__()
        self.terminal = terminal
        self.findings = findings
        self._workers = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        hdr = QLabel("OS HARDENING / LYNIS")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        for label, handler, obj in [
            ("📥  INSTALL LYNIS",             self._install_lynis, ""),
            ("🛡️   RUN LYNIS AUDIT  (~60s)",  self._run_lynis,     "ok"),
            ("⚡  QUICK CONFIG CHECKS",        self._quick_checks,  ""),
            ("🔧  GUIDED FIX WIZARD",          self._guided_wizard, "warn"),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(38)
            if obj: btn.setObjectName(obj)
            btn.clicked.connect(handler)
            layout.addWidget(btn)

        layout.addStretch()
        self.status = QLabel("Ready.")
        self.status.setObjectName("status")
        layout.addWidget(self.status)

        self.lynis_out = QTextEdit()
        self.lynis_out.setReadOnly(True)
        self.lynis_out.setPlaceholderText("Lynis / hardening output appears here...")
        layout.addWidget(self.lynis_out)

    def _lappend(self, text, colour=None):
        text = strip_ansi(text)
        cursor = self.lynis_out.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(colour or T["TEXT_MAIN"]))
        cursor.setCharFormat(fmt)
        cursor.insertText(text + "\n")
        self.lynis_out.setTextCursor(cursor)
        self.lynis_out.ensureCursorVisible()

    def _install_lynis(self):
        self.terminal.append_cmd("sudo apt install lynis -y")
        w = CommandWorker(["apt","install","lynis","-y"], sudo=True, timeout=120)
        w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
        w.error_ready.connect(self.terminal.append_err)
        w.finished_ok.connect(lambda: self.status.setText("Lynis installed."))
        self._workers.append(w); w.start()

    def _run_lynis(self):
        r = subprocess.run(["which","lynis"], capture_output=True, text=True)
        if not r.stdout.strip():
            QMessageBox.warning(self, "Lynis Not Found", "Click 'Install Lynis' first.")
            return
        self.lynis_out.clear()
        self.status.setText("Running Lynis — ~60 seconds...")
        self.terminal.append_cmd("sudo lynis audit system --quick")
        self._lappend("Running Lynis audit, please wait...", T["ACCENT"])
        w = CommandWorker(["lynis","audit","system","--quick"], sudo=True, timeout=180)
        w.output_ready.connect(self._parse_lynis)
        w.error_ready.connect(lambda t: self._lappend(t, T["DANGER"]))
        w.finished_ok.connect(lambda: self.status.setText("Lynis complete."))
        self._workers.append(w); w.start()

    def _parse_lynis(self, text):
        self.lynis_out.clear()
        text = strip_ansi(text)

        # Try structured log first
        try:
            with open("/var/log/lynis.log","r") as f:
                log = f.read()
            self._parse_lynis_log(log)
            return
        except Exception:
            pass

        # Parse hardening index from stdout
        idx_m = re.search(r'Hardening index\s*[:\|]\s*(\d+)', text, re.I)
        if idx_m:
            idx = int(idx_m.group(1))
            ic = T["OK"] if idx > 70 else (T["WARN"] if idx > 40 else T["DANGER"])
            self._lappend(f"\n  Lynis Hardening Index: {idx} / 100", ic)

        warn_count = 0
        for line in text.splitlines():
            clean = strip_ansi(line).strip()
            if not clean: continue
            if "Warning" in clean:
                self._lappend(f"  ⚠  {clean}", T["WARN"])
                warn_count += 1
                self.findings.add_finding(clean[:60], "HARDENING", "MEDIUM", clean, None, None)
            elif "Suggestion" in clean or "ℹ" in clean:
                self._lappend(f"  ℹ  {clean}", T["TEXT_DIM"])

        self._lappend(f"\n── {warn_count} warnings found ──", T["ACCENT"])

    def _parse_lynis_log(self, log):
        warns = []
        suggs = []
        idx = None
        for line in log.splitlines():
            if "|WARNING|" in line:
                parts = line.split("|")
                if len(parts) > 2: warns.append(parts[-1].strip())
            elif "|SUGGESTION|" in line:
                parts = line.split("|")
                if len(parts) > 2: suggs.append(parts[-1].strip())
            m = re.search(r'hardening_index=(\d+)', line, re.I)
            if m: idx = int(m.group(1))

        if idx is not None:
            ic = T["OK"] if idx > 70 else (T["WARN"] if idx > 40 else T["DANGER"])
            self._lappend(f"  Lynis Hardening Index: {idx} / 100", ic)

        self._lappend(f"\n── WARNINGS ({len(warns)}) ──", T["WARN"])
        for w in warns:
            self._lappend(f"  ⚠  {w}", T["WARN"])
            self.findings.add_finding(w[:60], "HARDENING", "MEDIUM", w, None, None)

        self._lappend(f"\n── SUGGESTIONS ({len(suggs)}) ──", T["TEXT_DIM"])
        for s in suggs[:20]:
            self._lappend(f"  ℹ  {s}", T["TEXT_DIM"])

        if not warns and not suggs:
            self._lappend("No structured data found in log. Check terminal output.", T["WARN"])

    def _quick_checks(self):
        self.lynis_out.clear()
        self.status.setText("Running quick checks...")
        self._lappend("Quick Hardening Checks\n" + "─"*44, T["ACCENT"])

        CHECKS = [
            ("SSH PermitRootLogin disabled",
             ["grep","-i","PermitRootLogin","/etc/ssh/sshd_config"],
             lambda o: "no" in o.lower() or "prohibit" in o.lower(),
             "Edit /etc/ssh/sshd_config → PermitRootLogin no",
             "Prevents attackers from logging in directly as root over SSH."),

            ("SSH PasswordAuthentication",
             ["grep","-i","PasswordAuthentication","/etc/ssh/sshd_config"],
             lambda o: "yes" not in o.lower(),
             "Edit /etc/ssh/sshd_config → PasswordAuthentication no",
             "Forces key-based login only — passwords can be brute-forced, keys cannot."),

            ("UFW firewall enabled",
             ["ufw","status"],
             lambda o: "active" in o.lower(),
             "sudo ufw enable",
             "Your firewall is off. UFW controls what traffic can reach your machine."),

            ("Fail2ban installed",
             ["which","fail2ban-server"],
             lambda o: bool(o.strip()),
             "sudo apt install fail2ban",
             "Blocks IPs that repeatedly fail login attempts — stops brute-force attacks on SSH."),

            ("Unattended upgrades enabled",
             ["dpkg","-l","unattended-upgrades"],
             lambda o: "ii" in o,
             "sudo apt install unattended-upgrades",
             "Auto-installs security patches so you don't have to remember to update."),

            ("No world-writable /etc/passwd",
             ["ls","-la","/etc/passwd"],
             lambda o: "rw-r--r--" in o,
             "sudo chmod 644 /etc/passwd",
             "The password file should only be writable by root."),

            ("Core dumps restricted",
             ["sysctl","fs.suid_dumpable"],
             lambda o: "= 0" in o,
             "echo 'fs.suid_dumpable=0' | sudo tee -a /etc/sysctl.conf",
             "Prevents crashed programs writing memory to disk — that memory can contain passwords."),

            ("ASLR enabled",
             ["sysctl","kernel.randomize_va_space"],
             lambda o: "= 2" in o,
             "echo 'kernel.randomize_va_space=2' | sudo tee -a /etc/sysctl.conf",
             "Randomises memory layout — makes exploits much harder to execute."),
        ]

        for desc, cmd, pass_fn, fix, why in CHECKS:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                passed = pass_fn(r.stdout + r.stderr)
                if passed:
                    self._lappend(f"  ✓  {desc}", T["OK"])
                else:
                    self._lappend(f"  ✗  {desc}", T["DANGER"])
                    self._lappend(f"     Why: {why}", T["WARN"])
                    self._lappend(f"     Fix: {fix}", T["TEXT_DIM"])
                    self.findings.add_finding(
                        desc, "HARDENING", "MEDIUM",
                        why, None, None
                    )
            except Exception as e:
                self._lappend(f"  ?  {desc} (skipped: {e})", T["TEXT_DIM"])

        self._lappend("\n── Done ──", T["ACCENT"])
        self.status.setText("Quick checks complete.")

    def _guided_wizard(self):
        dlg = GuidedWizard(self.terminal, self.findings, self)
        dlg.exec()


# ── Guided Fix Wizard ─────────────────────────────────────────────────────────
class GuidedWizard(QDialog):
    def __init__(self, terminal, findings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Guided Fix Wizard")
        self.setMinimumSize(600, 500)
        self.terminal = terminal
        self.findings = findings
        self._workers = []

        layout = QVBoxLayout(self)
        hdr = QLabel("🔧  GUIDED FIX WIZARD")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel("Step-by-step fixes for common security issues.\nEach step explains what it does before running anything.")
        info.setStyleSheet(f"color: {T['TEXT_DIM']}; font-size: 11px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        self.fixes = [
            ("Enable UFW Firewall", self._ufw_steps),
            ("Install Fail2ban",    self._fail2ban_steps),
            ("Harden SSH",          self._ssh_steps),
            ("Auto Security Updates", self._autoupdate_steps),
            ("Restrict Core Dumps", self._coredump_steps),
        ]

        # List selector
        selector = QWidget()
        sl = QVBoxLayout(selector)
        sl.addWidget(QLabel("Select a fix to walk through:"))
        self.fix_list = QListWidget()
        for name, _ in self.fixes:
            self.fix_list.addItem(QListWidgetItem(name))
        self.fix_list.currentRowChanged.connect(self._load_fix)
        sl.addWidget(self.fix_list)
        self.stack.addWidget(selector)

        # Detail panel
        detail_w = QWidget()
        dl = QVBoxLayout(detail_w)
        self.fix_title = QLabel("")
        self.fix_title.setStyleSheet(f"color: {T['ACCENT']}; font-size: 13px; font-weight: bold;")
        dl.addWidget(self.fix_title)
        self.fix_content = QTextEdit()
        self.fix_content.setReadOnly(True)
        dl.addWidget(self.fix_content)
        self.fix_run_btn = QPushButton("▶  RUN THIS FIX")
        self.fix_run_btn.setObjectName("ok")
        self.fix_run_btn.setFixedHeight(36)
        self.fix_run_btn.clicked.connect(self._run_fix)
        dl.addWidget(self.fix_run_btn)
        back_btn = QPushButton("← BACK TO LIST")
        back_btn.setObjectName("neutral")
        back_btn.setFixedHeight(32)
        back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        dl.addWidget(back_btn)
        self.stack.addWidget(detail_w)

        self._current_cmds = []

        close = QPushButton("CLOSE")
        close.setObjectName("neutral")
        close.clicked.connect(self.close)
        layout.addWidget(close)

    def _load_fix(self, idx):
        if idx < 0: return
        name, step_fn = self.fixes[idx]
        self.fix_title.setText(name)
        steps, cmds = step_fn()
        self._current_cmds = cmds
        text = ""
        for i, step in enumerate(steps, 1):
            text += f"Step {i}: {step}\n\n"
        self.fix_content.setPlainText(text)
        self.stack.setCurrentIndex(1)

    def _run_fix(self):
        if not self._current_cmds: return
        reply = QMessageBox.question(
            self, "Run Fix?",
            f"This will run {len(self._current_cmds)} command(s) with sudo.\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes: return
        for cmd in self._current_cmds:
            self.terminal.append_cmd(f"sudo {cmd}")
            w = CommandWorker(cmd.split(), sudo=True, timeout=120)
            w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
            w.error_ready.connect(self.terminal.append_err)
            self._workers.append(w)
            w.start()
        QMessageBox.information(self, "Fix Running", "Commands sent to terminal. Check terminal output for results.")

    def _ufw_steps(self):
        steps = [
            "Set default: deny all incoming traffic (nothing gets in unless you allow it)",
            "Set default: allow all outgoing traffic (your machine can reach the internet normally)",
            "Allow SSH so you don't lock yourself out of remote access",
            "Enable UFW — the firewall is now active",
        ]
        cmds = [
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw allow ssh",
            "ufw enable",
        ]
        return steps, cmds

    def _fail2ban_steps(self):
        steps = [
            "Install fail2ban from apt — it runs as a background service automatically",
            "Start the fail2ban service now",
            "Enable fail2ban to start on every boot",
        ]
        cmds = [
            "apt install fail2ban -y",
            "systemctl start fail2ban",
            "systemctl enable fail2ban",
        ]
        return steps, cmds

    def _ssh_steps(self):
        steps = [
            "Disable root login over SSH — you must log in as your user and use sudo instead",
            "Disable password auth — key-based login only (ensure you have SSH keys first!)",
            "Restart SSH service to apply the changes",
        ]
        cmds = [
            "sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ]
        return steps, cmds

    def _autoupdate_steps(self):
        steps = [
            "Install unattended-upgrades package — handles automatic security updates",
            "Enable and configure it to run in the background daily",
        ]
        cmds = [
            "apt install unattended-upgrades -y",
            "dpkg-reconfigure -plow unattended-upgrades",
        ]
        return steps, cmds

    def _coredump_steps(self):
        steps = [
            "Set fs.suid_dumpable=0 — prevents privileged programs dumping memory to disk",
            "Apply the change immediately without rebooting",
        ]
        cmds = [
            "sh -c \"echo 'fs.suid_dumpable=0' >> /etc/sysctl.conf\"",
            "sysctl -p",
        ]
        return steps, cmds


# ── Undo log tab ──────────────────────────────────────────────────────────────
class UndoTab(QWidget):
    def __init__(self, terminal):
        super().__init__()
        self.terminal = terminal
        self._workers = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hdr = QLabel("UNDO / ROLLBACK LOG")
        hdr.setObjectName("heading")
        layout.addWidget(hdr)

        info = QLabel("Every action taken by this app is logged here.\nPress UNDO next to any entry to reverse it.")
        info.setStyleSheet(f"color: {T['TEXT_DIM']}; font-size: 11px;")
        layout.addWidget(info)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["TIME","ACTION","COMMAND RAN","UNDO"])
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        refresh_btn = QPushButton("↻  REFRESH")
        refresh_btn.setObjectName("neutral")
        refresh_btn.setFixedHeight(30)
        refresh_btn.clicked.connect(self._refresh)
        layout.addWidget(refresh_btn)

    def _refresh(self):
        self.table.setRowCount(0)
        for entry in UNDO_LOG:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(entry["time"]))
            self.table.setItem(row, 1, QTableWidgetItem(entry["action"]))
            self.table.setItem(row, 2, QTableWidgetItem(entry["cmd"]))

            cell = QWidget()
            cell.setStyleSheet("background: transparent;")
            bl = QHBoxLayout(cell)
            bl.setContentsMargins(3, 2, 3, 2)
            if entry["undo_cmd"] != "N/A":
                ub = QPushButton("UNDO")
                ub.setObjectName("warn")
                ub.setFixedHeight(24)
                ub.clicked.connect(lambda _, e=entry: self._run_undo(e))
                bl.addWidget(ub)
            else:
                lbl = QLabel("N/A")
                lbl.setStyleSheet(f"color: {T['TEXT_DIM']};")
                bl.addWidget(lbl)
            bl.addStretch()
            self.table.setCellWidget(row, 3, cell)
            self.table.setRowHeight(row, 34)

    def _run_undo(self, entry):
        reply = QMessageBox.question(
            self, "Confirm Undo",
            f"Run: {entry['undo_cmd']}\n\nThis will reverse: {entry['action']}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            cmd = entry["undo_cmd"].replace("sudo ","").split()
            self.terminal.append_cmd(entry["undo_cmd"])
            w = CommandWorker(cmd, sudo=True)
            w.output_ready.connect(lambda t: self.terminal.append(t, T["OK"]))
            w.error_ready.connect(self.terminal.append_err)
            self._workers.append(w)
            w.start()


# ── Export ────────────────────────────────────────────────────────────────────
def export_html(findings_table, profile_key, score):
    score_val, (label, colour) = score, RISK.label()
    rows = ""
    for r in range(findings_table.rowCount()):
        name   = findings_table.item(r,0).text() if findings_table.item(r,0) else ""
        ftype  = findings_table.item(r,1).text() if findings_table.item(r,1) else ""
        risk   = findings_table.item(r,2).text() if findings_table.item(r,2) else ""
        tag    = findings_table.item(r,3).text() if findings_table.item(r,3) else ""
        detail = findings_table.item(r,4).text() if findings_table.item(r,4) else ""
        rc = {"HIGH":"#ff4444","MEDIUM":"#f0a500","LOW":"#3fb950","INFO":"#00d9ff"}.get(risk,"#aaa")
        rows += f"<tr><td>{name}</td><td>{ftype}</td><td style='color:{rc};font-weight:bold'>{risk}</td><td>{tag}</td><td>{detail}</td></tr>\n"

    profile_label = PROFILES.get(profile_key,{}).get("label","Unknown")
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    score_colour = "#3fb950" if score_val < 20 else ("#f0a500" if score_val < 50 else "#ff4444")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Linux Audit Report — {hostname}</title>
<style>
body {{ font-family: monospace; background: #0d1117; color: #e6edf3; padding: 24px; }}
h1 {{ color: #00d9ff; }} h2 {{ color: #00d9ff; border-bottom: 1px solid #30363d; padding-bottom: 6px; }}
.score {{ font-size: 2em; font-weight: bold; color: {score_colour}; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
th {{ background: #21262d; color: #8b949e; padding: 8px; text-align: left; font-size: 11px; letter-spacing: 1px; }}
td {{ padding: 8px; border-bottom: 1px solid #30363d; font-size: 12px; }}
tr:hover {{ background: #161b22; }}
.meta {{ color: #8b949e; font-size: 12px; margin-bottom: 20px; }}
</style></head><body>
<h1>⬡ Linux Security Audit Report</h1>
<div class="meta">Host: {hostname} &nbsp;|&nbsp; Profile: {profile_label} &nbsp;|&nbsp; Generated: {ts}</div>
<h2>Risk Score</h2>
<div class="score">{score_val} / 100 — {label}</div>
<h2>Findings ({findings_table.rowCount()})</h2>
<table>
<tr><th>NAME</th><th>TYPE</th><th>RISK</th><th>TAG</th><th>DETAIL</th></tr>
{rows}
</table>
<h2>Actions Taken</h2>
<table><tr><th>TIME</th><th>ACTION</th><th>COMMAND</th><th>UNDO</th></tr>
{"".join(f"<tr><td>{e['time']}</td><td>{e['action']}</td><td>{e['cmd']}</td><td>{e['undo_cmd']}</td></tr>" for e in UNDO_LOG)}
</table>
</body></html>"""
    return html


# ── Main window ───────────────────────────────────────────────────────────────
class AuditDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Security Audit Dashboard  v3")
        self.resize(1360, 860)
        self.setMinimumSize(1024, 680)
        self.profile_key = "mixed"

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(6)

        # ── Toolbar ──
        toolbar = QHBoxLayout()
        title = QLabel("⬡  LINUX AUDIT DASHBOARD  v3")
        title.setStyleSheet(f"color: {T['ACCENT']}; font-size: 14px; letter-spacing: 3px; font-weight: bold;")
        toolbar.addWidget(title)
        toolbar.addStretch()

        # Theme selector
        theme_lbl = QLabel("Theme:")
        theme_lbl.setObjectName("status")
        toolbar.addWidget(theme_lbl)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(list(THEMES.keys()))
        self.theme_combo.setFixedWidth(120)
        self.theme_combo.currentTextChanged.connect(self._change_theme)
        toolbar.addWidget(self.theme_combo)

        show_code_btn = QPushButton("{ } SHOW CODE")
        show_code_btn.setObjectName("neutral")
        show_code_btn.setFixedHeight(30)
        show_code_btn.clicked.connect(self._show_code)
        toolbar.addWidget(show_code_btn)

        export_btn = QPushButton("📄 EXPORT HTML")
        export_btn.setObjectName("neutral")
        export_btn.setFixedHeight(30)
        export_btn.clicked.connect(self._export)
        toolbar.addWidget(export_btn)

        root.addLayout(toolbar)

        # ── Risk score ──
        self.risk_panel = RiskScorePanel()
        root.addWidget(self.risk_panel)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {T['BORDER']};")
        root.addWidget(sep)

        # ── Shared widgets ──
        self.terminal = TerminalPanel()
        self.findings = FindingsTable(self.terminal, self.profile_key)
        self.findings.score_changed.connect(self.risk_panel.update_score)

        # ── Tabs ──
        self.tabs = QTabWidget()
        self.scan_tab      = ScanTab(self.terminal, self.findings)
        self.cve_tab       = CveTab(self.terminal, self.findings)
        self.harden_tab    = HardeningTab(self.terminal, self.findings)
        self.undo_tab      = UndoTab(self.terminal)

        # Findings panel
        fw = QWidget()
        fl = QVBoxLayout(fw)
        fl.setContentsMargins(6, 6, 6, 6); fl.setSpacing(4)
        fhdr_row = QHBoxLayout()
        fhdr = QLabel("ALL FINDINGS")
        fhdr.setObjectName("heading")
        fhdr_row.addWidget(fhdr)
        fhdr_row.addStretch()
        clr_btn = QPushButton("CLEAR ALL")
        clr_btn.setObjectName("danger")
        clr_btn.setFixedHeight(26)
        clr_btn.clicked.connect(self._clear_all)
        fhdr_row.addWidget(clr_btn)
        fl.addLayout(fhdr_row)
        fl.addWidget(self.findings)

        self.tabs.addTab(self.scan_tab,   "🔍  SCAN")
        self.tabs.addTab(self.cve_tab,    "🛡  CVE")
        self.tabs.addTab(self.harden_tab, "🔒  HARDEN")
        self.tabs.addTab(fw,              "⚠️   FINDINGS")
        self.tabs.addTab(self.undo_tab,   "↩  UNDO LOG")

        # ── Main splitter: tabs | terminal (vertical) ──
        self.main_split = QSplitter(Qt.Orientation.Vertical)
        self.main_split.setHandleWidth(6)
        self.main_split.addWidget(self.tabs)
        self.main_split.addWidget(self.terminal)
        self.main_split.setSizes([560, 240])

        root.addWidget(self.main_split)

        # ── Status bar ──
        sb = QStatusBar()
        self.setStatusBar(sb)
        sb.showMessage("Ready — run a scan to begin  |  Double-click any finding for explanation  |  Drag splitter handles to resize panels")

        # ── Detect profile on startup ──
        QTimer.singleShot(500, self._detect_profile)

    def _detect_profile(self):
        detected = detect_profile()
        dlg = ProfileDialog(detected, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.profile_key = dlg.selected
        else:
            self.profile_key = detected
        self.risk_panel.set_profile(self.profile_key)
        self.findings.profile_key = self.profile_key
        label = PROFILES.get(self.profile_key, {}).get("label", "Unknown")
        self.terminal.append(f"Profile set: {label}", T["ACCENT"])

    def _change_theme(self, name):
        apply_theme(name)
        self.setStyleSheet(make_style())

    def _show_code(self):
        dlg = ShowCodeDialog(self)
        dlg.exec()

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", f"audit-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.html",
            "HTML Files (*.html)"
        )
        if path:
            html = export_html(self.findings, self.profile_key, RISK.score())
            with open(path, "w") as f:
                f.write(html)
            QMessageBox.information(self, "Exported", f"Report saved to:\n{path}")

    def _clear_all(self):
        self.findings.clear_findings()
        self.terminal.output.clear()
        self.risk_panel.update_score()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QPalette()
    for role, col in [
        (QPalette.ColorRole.Window,          T["BG_DARK"]),
        (QPalette.ColorRole.WindowText,      T["TEXT_MAIN"]),
        (QPalette.ColorRole.Base,            T["BG_MID"]),
        (QPalette.ColorRole.AlternateBase,   T["BG_CARD"]),
        (QPalette.ColorRole.Text,            T["TEXT_MAIN"]),
        (QPalette.ColorRole.Button,          T["BG_CARD"]),
        (QPalette.ColorRole.ButtonText,      T["TEXT_MAIN"]),
        (QPalette.ColorRole.Highlight,       "#1f6feb"),
        (QPalette.ColorRole.HighlightedText, T["TEXT_MAIN"]),
    ]:
        palette.setColor(role, QColor(col))
    app.setPalette(palette)
    app.setStyleSheet(make_style())
    win = AuditDashboard()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
