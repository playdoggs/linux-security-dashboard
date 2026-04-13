# CLAUDE.md — AI Context File

This file is for AI assistants (Claude) to read at the start of a session
to get full context on this project without needing the developer to re-explain everything.

---

## Project Summary

**Linux Audit Dashboard** — a PyQt6 GUI security audit tool for Linux.
Target audience: non-technical home Linux users, homelab enthusiasts, gaming rig owners.
One Python file. No external dependencies beyond PyQt6.

---

## Developer Context

- **Name**: Ben
- **Location**: Australia (St Albans, Victoria)
- **Background**: OT Cybersecurity professional
- **Systems**: 
  - miniRig (gaming/management desktop, Ubuntu, runs Steam/Sunshine/Brave)
  - ThinkPad T14s (personal laptop, Ubuntu)
  - Proxmox homelab with LXC containers and Docker (Immich, Nextcloud, Graylog)
- **GitHub**: https://github.com/playdoggs
- **ADHD**: Yes — Ben has adult ADHD. Keep responses:
  - Short and concise
  - High-level first, details second
  - Practical examples over theory
  - One section at a time, pause for response

---

## Communication Preferences

- Plain English, no jargon unless explained
- Cheeky/fun tone where appropriate
- Short bullet points over long paragraphs
- Call out if conversation goes off-topic and redirect
- Don't compile/build anything until Ben says "compile now"
- Confirm scope before building — list what's going in

---

## Current Version: v3

### What's built and working:
- Orphan package detection (deborphan)
- Network port scanning (ss -tunlp)
- Risky service detection (dpkg check list)
- CVE lookup via Ubuntu security tracker API
- Lynis integration with ANSI stripping
- Quick hardening checks (SSH, UFW, fail2ban, core dumps, ASLR etc.)
- Guided Fix Wizard (UFW, fail2ban, SSH, auto-updates, core dumps)
- Plain English explanations on every finding (? button + double-click)
- Glossary tooltips on technical terms
- Risk score 0-100 with live update
- Undo/rollback log (session only — not persistent yet)
- System profile auto-detection (gaming/docker/hypervisor/webserver etc.)
- Multiple themes (Dark, Hacker, Solarized, Light)
- HTML report export
- Show Code button (full command reference)
- Pre-action confirmation dialog with impact explanation
- Post-action verification

### Known issues in v3:
- UFW check uses `ufw status` without sudo — returns nothing, always shows ✗
  Fix: use `systemctl is-active ufw` instead
- Risk score double-counts if quick checks run multiple times without clearing
  Fix: clear findings before re-running quick checks
- Undo log empty on startup — not persistent between sessions
  Fix: save to ~/.audit-dashboard.log

---

## Planned for v4:

### Layout changes:
- Left sidebar: all scan/harden/CVE buttons with descriptive labels
- Right side: tabbed output area (Findings, CVE, Harden, Tools, Undo)
- Terminal panel below with draggable splitter
- Font size A+/A- buttons on terminal

### New features:
- Tool Manager tab:
  - Cards for: htop, btop, rkhunter, chkrootkit, clamav, aide, auditd,
    timeshift, borgbackup, restic, nmap, smartmontools, lm-sensors,
    nethogs, ncdu, logwatch, fail2ban, apparmor, wireshark
  - Each card: install status, INSTALL button, HOW TO USE popup
  - Each tool feeds results back into findings table
  - Smart install: if install fails, checks if package name changed, retries
- Duke Nukem health face SVG (6 states: clean → wrecked, updates live with score)
- Multi-language support (EN, DE, FR, ES, PT, IT, NL, JP, CN, AR)
- Persistent undo log (~/.audit-dashboard.log)
- System update age check with cheeky messages
- Dual report modes: Executive (plain English) + Technical (CVE numbers/CVSS)
- Profile detection improvements:
  - Weight signals more carefully (one package shouldn't set profile)
  - Personal Laptop as explicit profile option
  - Save profile choice between sessions
  - Detect distro properly (/etc/os-release)
- Distro-aware commands (apt/dnf/pacman auto-switch)
- Timeshift snapshot offer before any remove/disable action
- Better tab styling — raised page tabs with borders

### Fixes for v4:
- UFW check → systemctl is-active ufw
- Score double-count fix
- Persistent undo log

---

## Architecture

Single Python file using PyQt6.
Key classes:
- `AuditDashboard` — main window
- `RiskTracker` — global findings/score tracker (RISK singleton)
- `FindingsTable` — shared findings table, receives from all tabs
- `TerminalPanel` — shared terminal output
- `RiskScorePanel` — risk bar + Duke face
- `ScanTab` — orphans/network/services
- `CveTab` — CVE lookup + upgradable
- `HardeningTab` — Lynis + quick checks + wizard
- `ToolsTab` — (v4) tool manager
- `UndoTab` — rollback log
- `CommandWorker` — QThread for shell commands
- `HttpWorker` — QThread for CVE API calls
- `ProfileDialog` — startup profile detection/confirmation
- `ExplainDialog` — plain English finding explanation
- `PreActionDialog` — confirmation before remove/disable
- `GuidedWizard` — step-by-step fix wizard
- `ShowCodeDialog` — full command reference

---

## Design Principles

1. Never do anything to the system without explicit user confirmation
2. Always show the exact command before running it
3. Every technical term must be explainable in plain English
4. Gaming rig context: Steam, Sunshine, game ports are NORMAL not suspicious
5. Cheeky but not annoying — humour in reports/messages, not in error states
6. One file — easy to clone, run, understand, contribute to

---

## Session Startup Checklist

When starting a new session, Claude should:
1. Read this file for full context
2. Ask what we're working on today
3. Confirm scope before building anything
4. Not compile until Ben says "compile now"
5. Keep responses short — ADHD-friendly
