# AGENT OPERATIONAL DIRECTIVES (CRITICAL)

## Documentation Authority
You are an agent with a "Documentation-First" mandate. All technical truth and state management must be mirrored in the `agent_docs/` directory for Obsidian tracking.
- **Path:** `./agent_docs/`
- **Mandate:** Before starting any task, `cat` the relevant `.md` file in `agent_docs/`.
- **Sync Rule:** After completing a code change, you MUST update the corresponding `.md` file to reflect the new state (e.g., if you add a class, update `service_architecture.md`).

## Specific File Mapping
- **Builds:** `agent_docs/building_the_project.md`
- **Tests:** `agent_docs/running_tests.md`
- **Standards:** `agent_docs/code_conventions.md`
- **Logic/Flow:** `agent_docs/service_architecture.md`
- **Data:** `agent_docs/database_schema.md`
- **API/Events:** `agent_docs/service_communication_patterns.md`

---

# CLAUDE.md — AI Developer Context

This file gives AI assistants full project context at the start of a session.
Paste the raw URL of this file into Claude to resume development instantly.

---

## Project Summary

**Linux Audit Dashboard** — an accessible, GUI-based cybersecurity health check
tool for Linux. Designed for non-technical users who want to know if their
system is safe without needing a cybersecurity background.

**Core philosophy:**
- Plain English first — every finding explained in human terms
- Never do anything without explicit user confirmation
- Show the exact command before running it
- One-click fixes with guided walkthroughs
- Accessible to beginners, useful to professionals

---

## Tech Stack

- **Language**: Python 3.10+
- **GUI**: PyQt6
- **Structure**: Single file application
- **External tools used**: deborphan, lynis, ss, dpkg, apt, systemctl, sysctl
- **CVE data**: Ubuntu Security CVE API (https://ubuntu.com/security/cves.json)
- **No external Python dependencies** beyond PyQt6

---

## Current Version: v3

### Working features:
- Orphan package detection (deborphan)
- Network port scanning (ss -tunlp)
- Risky service detection
- CVE lookup via Ubuntu security tracker API
- Lynis integration with ANSI stripping and hardening index parsing
- Quick hardening checks (SSH, UFW, fail2ban, core dumps, ASLR etc.)
- Guided Fix Wizard (UFW, fail2ban, SSH, auto-updates, core dumps)
- Plain English explanations on every finding (? button + double-click row)
- Glossary tooltips on technical terms
- Risk score 0-100 with live update
- Undo/rollback log (session only)
- System profile auto-detection (gaming/docker/hypervisor/webserver etc.)
- Multiple themes (Dark, Hacker, Solarized, Light)
- HTML report export
- Show Code button (full command reference)
- Pre-action confirmation dialog showing exact command + impact
- Post-action verification

### Known bugs to fix in v4:
- UFW check uses ufw status without sudo — always shows fail even when active
  Fix: use systemctl is-active ufw instead
- Risk score double-counts if quick checks run multiple times without clearing
  Fix: clear findings before re-running quick checks
- Undo log is session-only, lost on restart
  Fix: persist to ~/.audit-dashboard.log

---

## Planned: v4

### Layout:
- Left sidebar: scan/harden/CVE buttons with descriptive plain-English labels
- Right side: tabbed output (Findings, CVE, Harden, Tools, Undo Log)
- Terminal panel below with draggable splitter handle
- Font size A+/A- buttons on terminal panel
- Raised page-style tabs with borders (make it obvious they are clickable)

### New features:

**Tool Manager tab:**
- Cards for: htop, btop, rkhunter, chkrootkit, clamav, aide, auditd,
  timeshift, borgbackup, restic, nmap, smartmontools, lm-sensors,
  nethogs, ncdu, logwatch, fail2ban, apparmor, wireshark
- Each card: what it does in plain English, install status, INSTALL button,
  HOW TO USE popup (setup steps + key commands + how to verify it works)
- Tools feed results back into shared findings table and risk score
- Smart install: if package name changed, auto-searches for current name

**Duke Nukem health face:**
- SVG face, 6 states from clean to wrecked
- Updates live as risk score changes
- Sits next to the risk score bar

**Multi-language support:**
- English, German, French, Spanish, Portuguese, Italian, Dutch, Japanese,
  Chinese Simplified, Arabic with RTL layout support
- Translations stored as Python dictionaries — easy community contributions

**Scheduled scanning (cron integration):**
- Schedule automatic scans (daily/weekly/monthly)
- Output saved to ~/.audit-dashboard-history/
- Desktop notification if new findings appear since last scan
- What changed since last scan diff report
- Headless mode: run without GUI for cron jobs
  python3 linux-audit-dashboard.py --headless --output report.html

**Report improvements:**
- Executive report: plain English, analogies, traffic lights, action summary
- Technical report: CVE numbers, CVSS scores, full command output, port details
- Cheeky/fun tone in executive report
- Generate Report button replacing Export

**Profile detection improvements:**
- Weight signals — one package should not set the whole profile
- Add Personal Laptop as explicit profile option
- Save profile choice between sessions via config file
- Detect distro from /etc/os-release
- Show detection confidence level

**Distro support:**
- Auto-detect package manager (apt/dnf/pacman/zypper)
- Swap commands accordingly so one app works across distros

**System update age check:**
- Check when apt update and upgrades were last run
- Cheeky messages based on how overdue

**Other:**
- Persistent undo log saved to ~/.audit-dashboard.log
- Timeshift snapshot offer before any remove/disable action
- Drive health via smartmontools integration
- Live temperature monitoring via lm-sensors

---

## Architecture — Key Classes

| Class | Purpose |
|-------|---------|
| AuditDashboard | Main window |
| RiskTracker | Global findings/score singleton (RISK) |
| FindingsTable | Shared findings table, fed from all tabs |
| TerminalPanel | Shared terminal output panel |
| RiskScorePanel | Risk bar + Duke face |
| ScanTab | Orphans / network / services scans |
| CveTab | CVE lookup + upgradable packages |
| HardeningTab | Lynis + quick checks + guided wizard |
| ToolsTab | Tool manager (v4) |
| UndoTab | Rollback log |
| CommandWorker | QThread for shell commands |
| HttpWorker | QThread for CVE API calls |
| ProfileDialog | Startup profile detection + confirmation |
| ExplainDialog | Plain English finding explanation popup |
| PreActionDialog | Confirmation before remove/disable |
| GuidedWizard | Step-by-step fix wizard |
| ShowCodeDialog | Full command reference |

---

## Design Principles

1. Never run anything on the system without explicit user confirmation
2. Always show the exact command before executing it
3. Every technical term must be explainable in plain English
4. Profile-aware — what is flagged depends on machine type
5. Accessible first — designed for users with no security background
6. Cheeky but not annoying — humour in reports, not in error states
7. Single file — easy to clone, run, read, and contribute to
8. Open source — community translations and tool integrations welcome

---

## Session Startup Checklist for AI Assistants

1. Read this file for full project context
2. Check known bugs section — fix these first
3. Confirm scope with developer before building anything
4. Do not compile or build until developer says "compile now"
5. Keep responses concise — high level first, details on request
6. One section at a time — confirm before moving to next
7. Call out scope creep and redirect if conversation drifts

---

## Contributing

No coding experience needed to add a translation — it is just a Python dictionary.
See CONTRIBUTING.md for how to add languages, tools, and distro support.
