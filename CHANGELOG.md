# Changelog

All notable changes to Linux Security Dashboard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased] — v4.0

### Planned — Layout
- Left sidebar for all scan/harden/CVE controls with plain-English labels
- Right side tabbed output area (Findings, CVE, Harden, Tools, Undo Log)
- Raised page-style tabs with visible borders — makes navigation obvious
- Terminal panel below findings with draggable splitter handle
- Font size A+/A- buttons on terminal panel

### Planned — New Features
- Tool Manager tab with install/status/how-to-use for 20+ security tools
- Each tool feeds results back into shared findings table and risk score
- Smart install — if package name changed, auto-searches for current name
- Duke Nukem health face SVG (6 states: clean to wrecked, updates live)
- Multi-language support (EN, DE, FR, ES, PT, IT, NL, JP, CN, AR)
- Scheduled scanning via cron integration with headless mode
  `python3 linux-security-dashboard.py --headless --output report.html`
- What changed since last scan diff report
- Desktop notification on new findings
- Executive report (plain English, analogies, traffic lights, cheeky tone)
- Technical report (CVE numbers, CVSS scores, full command output)
- Generate Report button replacing Export HTML
- Profile detection improvements — weight signals, confidence percentage
- Personal Laptop added as explicit profile option
- Profile choice saved between sessions via config file
- Distro auto-detection via /etc/os-release
- Auto-switch package manager (apt/dnf/pacman/zypper) per distro
- System update age check with cheeky messages based on how overdue
- Timeshift snapshot offer before any remove/disable action
- Drive health monitoring via smartmontools integration
- Live CPU/GPU temperature monitoring via lm-sensors
- Persistent undo log saved to ~/.audit-dashboard.log
- Pink theme added (hot pink accent, deep purple background)

### Planned — Security Review Fixes
- Fix: package names from deborphan now validated against safe regex
  before being used in any command (prevents command injection)
- Fix: dpkg subprocess in _scan_services moved off main GUI thread
  into CommandWorker (prevents GUI freeze if dpkg hangs)
- Fix: worker threads cleaned up after completion (fixes memory leak
  on long sessions with many scans)
- Fix: html.escape() applied to all values written into HTML report
  (prevents XSS if package names contain special characters)
- Fix: explicit SSL context added to CVE API urllib calls
- Fix: error logging added via Python logging module to
  ~/.audit-dashboard-errors.log
- Fix: UFW check changed from ufw status to systemctl is-active ufw
  (works without sudo, more reliable)
- Fix: risk score clears before re-running quick checks
  (was double-counting findings on repeat runs)

---

## [3.0] — 2025-04-13

### Added
- CVE lookup tab via Ubuntu Security CVE API
  Scans high-value packages (openssh, curl, sudo, openssl etc.)
  Shows installed version, CVE count, highest severity per package
- OS Hardening tab with Lynis integration
  Installs and runs Lynis, parses warnings into findings table
  ANSI escape codes stripped from Lynis output
  Hardening index parsed and displayed clearly
- Quick Config Checks (no Lynis required)
  Checks SSH root login, password auth, UFW, fail2ban, core dumps,
  ASLR, passwd file permissions — with plain English why/fix per item
- Guided Fix Wizard
  Step-by-step walkthroughs for UFW, fail2ban, SSH hardening,
  auto-updates, core dumps — explains each step before running
- Risk score panel (0-100) with live update as findings come in
- System profile auto-detection on startup
  Detects Gaming Rig, Docker Host, Hypervisor, Web Server,
  File Server, Headless Server, Work Laptop, Mixed Use
  Profile dialog asks user to confirm or pick manually
  Affects what gets tagged NORMAL vs REVIEW vs RISKY
- Multiple themes — Dark, Hacker, Solarized, Light
- Show Code button — full plain-text command reference, copyable
- Pre-action confirmation dialog
  Shows exact command, what it will do, and the undo command
  before anything runs
- Post-action verification — checks fix actually worked
- Undo/rollback log tab — every action recorded with one-click undo
- Explain dialog on every finding
  Click ? button or double-click any row for plain English explanation:
  what it is, why it matters, what happens if ignored, how to fix
- Glossary — auto-shows relevant technical terms in explain popup
- Profile-aware finding tags (NORMAL / REVIEW / RISKY / ORPHAN etc.)
- HTML report export
- Upgradable packages check via apt list --upgradable
- One-click security upgrade with confirmation

### Changed
- Layout rebuilt with vertical splitter between findings and terminal
- Terminal panel moved below findings table
- Risk score replaces simple status label in header

### Fixed
- ANSI escape codes from Lynis now stripped before display
- Lynis hardening index now parsed correctly from log file

---

## [2.0] — 2025-04-13

### Added
- CVE tab (first version) — high-value package scan against Ubuntu tracker
- Hardening tab (first version) — Lynis install/run + quick checks
- Risk score bar 0-100 at top of window
- Upgradable packages list
- One-click security upgrade button

### Changed
- Findings table expanded with more detail columns
- Terminal panel shared across all tabs

---

## [1.0] — 2025-04-13

### Added
- Initial release — single file PyQt6 application
- Orphaned package detection using deborphan
- Network port scanning using ss -tunlp
  Flags FTP (21), Telnet (23), XRDP (3389), CUPS (631), mDNS (5353)
- Risky service detection using dpkg
  Checks: telnet, ftp, xrdp, cups, avahi-daemon, rsh-server,
  rpcbind, nfs-kernel-server
- All installed packages list via dpkg-query
- Findings table with REMOVE and DISABLE action buttons
- Confirmation dialog before any destructive action
- Terminal output panel showing live command output
- Dark theme

### Security foundations
- All subprocess calls use list format (not shell strings)
  Prevents shell injection attacks
- Timeouts on all subprocess calls
  Prevents GUI hanging on slow commands
- No eval() or exec() anywhere in codebase
- No hardcoded credentials
- Read-only terminal output

---

## Notes for Contributors

When submitting a pull request please add an entry to the Unreleased section
describing what you changed and why. Keep entries concise — one line per change
is enough. Security fixes should always note what the risk was and how it
was resolved.

Format:
- Added: new features
- Changed: changes to existing features  
- Fixed: bug fixes
- Security: security fixes (always include brief risk description)
- Removed: removed features
