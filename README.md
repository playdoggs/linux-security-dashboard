# Linux Security Dashboard

A GUI-based security audit tool for Linux.  

Built for people who want to know if their system is safe or at least get an idea of what safe might look like or be made up of on Linux — without needing a cybersecurity degree.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## What it does

Most Linux security tools are command-line only and assume you already know what you're doing.  

This tool assumes you don't — and that's fine.

- **Scans** your system for orphaned packages, open ports, and risky services
- **Checks** installed packages against Ubuntu's live CVE vulnerability database
- **Runs Lynis** (industry-standard audit tool) and translates the output into everyday language
- **Explains** every finding in everyday language — what it is, why it matters, what happens if you ignore it
- **One-click fixes** with a confirmation dialog that shows exactly what will run before anything happens
- **Guided Fix Wizard** — step-by-step walkthroughs for common security fixes
- **Tool Manager** — installs and explains security/monitoring tools like rkhunter, fail2ban, smartmontools
- **Hardware health** — live CPU / GPU / drive temperatures via lm-sensors; SMART self-assessment via smartmontools (read-only, never runs destructive self-tests)
- **Timeshift integration** — optional one-click snapshot before any destructive action; the action is aborted if the snapshot fails
- **RUN EVERYTHING** — runs seven non-sudo checks in sequence, then shows findings and
  separate coverage states. Failed, partial, skipped, cancelled or unknown checks
  prevent a complete assessment verdict; zero detected findings is not an all-clear.
  Results describe the selected checks at scan time, not certification or continuous monitoring.
- **Scan isolation** — conflicting scans and evidence-changing actions are blocked until
  the active operation finishes. A blocked request explains why; retry afterward.
  Lynis uses captured output from the current attempt, never an old shared log.
  Unrecognized or incomplete Lynis summaries remain unknown rather than clean.
- **Offline-aware** — detects no internet and advises you; CVE and tool install gracefully skip with a clear message
- **Live progress in terminal** — every multi-item scan shows `[N/TOTAL] …` as it runs
- **Risk Score** — 0 to 100, updates live as scans run
- **Duke Nukem health face** — gets progressively more battered as your risk score rises 😄
- **Undo Log** — supported actions record validated reverse operations across restarts.
  New history uses protected SQLite records with durable undo outcomes. Completed,
  failed and uncertain attempts remain in audit history and cannot automatically
  replay. Legacy JSONL is visible but non-executable. Pages show at most 200 rows.
  Reverse operations may restore exposure and do not guarantee prior configuration
  or state; persistence errors are reported rather than offering memory-only undo.
- **HTML Report** — everyday language (Executive) or full technical deep-dive; filename auto-tagged with hostname
- **Auto-detects** what kind of machine you're running (Gaming Rig, Home Server, Docker Host, etc.) and adjusts what's flagged as normal vs suspicious
- **Multiple themes** — Dark, Hacker, Solarized, Light, Pink
- **Multiple languages** — 12 built in (English, German, French, Spanish, Italian, Portuguese, Dutch, Japanese, Chinese Simplified, Arabic with RTL, and more)

---

## Who is this for

- Linux home users who switched from Windows and aren't sure if their system is secure
- Homelab enthusiasts running Proxmox, Docker, LXC containers
- Gaming rig owners who just want to know if something dodgy is running
- Anyone who's googled "how do I know if my Linux is secure" and gotten overwhelmed

---

## Requirements

```bash
# Python 3.10+
sudo apt install python3 python3-pip

# PyQt6
pip install PyQt6 --break-system-packages

# System display library
sudo apt install libxcb-cursor0

# Optional but recommended
sudo apt install deborphan lynis
```

---

## Install & Run

```bash
# Clone the repo
git clone https://github.com/playdoggs/linux-security-dashboard
cd linux-security-dashboard

# Run it
python3 linux-security-dashboard.py
```

### Build a `.deb` package

```bash
# One-time build dependencies
sudo apt install build-essential debhelper devscripts lintian

# From the repo root
./build-deb.sh

# Then install the resulting .deb (written to the parent directory)
sudo apt install ../linux-security-dashboard_*.deb
```

After installing, launch from your desktop menu (**Linux Security Dashboard**) or run `linux-security-dashboard` from a terminal.

---

## Distro Support

| Distro | Status |
|--------|--------|
| Ubuntu 22.04 / 24.04 | ✅ Fully supported |
| Linux Mint | ✅ Fully supported |
| Pop!_OS | ✅ Fully supported |
| Debian | ✅ Supported |
| Fedora | ⚠️ Partial (dnf support in progress) |
| Arch / Manjaro | ⚠️ Partial (pacman support in progress) |
| openSUSE | ⚠️ Planned |

---

## Screenshots

| Main Dashboard & Health Status | System Profile Logic |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/89dc34d3-12b0-455f-9502-287d5746884b" width="400" /> | <img src="https://github.com/user-attachments/assets/8b587be8-dec4-401b-8ea8-7a72f35b27d6" width="400" /> |
| **Duke Nukem Health Status** | **Smart Profile Detection** |

| Vulnerability (CVE) Scanning | Everyday Language Explanations |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/bdb0feac-bc92-4a92-9d26-801036f005ed" width="400" /> | <img src="https://github.com/user-attachments/assets/b8fc71bd-7da5-4000-9f91-0918084f5c3d" width="400" /> |
| **Deep Security Scanning** | **Jargon-Free Insights** |

| Tool Guides & Education | Tracking, Logging & Rollbacks |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/1b4a68dc-f853-47d9-b409-c83cc4f557a1" width="400" /> | <img src="https://github.com/user-attachments/assets/28601af7-9577-4bc5-a6cf-099f3e0a834a" width="400" /> |
| **Integrated Learning** | **Full Session Rollback Log** |

| Final Results |
| :---: |
| <img src="https://github.com/user-attachments/assets/78b6e1c7-210e-4e5a-8ed1-b3529b2273e3" width="600" /> |
| **Secured System State** |


---

## Roadmap

- [x] Orphan package detection
- [x] Network port scanning
- [x] Risky service detection
- [x] CVE lookup via Ubuntu security tracker
- [x] Lynis integration
- [x] Quick hardening checks
- [x] Guided Fix Wizard
- [x] Everyday Language explanations on every finding
- [x] Risk score 0-100
- [x] Undo/rollback log
- [x] System profile auto-detection
- [x] Multiple themes
- [x] HTML report export
- [x] Tool Manager tab (15 tools: rkhunter, clamav, smartmontools, timeshift etc.)
- [x] Duke Nukem health face (6 states)
- [x] Multi-language support (12 languages, RTL layouts for Arabic)
- [x] Persistent undo log (survives restarts)
- [x] Idempotent Guided Fix Wizard (skips fixes that are already applied)
- [x] RUN EVERYTHING chained assessment + summary dialog
- [x] Offline detection and graceful "requires internet" messaging
- [x] Live `[N/TOTAL]` progress output in terminal for multi-item scans
- [x] Hostname-tagged report filenames + one-click auto-open in browser
- [x] Hardware temperature check (lm-sensors) — parses per-sensor thresholds into findings
- [x] Drive health check (smartmontools) — read-only SMART self-assessment, never runs `-t`
- [x] Optional Timeshift snapshot before destructive actions — aborts the action if the snapshot fails
- [x] `.deb` package — `./build-deb.sh` builds an installable Debian package (`debian/` + `packaging/`)
- [ ] Full Fedora/Arch parity (package manager hooks done; CVE/inventory scans still apt-only)
- [ ] PPA submission

---

## Contributing

Contributions welcome — especially:
- **Translations** — add a new language dictionary in `translations.py`
- **Distro support** — help test and fix on Fedora, Arch, openSUSE
- **Tool integrations** — add a new tool to the Tool Manager
- **Bug reports** — open an issue, describe what happened

No coding experience needed to add a translation — it's just a Python dictionary.

---

## The AI Development Journey (Domain Knowledge > Prompt Engineering)

This project was a deep dive into using AI not just as a chatbot, but as a development partner. As a Cybersecurity Engineer, my goal was to see if "prompting" could produce a production-grade tool if given strict architectural guardrails.

I moved from simple mobile prompts to a full CLI/IDE workflow (Claude CLI, Gemini, and VS Code). To manage the "AI memory" and maintain the **"Safe Move"** philosophy, I developed a system of **Agent Instruction (.md) files** (found in the `agent_docs` folder).

These files served as the source of truth for the AI, specifically:
- **`service_architecture.md`** & **`service_communication_patterns.md`**: Defined how the GUI talks to the backend security logic.
- **`code_conventions.md`**: Enforced strict logging, tracking, and rollback logic (essential for system security).
- **`building_the_project.md`**: Kept the AI from hallucinating dependencies.
- **`known_bugs.md`**: A shared memory space to ensure we didn't fix one thing and break another.

Feel free to explore the `agent_docs` folder to see how these guardrails were built!

---

## License

MIT — free to use, modify, and share.

---

## Author

Built by [@playdoggs](https://github.com/playdoggs)  
Started as a personal homelab security tool — grew into something more useful...maybe.

*If this helped you, give it a ⭐ — it helps others find it.*
