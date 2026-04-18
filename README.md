# Linux Security Dashboard

A plain-English, GUI-based security audit tool for Linux.  
Built for people who want to know if their system is safe — without needing a cybersecurity degree.

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
- **Runs Lynis** (industry-standard audit tool) and translates the output into plain English
- **Explains** every finding in plain English — what it is, why it matters, what happens if you ignore it
- **One-click fixes** with a confirmation dialog that shows exactly what will run before anything happens
- **Guided Fix Wizard** — step-by-step walkthroughs for common security fixes
- **Tool Manager** — installs and explains security/monitoring tools like rkhunter, fail2ban, smartmontools
- **Risk Score** — 0 to 100, updates live as scans run
- **Duke Nukem health face** — gets progressively more battered as your risk score rises 😄
- **Undo Log** — every action recorded, one-click rollback
- **HTML Report** — plain English (Executive) or full technical deep-dive
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

*Coming soon*

---

## Roadmap

- [x] Orphan package detection
- [x] Network port scanning
- [x] Risky service detection
- [x] CVE lookup via Ubuntu security tracker
- [x] Lynis integration
- [x] Quick hardening checks
- [x] Guided Fix Wizard
- [x] Plain English explanations on every finding
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
- [ ] Fedora/Arch/pacman support
- [ ] Timeshift snapshot before actions
- [ ] Drive health (smartmontools integration)
- [ ] Live temperature monitoring (lm-sensors)
- [ ] .deb package for easy install
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

## License

MIT — free to use, modify, and share.

---

## Author

Built by [@playdoggs](https://github.com/playdoggs)  
Started as a personal homelab security tool — grew into something more useful.

*If this helped you, give it a ⭐ — it helps others find it.*
