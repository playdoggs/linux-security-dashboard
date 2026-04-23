# Build Instructions

No compile step. Run Python directly.

## Requirements
- Python 3.10+
- PyQt6
- Optional tools: `deborphan` (unused-package scan), `lynis` (hardening audit), `libxcb-cursor0` (Qt runtime on Debian/Ubuntu)

## Install
```bash
sudo apt install python3 python3-pip libxcb-cursor0 deborphan lynis
pip install PyQt6 --break-system-packages
```

## Run
```bash
python3 linux-security-dashboard.py
```

## Runtime files
- `~/.audit-dashboard.conf` — preferences
- `~/.audit-dashboard-undo.log` — JSONL rollback log
- `~/.audit-dashboard-errors.log` (fallback: `/tmp/.audit-dashboard-errors.log`)

## Sanity checks
```bash
python3 -m py_compile linux-security-dashboard.py
python3 linux-security-dashboard.py
```

## Size
`linux-security-dashboard.py` — ~6145 lines (2026-04-23).
