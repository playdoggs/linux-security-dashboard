# Running Tests

No automated test suite yet.

## Baseline
```bash
python3 -m py_compile linux-security-dashboard.py
python3 linux-security-dashboard.py
```

## Manual regression checklist

**Security checks** — UFW/fail2ban fail on `inactive`, pass only on exact `active`. SSH regex ignores commented lines.

**Guided wizard** — SSH sed steps apply correctly (shlex-parsed). Multi-step fixes run sequentially.

**Actions + undo** — action adds an undo entry; rollback removes the correct row when two entries share a timestamp.

**CVE / updates**
- Online: rows populate; terminal shows `[N/TOTAL] pkg — …` per package.
- Offline: CVE scan shows `⚠ Requires internet — CVE check skipped`; RUN EVERYTHING still completes.
- Switching CVE → updates clears stale CVE rows.
- Updates offline: cached warning, scan still runs from local apt cache.

**Progress lines** — CVE, risky services, quick checks, and updates all emit `[N/TOTAL]` lines; counter starts at 1 each run.

**Tool installs** — offline click on INSTALL shows "Requires Internet" dialog and does not prompt for sudo.

**Theme / language / profile** — theme switch updates persistent widgets; language choice persists; profile affects NORMAL tagging.
