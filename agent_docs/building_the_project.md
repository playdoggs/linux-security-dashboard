# Build Instructions
<!-- AGENT: Read this first. No build step — just run. -->

## Requirements
- Python 3.10+  (`python3 --version`)
- PyQt6: `pip install PyQt6 --break-system-packages`
- Optional system tools (features degrade gracefully without them):
  `sudo apt install libxcb-cursor0 deborphan lynis`

## Launch
```bash
python3 linux-audit-dashboard-v4.2.py
```

## Files
| File | Purpose |
|------|---------|
| `linux-audit-dashboard-v4.2.py` | Complete app — single file, ~5070 lines |
| `~/.audit-dashboard.conf` | Saved prefs: theme, lang, profile, sidebar collapse state |
| `~/.audit-dashboard-undo.log` | Persistent undo log — JSON Lines, one dict per action |
| `~/.audit-dashboard-errors.log` | Error log — written by `init_logging()`, never crashes app |

## Validation — can it start?
```bash
python3 -c "import PyQt6; print('PyQt6 ok')"
python3 -c "import sys; ast = __import__('ast'); ast.parse(open('linux-audit-dashboard-v4.2.py').read()); print('syntax ok')"
python3 linux-audit-dashboard-v4.2.py   # run it
```

## Key imports (if you see ImportError these must be present)
```python
import time, socket          # used in HttpWorker retry/timeout
import base64                # embedded face PNG data
from PyQt6.QtWidgets import ... QSplitterHandle
from PyQt6.QtGui    import ... QPainter
```
