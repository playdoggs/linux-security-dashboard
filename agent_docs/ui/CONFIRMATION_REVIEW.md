# Final Increment 4H — confirmation and keyboard hardening

H15 is corrected in the authorized 2026-11-18 follow-up. Qt's automatic default
promotion could turn a focused affirmative button into the default despite an
earlier request for No. `safe_confirmation_buttons` disables autoDefault on every
choice, clears previous defaults, establishes No/Cancel as the sole default and
requests initial focus there. `privileged_question` applies that policy to existing
Yes/No decisions and explicitly maps Escape to No.

## Audit of privileged entry points

Locations below refer to the source reviewed for this correction.

| Decision | Source/function | Correction and verification |
|---|---|---|
| Prerequisite package plan | linux-security-dashboard.py:3230, PrerequisitesPanel.install | Actual visible production preview: No default/initial focus; both autoDefault flags false; Enter/Escape/content keys cancel or remain unapproved; explicit Space approval proceeds only into mocks |
| Findings remediation and optional snapshot | linux-security-dashboard.py:3598, PreActionDialog.__init__ | Cancel default/focus; snapshot checkbox Space only toggles; command-details Enter does not approve |
| Guided command chain | linux-security-dashboard.py:5274, GuidedWizard._run_fix | Shared No-default question before the existing password and worker chain |
| Optional catalogue install/reinstall | linux-security-dashboard.py:6464, ToolCard._install | Shared No-default question; existing package workflow otherwise unchanged |
| Structured rollback | linux-security-dashboard.py:7173, UndoPanel._run_undo | Shared No-default question; post-dialog validation, durable claim and execution boundary unchanged |

All current QMessageBox.question call sites were inspected. Only the existing
dashboard shutdown question remains static: it waits for already authorized work
and intentionally retains its existing behaviour. Warnings/information/report/help
dialogs do not authorize privileged operations. The scheduler writes the user's
crontab without sudo and is not a privileged confirmation; it was not redesigned.

The shared password helper (line 1318) remains a **credential-entry** dialog, not a
Yes/No approval decision. Typed-password Enter submission and existing sudo-cache
semantics are preserved. SMART, Lynis and catalogue RUN actions use that helper;
no extra decision dialog or privileged capability was introduced. The prerequisite
plan still explicitly approves before forcing the existing authentication prompt.
Findings remediation retains its existing password-before-plan ordering.

## Verified keyboard contract

Tests read `isDefault()`, `autoDefault()`, dialog.focusWidget() and hasFocus() on
shown Qt widgets, including after focus changes. Merely calling setDefault is not
treated as evidence. The prerequisite fixture checks initial focus before activating
the dialog for synthetic keyboard delivery, then verifies actual Qt focus.

| Input/context | Observed result |
|---|---|
| Return/keypad Enter initially | No/Cancel; no privileged dispatch |
| Return with affirmative button focused | No/Cancel; focus does not promote approval to default |
| Enter in read-only details | May be consumed without dismissal; never approves, then Escape dismisses |
| Escape with affirmative/content focus | No/Cancel |
| Space on No/Cancel | Declines |
| Space on deliberately focused affirmative | Explicitly accepts the decision; only mocked operations follow in fixtures |
| Space on snapshot/remember checkbox | Toggles that checkbox without submitting |
| Space on prerequisite details | Does not approve |
| Tab/Shift+Tab | Traverses details/buttons and reverses; No/Cancel remains the default |

Read-only prerequisite and pre-action details explicitly use tabChangesFocus, so
keyboard navigation cannot be trapped in a text editor. The same button policy
preserves normal click handling and existing accepted/rejected signals. Enter on an
affirmative button intentionally no longer approves: use Space or a click.

ProfileDialog needed no production behaviour change. Activating the fixture dialog
and checking actual focus resolved the prior test limitation. Verified sequence:
checked radio → Remember → OK → Cancel → checked radio, reverse traversal, Space,
vertical radio-arrow navigation and Escape. The probe checks Qt's State_HasFocus
and captures each focused control. Shared dashed button focus differs structurally
from a solid default-button edge; check/radio focus retains its stronger outline.
See [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) for canonical visual rules.

## Validation and evidence

- Full suite: **262 tests passed in 24.525 seconds**; no failures/errors.
- Corrected Stage 1 fixtures: **MATCH**. Findings, scores, coverage and HTML data
  remain unchanged. Command workers, package allowlists, scan orchestration,
  SQLite/undo storage and shutdown implementations are unchanged by this correction.
- The new prerequisite keyboard regression fails against the pre-fix snapshot with
  `initial dialog focus is not No`; it passes with the correction. No missing-helper
  error or generic mocked decision is used for that before/after demonstration.
- Four new test methods cover real Qt pre-action/message/profile behaviour and
  guard the audited decision sites. Existing worker tests use explicit decision
  mocks; those mocks are not evidence of keyboard safety. Actual prerequisite
  callback/approval/ownership tests send Qt key events instead of dialog.accept().
- Enterprise/Hybrid desktop navigation and prerequisite fixtures passed. Profile
  Tab verification now passes **2/2**. Six additional desktop keyboard probes passed:
  nine pre-action scenarios, seven message scenarios and profile traversal in each
  appearance. No test performs sudo, installs packages or changes host settings.
- Screenshots and sanitized runtime observations are under
  the local evidence index, `screenshots/increment4h-final-confirmations/review.md`.
  Runtime logs and temporary state remain outside the repository. The five approved
  design references and historical captures are preserved.

Commands:

```bash
python3 -B -m unittest discover -s tests -p test_confirmation_keyboard.py -q
python3 -B -m unittest discover -s tests -p test_prerequisites_ui.py -q
python3 -B -m unittest discover -s tests -q
python3 -B tests/capture_ui_baseline.py --check tests/fixtures/ui_baseline_ui_bl_001
QT_QPA_PLATFORMTHEME=generic python3 -B tests/confirmation_keyboard_probe.py --case profile --theme 'Hybrid Professional'
```

## Remaining risks and limits

This is synthetic interaction with real Qt widgets, not a real installation or
credential test. Actual compositor/hardware-keyboard behaviour, screen readers and
other Qt/platform versions are not comprehensively verified. Non-fatal Wayland
text-input warnings occurred on teardown of one successful desktop fixture.
Keyboard focus is actively established for test delivery; it is not proof that the
desktop permits unsolicited focus stealing. Generic legacy package timeout risks
and the other deferred consolidated-review items remain outside this correction.
No claim of exhaustive security or accessibility certification is made.
