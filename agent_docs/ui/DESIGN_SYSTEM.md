# Linux Security Dashboard — UI Design System

Canonical visual guidance for the existing PyQt6 Widgets application. Enterprise
Workspace remains the default light appearance; Hybrid Professional keeps dark
navigation and light content. Retain five legacy themes and saved preferences.
This document defines presentation, not scan behaviour or security policy.

## Reference interpretation

All five supplied references were inspected for this alignment on 2026-11-18:

| Reference | Visual guidance adopted |
|---|---|
| [dashboard.png](references/dashboard.png) | Clear title/description hierarchy, grouped surfaces, restrained teal emphasis and separated activity |
| [findings.png](references/findings.png) | Readable headers, quiet row separators, aligned controls, severity text plus symbols |
| [prerequisites.png](references/prerequisites.png) | Distinct checked, focused, pressed and disabled states; secondary/primary action hierarchy |
| [selected-states.png](references/selected-states.png) | Native tick marks, tinted selection, navigation edge marker and readable status text |
| [dialogs.png](references/dialogs.png) | Bordered surface, readable details, separated footer and visible dismissal/approval controls |

The images have dark content. Adapt their component discipline and teal emphasis
to the approved light/Hybrid identities. Do not copy example data, packages, extra
navigation, charts or capabilities. Do not add Critical severity, compliance claims,
package upgrades or tool-version requirements. Keep the actual seven-section
navigation, six logical findings columns, five prerequisite states, seven-step
assessment scope and existing package allowlists. No gradients or glow are needed.

## Semantic colours

Use `THEMES`, `apply_theme()`, `build_palette()` and `make_style()`, rather than
literal widget colours. Values below are accessible adaptations, not sampled pixels.

| Role | Enterprise Workspace | Hybrid Professional | Purpose |
|---|---|---|---|
| BG_DARK | #f5f7fa | #f5f7fa | Workspace/dialog background |
| BG_MID / BG_CARD | #ffffff / #eef2f6 | Same | Content, headers and alternate rows |
| SIDEBAR | #ffffff | #172b4d | Persistent navigation |
| TEXT_MAIN / TEXT_DIM | #172b4d / #475467 | Same | Primary/supporting text |
| ACCENT / FOCUS / SELECTED_BORDER | #08786f | #08786f | Teal action edges, focus and selection |
| ACCENT_TEXT | #ffffff | #ffffff | Text on filled primary action |
| SELECTED / HOVER | #e2f4f1 / #f0f8f6 | Same | Selected/hovered content |
| BORDER / CONTROL_BORDER | #cbd5e1 / #667085 | Same | Dividers and control boundaries |
| NAV_TEXT / NAV_DIM | #172b4d / #475467 | #ffffff / #d0d5dd | Navigation labels |
| NAV_ACTIVE / NAV_ACCENT | #eef2f6 / #08786f | #15434b / #9df3e6 | Active navigation surface/marker |
| OK / WARN / DANGER | #146c43 / #854a0e / #b42318 | Same | Existing status meanings |

Legacy accents remain unchanged; new roles derive from their existing palettes.
The legacy Light theme keeps its blue selection tint. Theme changes refresh
existing widgets and bound styles, without rebuilding controllers or result data.
Normal-size professional text targets 4.5:1 contrast on its actual surface;
focus/control boundaries target 3:1. Tests cover primary, selected-text and active
navigation combinations. This is not complete accessibility certification.

## Typography, spacing and layout

- Use the existing Sans Serif/system fallback. Preserve `BASE_FS`, `fs()` and
  Activity font scaling. Default base: 13 px; shared body: 14 px; shared heading
  labels: 16 px, with existing context-specific headings allowed to be larger.
  Use weight 600 for selected emphasis and headings; do not require new fonts.
- Prefer an 8 px spacing rhythm, 4 px for tight groups and 12–16 px panel padding.
  Preserve historical layouts where changing them would affect behaviour; these
  are shared defaults, not a rewrite of every spacing constant.
- Shared radius: 8 px. Controls remain at least 32 logical pixels high and findings
  rows at least 44; scaled text may increase them. Compensate padding for thicker
  borders to limit geometry changes between states.
- Findings prioritise Name, Risk and Actions; preserve cached width minima,
  logical column indices, sorting, filtering, escaped tooltips and action routing.
  Use horizontal scrolling when needed, without scanning all rows on resize.
- Validate 1100×700 and larger windows, narrow findings views and longer text.
  Sizes are logical pixels; screenshots may have different physical dimensions.

## Components and interaction states

| Component/state | Presentation and interaction |
|---|---|
| Secondary button | Neutral surface, readable label and 1 px control border |
| Primary button | Explicit `uiRole="primary"`: accent fill/white text; Install Selected uses it without granting approval |
| Hover | Role-based tint/accent edge; never selects packages or dispatches work |
| Focus | Visible 2 px outline; button focus is dashed so it differs structurally from a solid default-button edge. Active navigation retains its 4 px edge marker |
| Pressed/checked button | Stronger edge, tinted surface and semibold label; no success or permission implied |
| Check/radio | Native tick/dot, 18 px indicator, checked tint/outline and separate focus boundary |
| Active navigation | Exclusive checked destination, leading marker and text emphasis; preserve shortcuts/accessibility labels |
| Table row | Quiet alternating/hover surfaces; selected row has a 3 px underline and tint; severity retains text/symbols |
| Disabled | Muted text/border/native indicator; disabled primary action has neutral fill. A remembered selection is not permission to execute |
| Loading/progress | Existing operation text, progress/ownership state and blocked controls; never invent percentages or completion |
| Status | Existing text/symbol plus semantic colour. Missing/Unknown/Skipped/Partial cannot become success through styling |

Selected states must not depend on colour alone. Widget-local styles must preserve
applicable hover/focus cues and use theme-bound recipes. Keep native indicator
drawings; no custom image may obscure a checkbox tick or radio dot.

## Dialogs and confirmations

Preserve current contents and workflow: readable title/body, bounded or scrollable
long details, bordered surface and separated button footer. Keep Close, Escape,
default buttons and worker close-protection intact. Do not introduce frameless
windows, custom close handling or modal chains for visual parity.

The prerequisite preview remains plain text with exact packages, commands, sources
and side effects. **No is the sole default and initially focused button**, with
approval before authentication. H15 is corrected by disabling Qt automatic default
promotion on every confirmation button. Focus may move to Yes without making it
the default. Enter declines from buttons; text widgets may consume it but cannot
approve. Space on the focused approval button or a click explicitly approves.
Escape declines. This policy also covers pre-action, guided-fix, tool-install and
rollback decisions. Read-only details support Tab traversal. Installation styling
is not authorisation. Active workers retain existing close/shutdown protection.

## Evidence and change control

Before/after real-widget captures use synthetic host/findings/package data and
mocked transactions. Save unique evidence under
`screenshots/ui-reference-alignment/before/` and `after/`, preserving prior evidence.
Temporary preferences, history and runtime logs stay outside the repository.
Fixtures explicitly select controls after startup; application installation
checkboxes still start unchecked. Focus/pressed captures use a safe Cancel button.

Validate both professional appearances and retained themes, navigation during a
fixture QThread, prerequisite approval/failure, shutdown and corrected Stage 1
captures. Record actual results separately: editing this specification does not
validate every widget, screen reader, desktop or deployed system.

Scanning, prerequisite rules, allowlists, results, approval, undo and worker
ownership are outside visual scope. Architecture/policy changes require separate
review. Wider findings remain in [the consolidated review](../consolidated_hardening_review.md).

Visual-alignment validation (2026-11-18): **258 tests passed**, corrected Stage 1 captures
**MATCH**, and both synthetic desktop fixtures exited successfully before/after.
The local paired capture index (`screenshots/ui-reference-alignment/comparison.md`)
links Overview, findings, prerequisite selection, focused/pressed controls and
dialogs. Main-window Tab traversal and safe Cancel-button focus were verified;
profile-dialog Tab traversal initially lacked desktop focus.

Final confirmation validation (2026-11-18): **262 tests passed**, corrected captures
MATCH. The profile fixture now activates the dialog and verifies real Qt focus:
Tab/Shift+Tab, wrap, checkbox Space, radio arrows and Escape passed in Enterprise
and Hybrid. Visible focus states were captured. See the
[confirmation audit and keyboard results](CONFIRMATION_REVIEW.md) for exact scope,
runtime assertions, evidence and limitations. Historical captures remain unchanged.
