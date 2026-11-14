# Changelog

All notable changes to Linux Security Dashboard are documented here.

## [Unreleased] — v4.2.1

### Changed
- Documentation refreshed across all markdown files to match current v4.2 code behavior.
- Architecture, communication flow, persistence model, and test checklist updated to current implementation.

### Security
- Added an explicit security review record (2026-04-23) to docs.
- Documented open high-impact logic/command-execution bugs in Guided Wizard and quick checks.

### Fixed
- Buffered command failures no longer trigger success callbacks. Guided fixes
  stop after failure and restore controls; failed actions and rollbacks retain
  their findings/history. Failed Lynis installation and update checks clear
  pending scan state without invoking healthy-completion callbacks. Partial
  wizard failures refresh status indicators without claiming full completion.
  Update callback references are released on either outcome.
- Added mocked command-outcome regression tests; no privileged commands are
  executed by the suite. Streaming worker behavior is unchanged.

## [v4.2]
- Current production baseline reflected by this repository state.
