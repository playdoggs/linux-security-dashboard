# Project Instructions

## Review Handover Protocol

For every completed implementation, security review, bug fix, UI change or
development increment, produce a final response using the structure below.

The response must be self-contained, technically specific and suitable for copying
directly into another ChatGPT conversation for independent assessment.

### 1. Outcome

- Increment/task identifier and objective.
- Status: COMPLETE / PARTIAL / BLOCKED.
- What was delivered.
- Whether independent approval is requested.

### 2. Change inventory

Provide a table with:

- File path relative to repository root.
- Functions/classes changed.
- Nature of change.
- Reason for change.
- Security or behavioural impact.

Identify new, modified and deleted files.

### 3. Implementation details

Explain:

- Previous behaviour.
- New behaviour.
- Relevant state transitions and component relationships.
- Important design decisions and alternatives rejected.
- Any changes to existing interfaces or contracts.

Include exact file and line references for significant changes.

### 4. Security assessment

Explicitly report:

- Privileged operations and authorization boundaries.
- Subprocess execution and command construction.
- Input validation and trust boundaries.
- Credentials, secrets and sensitive output handling.
- Filesystem and package-management risks.
- Concurrency, cancellation, timeout and shutdown behaviour.
- Any new attack surface.
- Remaining risks.

If an area is unaffected, state that rather than omitting it.

### 5. UI/UX assessment

For UI changes, report:

- Affected screens and components.
- Styling changes and design-reference alignment.
- Default, hover, selected, checked, focus and disabled states.
- Keyboard navigation and dialog defaults.
- Enterprise and Hybrid profile behaviour.
- Responsive layout behaviour.
- Screenshot evidence paths.

Explicitly report any differences from agent_docs/ui/DESIGN_SYSTEM.md and the five
reference images.

### 6. Verification evidence

Provide:

- Exact test commands.
- Passed, failed, skipped and errored counts.
- Whether tests were run or results are from a previous execution.
- Synthetic versus real-environment testing.
- UI fixture results.
- Static analysis and diff checks.
- Any warnings or resource leaks.

Never claim a test passed without execution evidence.

### 7. Findings and limitations

List outstanding issues with:

- ID and severity.
- File/function affected.
- Reproduction conditions.
- Consequences.
- Recommended correction.
- Whether blocking or deferred.

Separate verified defects from suspected risks.

### 8. Git and artifact state

Report:

- Git branch.
- Changed and untracked files.
- Staged versus unstaged changes.
- Whether any commit was created.
- Review archive location and SHA-256, if produced.

Do not stage, commit, push, reset or otherwise modify Git state unless explicitly
authorised.

### 9. Independent review checklist

State:

- What another reviewer can verify from supplied evidence.
- What cannot be verified without source access.
- Any security-sensitive changes needing manual review.
- Whether the implementation is ready for independent review.

Do not declare independent approval on behalf of the reviewer.

### 10. Final summary

End with:

**Done:** Verified completed work.\
**Next:** Specific action required.\
**Goal:** Intended project outcome.

### Reporting rules

- Use Markdown tables and fenced code blocks where useful.
- Prefer evidence over reassurance.
- Include meaningful detail, not a superficial summary.
- Never omit failures, warnings or limitations.
- Never invent file paths, line numbers, test results or validation.
- Keep all paths repository-relative wherever possible.
- Redact credentials, tokens, private keys, usernames, full home paths, hostnames,
  public IPs and identifying infrastructure details.
- Do not dump complete logs or source files into the response.
- For large changes, prepare a separate review archive containing relevant source,
  patch, tests and evidence; reference it in the report.
- Keep the final report detailed but practical to copy and paste.
