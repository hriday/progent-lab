# Vendored: Progent reference implementation

Source: https://github.com/sunblaze-ucb/progent (directory `secagent/`)
Commit: 5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565 (2026-09-24)
License: MIT (see LICENSE in this directory)

Files are copied unmodified. The app imports only pure functions and prompt
constants from them (`_check_tool_call`, `security_policy_subset_check`,
`SYS_PROMPT`, `SYS_PROMPT_UPDATE`, `SYS_PROMPT_2`, `extract_json`); it never
touches the module-level globals, `sys.exit()` or `input()` paths, so that
several sessions can share one process.

`role_analyzer.py` is itself adapted by the Progent authors from
https://github.com/gravitational/rbac-linter (Apache-2.0).
