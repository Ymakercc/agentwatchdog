---
name: Agent fingerprint
about: Request support for an agent CLI, or report a wrong fingerprint
labels: fingerprint
---

**Agent CLI and version**

**How it appears in a process list**

- `comm` (from `cat /proc/<pid>/comm` while it runs):
- `argv[0]` (first element of the command line):

**Where does it carry the prompt?**

Check everything that applies — this is the part that matters:

- [ ] bare positional argument (`agent "do the thing"`)
- [ ] positional after a subcommand (`agent run "do the thing"`)
- [ ] flag value (which flags? e.g. `-m`, `--prompt`):
- [ ] file referenced by a flag (which flags?):
- [ ] stdin only

**Flags whose values are worth keeping in an audit log**

(model selection, sandbox/permission mode, output format — things an operator
would want to see; NOT paths, prompts, session ids or keys)

**If reporting a wrong fingerprint: what was misidentified or leaked?**

> If the bug is that something sensitive survived redaction, stop — report it
> privately via SECURITY.md, not here.

**Willing to submit the PR yourself?**

A fingerprint is one JSON file plus one test case; CONTRIBUTING.md walks
through it. Fingerprint PRs without a redaction test are not merged.
