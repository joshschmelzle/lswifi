# Agent notes

- `--json` output, including `--watchevents --json`, is parsed by third-party tools. Adding keys or events is safe at any time. A change that renames, removes, or retypes a key or event, or that changes the top-level shape, is allowed when it improves the output. Call it out in the PR body with the old and new form. The release that ships it bumps the minor version, and its `HISTORY.md` entry names the old and new form.
- No vendor, product, or chipset names in code, tests, new fixture names, commit messages, or PR text.
- No unnecessary code comments.
- Run the full pytest suite and mypy before pushing.
- Don't bump the version unless asked. A version change merged to `main` publishes a release.
- Don't design for rare or future cases nobody asked about.
- When reviewing, report a finding only if it would materially prevent or mislead a user doing ordinary work, or could cause data loss, a security hole, or a crash. Write the scenario first: the task, the normal steps, and what the user loses. If you can't write a concrete scenario, drop the finding.
- After the scenario, label the finding with one word: Blocker (fix it in this change), Follow-up (file an issue, leave the code alone), or Drop (don't report it). A rare data-loss, security, or crash bug never drops below Blocker just because it's rare.
- Don't report style, naming, docs, or rare future cases nobody asked about. A review with no comments is fine.
