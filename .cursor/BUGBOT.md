# Review rules

Report a finding only when it would materially prevent or mislead a user doing ordinary work with lswifi, such as scanning, reading the decoded output, or parsing `--json`, or when it could cause data loss, a security hole, or a crash. Write the scenario first: the task, the normal steps, and what the user loses. If you can't write a concrete scenario, drop the finding.

After the scenario, label the finding with one word:

- Blocker: fix it in this change.
- Follow-up: file an issue and leave the code alone.
- Drop: don't report it.

A rare data-loss, security, or crash bug never drops below Blocker just because it's rare.

Don't report style, naming, docs, or rare future cases nobody asked about. A review with no comments is fine.

A change that renames, removes, or retypes a `--json` key without saying so in the PR body counts as user impact.
