# Review rules

Report a finding only when it would materially prevent or mislead a user doing ordinary work with lswifi, such as scanning, reading the decoded output, or parsing `--json`. For each finding, state the realistic task, the normal steps, and what the user loses.

Rate each finding from 1 to 10 for likelihood and from 1 to 10 for severity. Don't report a finding whose product is below 5. Leave low-impact findings out rather than reporting them at a lower severity.

A change that renames, removes, or retypes a `--json` key without saying so in the PR body counts as user impact.
