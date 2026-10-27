# Agent notes

- `--json` output, including `--watchevents --json`, is parsed by third-party tools. Adding keys or events is safe at any time. A change that renames, removes, or retypes a key or event, or that changes the top-level shape, is allowed when it improves the output. It needs a minor version bump and a `HISTORY.md` entry that names the old and new form, so consumers can update. Call it out in the PR body.
- No vendor, product, or chipset names in code, tests, new fixture names, commit messages, or PR text.
- No unnecessary code comments.
- Run the full pytest suite and mypy before pushing.
- Don't bump the version unless asked or a breaking `--json` change needs it.
