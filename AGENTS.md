# Agent notes

- `--json` output, including `--watchevents --json`, is parsed by third-party tools. Adding keys or events is safe at any time. A change that renames, removes, or retypes a key or event, or that changes the top-level shape, is allowed when it improves the output. Call it out in the PR body with the old and new form. The release that ships it bumps the minor version, and its `HISTORY.md` entry names the old and new form.
- No vendor, product, or chipset names in code, tests, new fixture names, commit messages, or PR text.
- No unnecessary code comments.
- Run the full pytest suite and mypy before pushing.
- Don't bump the version unless asked. A version change merged to `main` publishes a release.
