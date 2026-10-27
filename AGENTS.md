# Agent notes

- `--json` output, including `--watchevents --json`, is parsed by third-party tools. Changes must be additive only: no renaming, removing, or retyping keys, and the top-level shape stays the same.
- No vendor, product, or chipset names in code, tests, new fixture names, commit messages, or PR text.
- No unnecessary code comments.
- Run the full pytest suite and mypy before pushing.
- Don't bump the version unless asked.
