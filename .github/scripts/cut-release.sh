#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

: "${GITHUB_OUTPUT:?}"
: "${GITHUB_SHA:?}"
: "${GITHUB_REPOSITORY:?}"
: "${BEFORE:?}"

notes_dir="${RUNNER_TEMP:-$(mktemp -d)}"

skip() {
  echo "$1"
  echo "released=false" >> "$GITHUB_OUTPUT"
  exit 0
}

read_version() {
  python3 -c '
import ast, pathlib, sys
mod = ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for node in mod.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                value = ast.literal_eval(node.value)
                if isinstance(value, str) and value:
                    print(value, end="")
                    raise SystemExit(0)
raise SystemExit("__version__ missing")
' "$1"
}

tag_exists() {
  local tag="$1"
  local listed
  if ! listed="$(git ls-remote --tags origin "refs/tags/${tag}")"; then
    return 2
  fi
  printf '%s\n' "$listed" | awk -v ref="refs/tags/${tag}" '$2 == ref { found = 1 } END { exit found ? 0 : 1 }'
}

gh_release() {
  if [[ "${DRY_RUN:-}" == 1 ]]; then
    printf 'dry-run:'
    printf ' %q' gh "$@"
    printf '\n'
    return 0
  fi
  gh "$@"
}

if [[ -z "$BEFORE" || "$BEFORE" =~ ^0+$ ]]; then
  skip "No previous commit; skipping."
fi

if ! git cat-file -e "${BEFORE}^{commit}" 2>/dev/null; then
  git fetch --no-tags origin "$BEFORE"
fi

current="$(read_version lswifi/__version__.py)"
if [[ ! "$current" =~ ^[0-9A-Za-z.+-]+$ ]]; then
  echo "Refusing version: ${current}" >&2
  exit 1
fi

if git cat-file -e "${BEFORE}:lswifi/__version__.py" 2>/dev/null; then
  prev_file="${notes_dir}/previous_version.py"
  git show "${BEFORE}:lswifi/__version__.py" > "$prev_file"
  previous="$(read_version "$prev_file")"
else
  previous=""
fi

echo "Version ${previous:-<none>} -> ${current}"
if [[ "$current" == "$previous" ]]; then
  skip "Version unchanged (${current}); skipping."
fi

tag="v${current}"
set +e
tag_exists "$tag"
exists=$?
set -e
if [[ "$exists" -eq 0 ]]; then
  skip "Tag ${tag} already exists; skipping."
elif [[ "$exists" -ne 1 ]]; then
  echo "Could not check whether ${tag} exists" >&2
  exit 1
fi

notes_file="${notes_dir}/release-notes.md"
set +e
python3 .github/scripts/history_notes.py HISTORY.md "$current" > "$notes_file"
status=$?
set -e
title="lswifi ${tag} 🛜🚀"
if [[ "$status" -eq 0 ]]; then
  printf '\nSee [HISTORY.md](https://github.com/%s/blob/main/HISTORY.md).\n' "$GITHUB_REPOSITORY" >> "$notes_file"
  gh_release release create "$tag" \
    --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" \
    --title "$title" \
    --notes-file "$notes_file"
elif [[ "$status" -eq 2 ]]; then
  echo "No HISTORY.md section for ${current}; generating notes."
  gh_release release create "$tag" \
    --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" \
    --title "$title" \
    --generate-notes
else
  exit "$status"
fi

echo "released=true" >> "$GITHUB_OUTPUT"
echo "tag=${tag}" >> "$GITHUB_OUTPUT"
