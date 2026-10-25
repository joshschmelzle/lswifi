#!/usr/bin/env bash
set -euo pipefail

tag="${TAG:?}"
author="${RELEASE_AUTHOR:-}"
actor="${ACTOR:-}"

if [ "$author" = "github-actions[bot]" ] || [ "$actor" = "github-actions[bot]" ]; then
  echo "Release was created by the push workflow; not publishing again." >&2
  echo "publish=false"
  exit 0
fi

version="${tag#v}"
if [ "$version" = "$tag" ] || [[ ! "$version" =~ ^[0-9A-Za-z.+-]+$ ]]; then
  echo "Refusing tag: ${tag}" >&2
  exit 1
fi

case "$version" in
  *+*) version_url="${version//+/%2B}" ;;
  *) version_url="$version" ;;
esac

code="$(curl -sS -o /dev/null -w '%{http_code}' --retry 3 --retry-delay 1 \
  "https://pypi.org/pypi/lswifi/${version_url}/json")" || {
  echo "Could not check PyPI for ${version}" >&2
  exit 1
}

if [ "$code" = "200" ]; then
  echo "lswifi ${version} is already on PyPI; not publishing again." >&2
  echo "publish=false"
elif [ "$code" = "404" ]; then
  echo "publish=true"
  echo "tag=${tag}"
else
  echo "PyPI check for ${version} returned HTTP ${code}" >&2
  exit 1
fi
