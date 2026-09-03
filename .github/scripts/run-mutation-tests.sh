#!/usr/bin/env bash

set -euo pipefail

run_full_suite() {
  uv run --locked --only-group mutation mutmut run
}

if [[ "${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME must be set}" != "pull_request" ]]; then
  run_full_suite
  exit 0
fi

changed_modules=()
changed_modules_output="$(
  git diff --name-only --diff-filter=ACMR "${BASE_SHA:?BASE_SHA must be set}" "${HEAD_SHA:?HEAD_SHA must be set}" -- \
    'scripts/*.py' |
    sed -e '/^scripts\/tests\//d' -e 's#\.py$##' -e 's#/#.#g' -e 's/$/*/'
)"

if [[ -n "$changed_modules_output" ]]; then
  while IFS= read -r module; do
    changed_modules+=("$module")
  done <<<"$changed_modules_output"
fi

if [[ "${#changed_modules[@]}" -eq 0 ]]; then
  echo "No production script modules changed; running the full mutation suite."
  run_full_suite
  exit 0
fi

printf 'Mutating changed modules: %s\n' "${changed_modules[*]}"
uv run --locked --only-group mutation mutmut run "${changed_modules[@]}"
