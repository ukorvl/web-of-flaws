#!/usr/bin/env bats

setup() {
  script="$BATS_TEST_DIRNAME/../run-mutation-tests.sh"
  fake_bin="$BATS_TEST_TMPDIR/bin"
  uv_log="$BATS_TEST_TMPDIR/uv.log"

  mkdir -p "$fake_bin"
  export PATH="$fake_bin:$PATH"
  export UV_LOG="$uv_log"
  export GITHUB_EVENT_NAME="pull_request"
  export BASE_SHA="base-sha"
  export HEAD_SHA="head-sha"

  cat >"$fake_bin/git" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${GIT_DIFF_OUTPUT:-}" ]]; then
  printf '%s\n' "$GIT_DIFF_OUTPUT"
fi
EOF

  cat >"$fake_bin/uv" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$UV_LOG"
EOF

  chmod +x "$fake_bin/git" "$fake_bin/uv"
}

@test "runs the full suite outside pull requests" {
  export GITHUB_EVENT_NAME="schedule"

  run bash "$script"

  [ "$status" -eq 0 ]
  [ "$(cat "$uv_log")" = "run --locked --only-group mutation mutmut run" ]
}

@test "runs the full suite when a pull request changes no production scripts" {
  export GIT_DIFF_OUTPUT="scripts/tests/test_check.py"

  run bash "$script"

  [ "$status" -eq 0 ]
  [ "$(cat "$uv_log")" = "run --locked --only-group mutation mutmut run" ]
}

@test "mutates changed production script modules only" {
  export GIT_DIFF_OUTPUT=$'scripts/check.py\nscripts/validate_standards.py\nscripts/tests/test_check.py'

  run bash "$script"

  [ "$status" -eq 0 ]
  [ "$(cat "$uv_log")" = "run --locked --only-group mutation mutmut run scripts.check* scripts.validate_standards*" ]
}
