# Contributing

Bug reports and pull requests are welcome.

- Keep `ssh_exec.py` and `xlsx_safe.py` in sync with the rest of the family.
- Policy resolution, diffing, and the SSH lockout guard are pure functions. Add
  a fixture under `tests/fixtures/` for any new ruleset or policy shape rather
  than testing over a live firewalld.
- The SSH lockout guard must stay on by default; only `--force` disables it, and
  unmanaged hosts must never have rules removed.
- Run `pytest -q` before opening a PR. CI runs on Python 3.9 through 3.12.
- Plain, direct writing in docs and messages.
