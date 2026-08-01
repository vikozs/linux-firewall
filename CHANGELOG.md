# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
semantic versioning.

## [1.0.0] - 2026-07-31

Initial release.

### Added
- `discover` mode: read the effective firewalld ruleset (services and ports on
  the default zone), diff it against a declarative policy, and write a plan
  (JSON) and an Excel report.
- `apply` mode: reconcile firewalld from a plan with per-host confirmation,
  re-validating against the live ruleset first, writing permanent changes then
  reloading and verifying.
- Declarative policy in JSON (YAML too, if PyYAML is installed), with groups,
  per-host entries, and optional defaults.
- SSH lockout guard: a change that would remove the ssh service or the control
  SSH port is blocked unless `--force`.
- Unmanaged hosts (no policy entry and no defaults) are reported but never have
  rules removed.
- Runtime-vs-permanent drift detection.
- nftables fallback: on a host without firewalld, or with `--backend nftables`,
  discover dumps the nftables ruleset for visibility; it is not diffed or
  reconciled.
- `report` mode: re-render an existing plan to Excel with no SSH.
- Shared `ssh_exec.py` transport and `xlsx_safe.py` Excel safety layer from the
  linux-audit family. Test suite and GitHub Actions CI on Python 3.9-3.12.
