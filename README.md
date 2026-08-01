# linux-firewall

firewalld policy audit and reconciliation for a RHEL 9 fleet. You describe what
each host is allowed to expose in a declarative policy; linux-firewall reads the
effective firewalld ruleset, diffs it against the policy, and can reconcile the
difference with per-host confirmation. Output is a formatted Excel report and a
machine-readable plan.

An SSH lockout guard blocks any change that would drop your control SSH access
unless you explicitly `--force` it.

Part of a family with [linux-audit](https://github.com/vikozs/linux-audit),
[linux-harden](https://github.com/vikozs/linux-harden),
[linux-diskspace](https://github.com/vikozs/linux-diskspace),
[linux-patch](https://github.com/vikozs/linux-patch),
[linux-certs](https://github.com/vikozs/linux-certs),
[linux-users](https://github.com/vikozs/linux-users), and
[linux-drift](https://github.com/vikozs/linux-drift). It shares their transport
(`ssh_exec.py`) and Excel safety layer (`xlsx_safe.py`).

## What it does

- Reads the effective firewalld config for each host's default zone: allowed
  services and ports, runtime and permanent.
- Diffs that against your policy and produces a set of changes: services and
  ports to add, and ones to remove.
- Applies the changes with confirmation, writing permanent rules then reloading
  and verifying the result.
- Flags runtime-vs-permanent drift (rules that exist in one but not the other).

## Backends

firewalld is the primary backend and the only one `apply` supports. On a host
without firewalld, or with `--backend nftables`, `discover` falls back to
dumping the nftables ruleset for visibility. It does not diff or reconcile that.

## Policy

A JSON file (YAML too, if PyYAML is installed). Groups hold shared allow-lists;
hosts can name a group and add their own; optional defaults apply to any host
not listed.

```json
{
  "groups": {
    "web": {"allow_services": ["ssh", "http", "https"],
            "allow_ports": ["8443/tcp"]}
  },
  "hosts": {
    "web01.zav-mb.loc": {"group": "web", "allow_ports": ["9100/tcp"]},
    "db01.zav-mb.loc": {"allow_services": ["ssh"], "allow_ports": ["5432/tcp"]}
  },
  "defaults": {"allow_services": ["ssh"]}
}
```

A host's effective allow-list is the union of defaults, its group, and its own
entry. Ports without a protocol default to `/tcp`. A host that is absent from
the policy with no defaults is treated as unmanaged: its extra rules are
reported but never removed.

## Requirements

- Python 3.9+ and `openpyxl` on the machine you run it from. `PyYAML` only if
  you write the policy in YAML.
- `sshpass` on that machine if you use password SSH login.
- RHEL 9 targets with firewalld. Sudo is needed for `firewall-cmd`.

```
pip install -r requirements.txt
```

## Usage

Audit the fleet against a policy, writing `firewall_plan.json` and a report:

```
python3 linux_firewall.py discover -H hosts.txt -u sa.vko --policy policy.json \
    --ask-ssh-pass --sudo-pass-same-as-ssh
```

Review the report, then reconcile, confirming per host:

```
python3 linux_firewall.py apply --plan firewall_plan.json --policy policy.json \
    -H hosts.txt -u sa.vko --ask-ssh-pass --sudo-pass-same-as-ssh
```

If your SSH runs on a non-default port, tell the guard so it protects the right
one:

```
python3 linux_firewall.py discover -H hosts.txt -u sa.vko --policy policy.json \
    --ask-ssh-pass --sudo-pass-same-as-ssh --ssh-port 2222/tcp
```

Re-render an existing plan to Excel without touching the fleet:

```
python3 linux_firewall.py report --plan firewall_plan.json -o report.xlsx
```

`--force` disables the SSH lockout guard; `-y`/`--yes` skips per-host
confirmation. Passwords travel via stdin or the `SSHPASS` env var, never on the
command line.

## Output

`firewall_report.xlsx` sheets:

- Summary: per host, backend, zone, change count, blocked count, runtime/
  permanent drift, whether the host is managed.
- Policy Drift: every service/port to add or remove, and anything the SSH guard
  blocked.
- Effective Rules: runtime services and ports next to what the policy allows.
- Runtime vs Permanent: rules present in one but not the other.
- Errors: hosts that could not be reached.
- About: tool version, build stamp, guarded SSH port, totals.

`firewall_plan.json` is the same data as structured input for `apply`, which
writes `firewall_results.json` recording what changed per host.

## Notes and limitations

- v1 reconciles services and ports on the default zone. Rich rules, sources,
  interfaces, and multi-zone setups are not modified.
- nftables hosts are shown for visibility only, not diffed or reconciled.

## Development

```
pip install -r requirements.txt pytest PyYAML
pytest -q
```

Policy resolution, diffing, and the SSH lockout guard are pure functions.
Fixtures cover policy drift, the SSH guard (with and without `--force`),
unmanaged hosts, an nftables host, and runtime/permanent drift.

## License

MIT. See [LICENSE](LICENSE).
