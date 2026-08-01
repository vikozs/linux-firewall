# Security

## Reporting

Report vulnerabilities privately through GitHub Security Advisories on this
repository. Please do not disclose details publicly until a fix is released.

## Handling of credentials and run artifacts

- SSH and sudo passwords are passed over stdin or the `SSHPASS` environment
  variable, never as command-line arguments.
- SSH lockout guard: apply refuses to remove the ssh service or the control SSH
  port unless `--force` is given. Use `--force` only when you have out-of-band
  access to the host.
- Unmanaged hosts (absent from the policy, no defaults) are reported but never
  reconciled, so an incomplete policy cannot strip a host's rules.
- apply writes permanent firewalld changes, reloads, and verifies the resulting
  runtime. It re-validates against the live ruleset before acting.
- Plans, results, and the report describe your network exposure. They are
  gitignored. Do not commit them.
- Values written into the Excel report are neutralised against spreadsheet
  formula injection.
