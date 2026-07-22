# Security Policy

## Supported Versions

xprobe is a pre-1.0 project. Security fixes are provided for the latest release
only. Reproduce a report against the latest release or the current `master`
branch when possible.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a Vulnerability

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/itdevwu/xprobe/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

Include the affected xprobe version, operating system and kernel, relevant
permission and namespace configuration, reproduction steps, observed impact,
and whether the target process recovered cleanly. Remove application secrets,
captured payloads, and other unrelated sensitive data from the report.

This project is maintained independently and does not promise a response SLA.
Reports will be assessed as time permits. Please allow a reasonable period for
triage and remediation before public disclosure.

## Trust Boundary

xprobe uses eBPF/perf and ptrace capabilities granted by Linux. A live CUDA
measurement may inject a CUPTI Agent into a process that the invoking user is
already permitted to trace. The Agent remains mapped after collection and is
disabled logically. These documented operations intentionally modify target
state and require elevated access in many environments.

Security boundaries still apply around which process is selected, which Linux
credentials and namespaces authorize access, what data is collected, how target
state is restored, and who can read or control local artifacts and Agent sockets.

## Scope

Examples of security issues include:

- accessing or modifying a process outside the invoking user's Linux authority;
- PID reuse or identity-check failures that attach to a different process;
- failed attach or injection cleanup that does not restore target execution
  state;
- Agent sockets, trace artifacts, or installed files with unsafe permissions;
- collection or exposure of sensitive target data beyond the documented event
  contract;
- package or installer behavior that violates the documented integrity checks.

Ordinary profiling overhead, inaccurate measurements without a security impact,
expected mutation disclosed by `validate` and `measure`, and behavior on an
unsupported release are not security vulnerabilities by themselves.
