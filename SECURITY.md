<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com> -->

# Security Policy

## Scope

BasmOS is an experimental systems-research artifact. It is not intended to
protect production workloads or execute untrusted guest images without an
external sandbox.

Security reports are welcome for:

- host memory-safety issues in `basm-nano`, `bemu-nano` or `proofctl`;
- guest-to-host boundary issues in the KVM runner or test harnesses;
- artifact verification bypasses;
- unexpected CPL3-to-CPL0 escalation in `basmos-sh.bin`;
- supply-chain, CI or release provenance issues.

`basmos.bin` provides bounded task-data segments (see `DOMAINS.md`) but no
process-isolation boundary: both tasks run in CPL0 with a flat SS, and the
documented absence of hostile-code isolation is a design limit, not a
vulnerability. See `THREAT_MODEL.md` for the explicit trust boundaries.

## Reporting

Email **security reports privately** to <contact@fermihart.com> with:

- affected commit or release;
- reproduction steps;
- expected and observed behavior;
- impact assessment;
- suggested embargo requirements.

Do not open a public issue containing a working exploit or sensitive data.
Receipt should be acknowledged within seven days. Disclosure timing will be
coordinated with the reporter after a fix or mitigation is available.

## Safe Execution

Only execute code from revisions you trust. Host tools are built locally from
source and are not committed. QEMU tests use a read-only image, disabled
networking and QEMU sandboxing. KVM still exposes a host kernel interface and
should be run as an unprivileged user inside an appropriate host sandbox when
testing modified guests.
