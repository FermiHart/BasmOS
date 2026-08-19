<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Contributing

Contributions that improve correctness, reproducibility, documentation and
verification are welcome.

## Development

1. Build with `make all`.
2. Run focused tests for the files changed.
3. Run `make proof` before submitting a pull request when KVM is available.
4. If guest bytes change intentionally, run `make manifest` and explain the byte
   budget and behavioral effect in the pull request.
5. Keep host executables, caches and private development records out of commits.

The record artifact is byte-budgeted. A change that adds bytes should state why
the behavioral or correctness benefit justifies the cost.

## Certificate Of Origin

All commits must include a `Signed-off-by` trailer certifying the Developer
Certificate of Origin 1.1:

```text
Signed-off-by: Your Name <you@example.com>
```

Add it with `git commit -s`. By contributing, you agree that your contribution
is licensed under BSD-3-Clause.

## Style

- Preserve LF line endings.
- Keep assembly comments focused on invariants and byte-level decisions.
- Add SPDX identifiers to new source and script files.
- Do not add dependencies without documenting their license and purpose.
- Never weaken a verification gate merely to make CI pass.

## Security

Use the private process in `SECURITY.md` for vulnerabilities. Do not submit a
public pull request containing an undisclosed exploit.
