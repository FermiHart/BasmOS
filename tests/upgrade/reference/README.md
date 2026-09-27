<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Original BASM-NANO reference

This is the frozen C reference used by the original upgrade's before/after
tests. It retains its BSD-3-Clause identification and FermiHart copyright.
The repository's LICENSE applies. Comparison with the actual source at GitHub
commit `8614d096` found only 35 omitted blank lines; code and comments match.

Local SHA-256: 75aad1c5e822e2b7040637d5eb07700cf540128598b343160fc9b8de32aee9df

Do not optimize this reference or use it in the production build. The original
warnings and defects are intentionally preserved for reproductions. The
benchmark accepts `--baseline FILE` to use an exact upstream source instead;
the published optimization results used the actual GitHub source.
