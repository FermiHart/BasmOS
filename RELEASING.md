<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com> -->

# Release And Publication Procedure

This procedure publishes only the Git allowlist. Private due-diligence records,
host executables and caches are excluded by `.gitignore`.

## 1. Rebuild And Verify

When guest source changes, rebuild and review the new artifacts before updating
their expected hashes:

```sh
make clean
make all
make map
make shell-map
make jash-map
make manifest
make readme-art
```

Then execute the release gates:

```sh
make clean-room-proof
make verify-nasm
make verify-sacred
make verify-jash-capture
git add --dry-run .
git status --short --ignored
```

Review every generated binary and manifest change. `make manifest` records the
current bytes; it does not decide whether those bytes are correct.

Remove generated host executables before publication. They are ignored in any
case:

```sh
make -C basm-nano clean
make -C bemu clean
rm -f tools/proofctl
```

## 2. Create The Initial Commit

Set the GitHub owner and repository name, then inspect and commit the public
allowlist:

```sh
export OWNER='YOUR_GITHUB_ACCOUNT'
export REPO='BasmOS'
export VERSION='v0.1.0'

git add .
git diff --cached --check
git diff --cached --stat
git status --short
git commit -s -m 'Release BasmOS v0.1.0'
```

The `-s` flag records the Developer Certificate of Origin sign-off required by
`CONTRIBUTING.md`. Use a cryptographically signed commit as well if the local Git
identity has signing configured.

## 3. Create And Push The GitHub Repository

Authenticate GitHub CLI, create the public repository and push `main`:

```sh
gh auth status
gh repo create "$OWNER/$REPO" \
  --public \
  --source=. \
  --remote=origin \
  --push \
  --description='A complete IA-32 nanokernel record artifact in one 512-byte boot sector'

gh repo edit "$OWNER/$REPO" \
  --homepage='https://nanokernel.org' \
  --add-topic=operating-system \
  --add-topic=nanokernel \
  --add-topic=x86 \
  --add-topic=boot-sector \
  --add-topic=systems-programming
```

Do not use `git add -f` on ignored files.

## 4. Enable GitHub Pages

The committed `CNAME` makes `nanokernel.org` the custom domain on the first
deploy, so point and verify DNS before enabling Pages. The pinned
`.github/workflows/pages.yml` workflow publishes automatically after CI succeeds
for the current `main` revision. After the repository's first push, enable
workflow-based Pages and rerun that verified push's CI attempt:

```sh
gh api --method POST "repos/$OWNER/$REPO/pages" -f build_type=workflow
RUN_ID=$(gh run list --repo "$OWNER/$REPO" --workflow CI --branch main \
  --event push --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID" --repo "$OWNER/$REPO"
gh run rerun "$RUN_ID" --repo "$OWNER/$REPO"
gh run watch "$RUN_ID" --repo "$OWNER/$REPO"
```

The default URL is `https://OWNER.github.io/REPO/`; the committed `CNAME`
selects `nanokernel.org`. Domain and DNS ownership remain deployment concerns
outside this repository.

## 5. Tag And Publish A Release

Create a signed tag when signing is configured, push it, and attach the exact
guest artifacts plus their checksums:

```sh
git tag -s "$VERSION" -m "BasmOS $VERSION"
git push origin "$VERSION"

gh release create "$VERSION" \
  basmos.bin \
  basmos-vm.bin \
  basmos-sh.bin \
  jash/jash.bin \
  jash/jash-pack.bin \
  ARTIFACTS.manifest \
  SHA256SUMS \
  --repo "$OWNER/$REPO" \
  --verify-tag \
  --title="BasmOS $VERSION" \
  --notes='Reproducible BasmOS guest artifacts. Verify with sha256sum -c SHA256SUMS and make proof.'
```

If signed tags are not configured, configure a trusted signing identity before
publishing rather than silently replacing the command with an unsigned tag.

## 6. Post-Publication Checks

```sh
gh workflow list --repo "$OWNER/$REPO"
gh run list --repo "$OWNER/$REPO" --limit 10
gh release view "$VERSION" --repo "$OWNER/$REPO"
```

Download the release into a fresh directory, run `sha256sum -c SHA256SUMS`, and
confirm that the Pages download produces the same 512-byte `basmos.bin`.
