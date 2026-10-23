# Releasing veilcore-records

This package is a verifier other people rely on, so what reaches npm has to be exactly
what this repository builds, and anyone has to be able to check that.

## The gate (runs on every `npm publish`, and as its own step in CI before staging)

`prepublishOnly` runs, in order, and any failure stops the publish:

1. `npm run clean`: deletes `dist/` and `conformance/__pycache__/`, so nothing stale or
   compiled elsewhere can ride along.
2. `npm run build`: regenerates the embedded `verify.py` and compiles `src/`.
3. `npm test`: the unit tests, the checks and the 181 conformance vectors (TypeScript).
4. `npm run conformance:python`: the same vectors against `conformance/impl.py`.
5. `node scripts/check-pack.mjs`: lists exactly what `npm pack` would upload and fails on
   anything that must not ship (`__pycache__`, `.pyc`, `src/`, `test/` and its TEST-ONLY
   keys, `.key`/`.pem` files) or on a missing entry point.

`package.json` `files` also excludes `**/__pycache__` and `**/*.pyc`. `.gitignore` alone
does not: `files` overrides it.

Before tagging, check by hand once:

```
npm pack --dry-run          # expect ~64 files, no .pyc, no test/, no src/
```

The Rust crate is checked separately, against these vectors:

```
cd veilcore-rs && cargo test && cargo build --release
node ../veilcore-sdk/conformance/run-cli.mjs "$PWD/target/release/conform" --without-animal-profile --without-strain-profile
```

A crate that does not answer the `keyFromSecret`, `recordFingerprint` and `keyMatch` ops
(SPEC 3.6.1, added October 2026) passes 101 of the 121 vectors; one that does not answer
`dnaPair` either (SPEC 3.7) passes 100, the record-format ones.

## Provenance

npm provenance links a published version to the public commit and CI run that built it,
and npm shows it on the package page. **It can only be produced by a CI publish**
(GitHub Actions or GitLab CI with OIDC). A publish from a laptop carries none, and
nothing ties that tarball to a commit except trust in whoever ran it.

To publish with provenance, using npm trusted publishing (no long-lived npm token) and
npm staged publishing (nothing goes live without a person's 2FA):

1. On npmjs.com, package `veilcore-records` -> Settings -> Trusted publishing: add
   GitHub Actions, repository `hunterincoming/veilcore-sdk`, workflow `publish.yml`,
   environment blank. Under **Allowed actions** leave "publish directly" and "manage
   dist-tags" **unticked**: this publisher can only stage.
2. Under Publishing access choose "Require two-factor authentication and disallow tokens",
   so a leaked token cannot publish.
3. `.github/workflows/publish.yml` (in this repository) runs on a `v*` tag: `npm ci`, the
   gate, then `npm stage publish --provenance --access public` with npm 11.15.0 (staging
   needs 11.15.0 or later; Node 24.11.1 ships an older npm).

Why staged: CI can build and sign a version but cannot make it live. A stolen GitHub
account, a poisoned dependency in CI or a mistaken tag ends as a staged version nobody
approves, not as a release thousands of verifiers install. The cost is one approval per
release.

4. Release: bump `version` in `package.json` and `package-lock.json`, commit, push, then
   create a GitHub release with a new tag `vX.Y.Z` on that commit (the tag starts the run).
5. When the run is green: npmjs.com -> `veilcore-records` -> **Staged Packages** -> check
   the version and its provenance -> **Approve** (asks for 2FA). Or from a terminal:
   `npm stage list`, then `npm stage approve <stage-id>`.

Never move or reuse a tag. If a run fails, fix it on main and release the next patch
version (0.17.0 was tagged but never reached npm; 0.17.1 is the same code).

Check the result: `npm view veilcore-records@X.Y.Z --json | grep -A3 attestations`, or
`npm audit signatures` in a project that depends on it. The package page shows a
"Provenance" panel naming the commit and workflow run.

## If a release has to go from a laptop

It will have no provenance; say so in the release notes. Run the gate explicitly first
and read the listing:

```
git status                  # clean tree, on the commit being released
npm run clean && npm run build && npm test && npm run conformance:python
npm pack --dry-run
npm publish                 # prepublishOnly runs the gate again
```

Afterwards, record the published tarball's integrity next to the commit, so it can be
compared with a rebuild: `npm view veilcore-records@X.Y.Z dist.integrity`.
