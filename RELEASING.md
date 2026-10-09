# Releasing veilcore-records

This package is a verifier other people rely on, so what reaches npm has to be exactly
what this repository builds, and anyone has to be able to check that.

## The gate (runs on every `npm publish`)

`prepublishOnly` runs, in order, and any failure stops the publish:

1. `npm run clean`: deletes `dist/` and `conformance/__pycache__/`, so nothing stale or
   compiled elsewhere can ride along.
2. `npm run build`: regenerates the embedded `verify.py` and compiles `src/`.
3. `npm test`: the unit tests, the checks and the 101 conformance vectors (TypeScript).
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
node ../veilcore-sdk/conformance/run-cli.mjs "$PWD/target/release/conform"
```

Until the crate answers the `dnaPair` op (SPEC 3.7, added October 2026), it passes 100 of
the 101 vectors: the record-format ones.

## Provenance

npm provenance links a published version to the public commit and CI run that built it,
and npm shows it on the package page. **It can only be produced by a CI publish**
(GitHub Actions or GitLab CI with OIDC). A publish from a laptop carries none, and
nothing ties that tarball to a commit except trust in whoever ran it.

To publish with provenance, using npm trusted publishing (no long-lived npm token):

1. On npmjs.com, package `veilcore-records` -> Settings -> Trusted publishing: add
   GitHub Actions, repository `hunterincoming/veilcore-sdk`, workflow `publish.yml`.
2. Then under Publishing access choose "Require two-factor authentication and disallow
   tokens", so a leaked token cannot publish.
3. Add `.github/workflows/publish.yml`:

```yaml
name: publish
on: { push: { tags: ['v*'] } }
permissions: {}
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with: { persist-credentials: false }
      - uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0
        with: { node-version: "24.11.1", registry-url: "https://registry.npmjs.org" }
      - run: npm ci
      - run: npm publish --provenance --access public   # prepublishOnly runs the gate
```

   The action SHAs are the ones pinned in veilcore-midnight-testnet's CI. `ubuntu-latest`
   ships python3, which the gate's Python steps need.

4. Release: bump `version` in `package.json`, commit, `git tag vX.Y.Z`, push the tag.

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
