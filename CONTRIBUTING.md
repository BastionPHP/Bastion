# Contributing to Bastion

Bastion needs findings that operators can explain and reproduce. A small change with a clear fixture and a primary source is more useful than a broad claim of support.

For a vulnerability in Bastion or an affected build incorrectly reported as `fixed`, use [private vulnerability reporting](https://github.com/BastionPHP/Bastion/security/advisories/new). See [SECURITY.md](SECURITY.md). Other bugs, coverage requests and documentation fixes belong in [Issues](https://github.com/BastionPHP/Bastion/issues/new/choose).

## Set up a development environment

The CLI targets Linux and macOS. Use Go 1.24+, Make and Node.js 20+. Container integration requires Linux, Docker, and root or passwordless `sudo`.

```sh
git clone https://github.com/BastionPHP/Bastion.git
cd Bastion
make build
make test
```

The website uses a dependency-free Node build. A complete build runs the CLI to generate its command-reference tables:

```sh
make site-serve
```

Read [Architecture](docs/ARCHITECTURE.md) before changing discovery, assessment or output schemas. Work on a branch in your fork and keep each pull request focused on one behavior.

## Choose the right evidence

| Change | Required evidence |
| :--- | :--- |
| Advisory or vendor fix data | Official vendor/advisory URL, exact package/branch scope, and a regression fixture |
| Assessment or version comparison | Go test and shared vector covering the changed decision; matching browser behavior |
| Discovery or package attribution | Representative filesystem/package fixture; relevant container integration case |
| Trace signature | Inert positive fixture, legitimate negative fixture, and false-positive corpus results |
| CLI output or schema | Before/after output and compatibility impact |
| Website or documentation | Successful build; relevant desktop/mobile screenshots for layout changes |

Never infer a fixed package version from a similar distribution or from an upstream version alone. If a vendor fix cannot be verified, retain `unknown` rather than adding unsupported data.

## Keep the two engines aligned

Assessment logic lives in [`internal/advisory/`](internal/advisory/); browser logic lives in [`site/assets/engine.js`](site/assets/engine.js). Both use fixtures from [`testdata/`](testdata/).

1. Add a case to `testdata/vectors.json` or `testdata/paste.json` that demonstrates the behavior.
2. Update the relevant implementation and its counterpart.
3. Run `make test` and check that both agree on the expected verdict.

Preserve explicit uncertainty. Do not turn missing evidence into `fixed`, or hide a discovery failure merely to produce a clean result.

## Test the change you make

```sh
make test

# Required when changing discovery, package lookup or scanning:
make integration

# Required when changing pages, assets or generated documentation:
make site
```

CI also exercises cross-compilation, installer verification and a legitimate PHP corpus. For a new trace rule, use the corpus procedure in [ci.yml](.github/workflows/ci.yml), inspect every new match, and explain unavoidable ambiguity in the PR. Test payloads must be inert; follow the fixtures in [`internal/trace/trace_test.go`](internal/trace/trace_test.go).

If a check cannot run in your environment, name it and explain why. Do not mark it as passed. Container setup failures should include the relevant setup logs, not just a timeout message.

## Submit a useful pull request

Explain the concrete problem, the resulting behavior, and the evidence used to validate it. Include commands and results. Link the issue or primary advisory where relevant.

Keep formatting changes separate from behavior changes. Do not edit generated demo output by hand: regenerate it with [`scripts/demo/record.sh`](scripts/demo/record.sh) and retain the recording metadata. Avoid new dependencies unless the benefit outweighs the installation and audit cost.

Reports and fixtures must not contain credentials, private customer data or an executable webshell. Use synthetic paths and inert payloads when a real example cannot be shared safely.

## Compatibility and scope

- Keep CLI exit codes and versioned JSON schemas stable, or call out a proposed breaking change explicitly.
- Preserve evidence and confidence fields when extending verdicts.
- Keep inspection separate from actions that modify a target system. A remediation feature requires a separate design discussion.
- Do not add exploit execution or automatic remote probing.
- Treat roadmap entries as proposals. Discuss substantial new capabilities before implementing them.

Contributions are made under the repository's [MIT license](LICENSE).
