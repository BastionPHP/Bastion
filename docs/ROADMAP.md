# Project direction

Bastion is pre-release. This document separates implemented capabilities from work that still needs design, verification or a published release. It is not a release schedule.

## Implemented in source

- Discover PHP installations and assess their patch state against the bundled advisory data.
- Inspect supported container and image surfaces, including replaced running binaries on Linux.
- Check selected PHP configuration mitigations for affected builds.
- Trace file, persistence and log indicators, with a timeline.
- Produce terminal, JSON, SARIF and offline HTML output.
- Assess pasted PHP/package output in the browser using shared test vectors.

Implementation does not imply universal platform coverage. See the [README](../README.md#coverage) and [architecture boundaries](ARCHITECTURE.md#boundaries-that-matter).

## Before the first binary release

- Complete a passing validation run for the tagged commit, including container integration and the false-positive corpus.
- Verify installation and signature checks against assets published by `BastionPHP/Bastion`.
- Review discovery limitations, privilege behavior and advisory coverage against the release documentation.
- Publish checksums, signature bundles and provenance attestations through the release workflow.
- Replace source-only onboarding with instructions for the actual published release.

## Priorities

**Better evidence.** Expand vendor and installation coverage with primary sources and regression fixtures. Make incomplete scans and unsupported cases easier to diagnose.

**Reproducible investigations.** Improve fixtures, offline workflows and the clarity of report evidence. Keep versioned output contracts usable by automation.

**Reliable contributions.** Make a new advisory, vendor package entry or trace rule straightforward to test without weakening uncertainty or false-positive controls.

## Proposals, not supported features

Patch-package generation for end-of-life PHP, migration assistance and runtime protection were previously described as Forge, Shift and Guard. They remain proposals. They require separate designs, operational boundaries and review before becoming supported commands.

Use a [feature proposal](https://github.com/BastionPHP/Bastion/issues/new?template=feature_request.yml) to describe the operator's problem, evidence available and a concrete acceptance criterion.
