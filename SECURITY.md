# Security policy

Bastion inspects PHP installations and signs of intrusion. It does not establish that a host is trustworthy, and it is not a substitute for forensic acquisition on a compromised system.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/BastionPHP/Bastion/security/advisories/new) for:

- Vulnerabilities in Bastion's own file handling, parsers, image processing or report rendering.
- A PHP build reported as `fixed` when it is actually affected.
- Findings that could expose sensitive data or cause unrequested code execution.

Include the Bastion commit or version, platform, minimal reproduction, expected behavior and actual result. For a false-safe verdict, include sanitized `bastion scan --format json` output and the vendor or upstream evidence that contradicts it. Keep credentials and unrelated customer data out of the report.

Do not disclose an unpatched vulnerability in a public issue. We will use the private advisory to coordinate reproduction, remediation and disclosure. This project does not promise a response-time SLA or provide a paid incident-response service.

## Maintenance status

Bastion is currently pre-release, with no published binary release. Security fixes are developed against `main`; no historical maintenance branches or extended support windows have been established. Include the exact commit when reporting a problem with a source build.

Missing vendor coverage, stale data that does not produce a false-safe verdict, and ordinary false positives can use the public [issue forms](https://github.com/BastionPHP/Bastion/issues/new/choose). Include a primary source for advisory corrections.

## Inspection boundaries

The scanner reads binaries and metadata. When static identification is insufficient, the default scan may invoke `php -v` or a container-exec fallback. `scan --no-exec` disables those fallbacks; image export can still invoke the container runtime CLI. Container operations follow the configured Docker/Podman context.

`report` writes an HTML output file. Image scanning uses temporary files. Bastion does not intentionally patch packages, restart services, quarantine findings or remove inspected files.

A compromised host can conceal or falsify the evidence available to an on-host tool. For offline investigations, use `--sysroot` against an appropriately acquired filesystem; that mode does not inspect live processes or running containers.

## Data and release verification

Reports can include hostnames, local paths, package details and matching snippets. Review them before attaching them to public issues.

The [release workflow](.github/workflows/release.yml) is configured to produce SHA-256 checksums, Sigstore signatures and GitHub build-provenance attestations. This describes the publishing pipeline, not a claim that a release already exists. The [installer](scripts/install.sh) verifies archive checksums and verifies signatures when `cosign` is available; `BASTION_REQUIRE_SIGNATURE=1` makes signature verification mandatory.

Before the first release, the installer repository and signing identity must match the canonical repository, `BastionPHP/Bastion`. Source builds and unsigned development artifacts do not carry release attestations.
