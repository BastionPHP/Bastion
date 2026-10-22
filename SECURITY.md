# Security policy

Bastion is a defensive, read-only tool. It contains no exploit code and never
modifies the systems it inspects.

## Reporting a vulnerability in Bastion

Please use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repository). Do not open a public
issue for security problems. We aim to acknowledge reports within 3 working days.

## Wrong verdicts

A build reported as `fixed` that is actually vulnerable is treated as a security
bug — report it privately as above, with the output of `bastion scan --json`
for that instance. Missing or outdated vendor data (a distribution's fixed
package version) can be reported as a normal issue with a link to the vendor's
advisory.

## Verifying releases

Release checksums are signed keylessly with Sigstore from
`.github/workflows/release.yml`, and archives carry a GitHub build provenance
attestation. See the [docs](https://larptard.github.io/bastion/docs/#install).
