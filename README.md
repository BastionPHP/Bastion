<div align="center">

# Bastion

**Is your PHP still exposed? Has someone already got in?**

Open-source, local, **read-only** PHP security tool. Finds every PHP build on a server —
distro packages, BaoTa, cPanel, containers — tells you which ones are *really* patched
against **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), and traces what an intruder left behind.

[Website](https://larptard.github.io/bastion/) ·
[Online check](https://larptard.github.io/bastion/check/) ·
[How it works](https://larptard.github.io/bastion/how-it-works/) ·
[Docs](https://larptard.github.io/bastion/docs/)

[![ci](https://github.com/larptard/bastion/actions/workflows/ci.yml/badge.svg)](https://github.com/larptard/bastion/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<img src="docs/assets/scan.png" alt="bastion scan: real output on an Ubuntu 24.04 host with four PHP containers" width="860">

<sub>Real output of <code>bastion scan</code> on an Ubuntu 24.04 host running four official PHP containers, recorded with <code>scripts/demo/record.sh</code>.</sub>

</div>

## Why

On **21 October 2026** PHP shipped emergency releases (**8.5.12, 8.4.27, 8.3.36, 8.2.35**) for two
engine bugs rated **CVSS v4 9.2**: unauthenticated remote code execution, demonstrated against
Apache mod_php before any application code runs. PHP ≤ 8.1 gets no release at all — only
source backport branches.

Knowing whether *your* server is safe is harder than it sounds:

- **Version numbers lie.** Ubuntu 24.04's fixed PHP still reports `8.3.6` (upstream fix: 8.3.36).
  Distributions backport fixes without changing the version — a version-only check gets it wrong
  in both directions.
- **There is more than one PHP.** System package, two panel versions, a container built last month.
- **Patched files ≠ patched processes.** php-fpm and Apache keep running the old code until restarted.
- **A patch doesn't evict an attacker** who got in first.

## Install

```sh
curl -fsSL https://larptard.github.io/bastion/install.sh | sh
```

Linux & macOS, amd64 & arm64. The script verifies the SHA-256 checksum and, when `cosign` is
installed, the Sigstore signature of the release (`BASTION_REQUIRE_SIGNATURE=1` makes that
mandatory). Prefer to read it first? It's [scripts/install.sh](scripts/install.sh).
Other options: [manual download + verify](https://larptard.github.io/bastion/docs/#install),
`go install github.com/larptard/bastion/cmd/bastion@latest`, or `make build`.

## Use

```sh
sudo bastion scan                 # every PHP build, and whether it is really fixed
sudo bastion scan --images        # also every local container image (read, never run)
sudo bastion trace                # webshells, persistence, log traces + timeline
sudo bastion report               # both, as one self-contained offline HTML file
sudo bastion scan --format sarif  # for GitHub code scanning and security dashboards
php -v | bastion check            # assess pasted output (same engine as the website)
```

| | |
|---|---|
| **`scan`** finds PHP in distro paths, BaoTa/aaPanel, cPanel EA4, CloudLinux, Plesk, Remi, LiteSpeed, Homebrew, source builds, running processes (php-fpm, mod_php, lsphp, FrankenPHP), **Docker/Podman containers, Kubernetes pods and container images**, and processes still running a **replaced binary**. For builds that are not fixed it audits the **interim mitigations** in php.ini and PHP-FPM pools. | **`trace`** checks web roots (found from nginx/Apache/LiteSpeed/Caddy config) for webshell signatures, PHP in uploads/images, `.user.ini`/`.htaccess` tricks; cron, systemd, `ld.so.preload`, SSH keys, UID 0; and logs: requests to flagged files, worker segfaults, start-up OOM. |
| <img src="docs/assets/trace.png" alt="bastion trace output" width="420"> | <img src="docs/assets/report.png" alt="HTML report" width="420"> |

Exit codes make it scriptable: `0` clean · `1` vulnerable/compromised · `2` unknown/suspicious.
`--format json` gives versioned output (`bastion.scan/v1`, `bastion.trace/v1`); `--format sarif` gives SARIF 2.1.0.
[Sample report →](https://larptard.github.io/bastion/demo/report.html)

## How it decides

For each binary Bastion reads the version **without executing it** (every PHP SAPI embeds
`X-Powered-By: PHP/<version>`), then goes down a ladder and stops at the first proof:

1. **Upstream version** ≥ the branch's fixed release → fixed.
2. **Vendor fix table** — exact fixed package versions from the Ubuntu, Debian and Red Hat (RHEL 8/9/10) trackers, compared with dpkg's or rpm's ordering.
3. **Dated vendor rebuilds** — Plesk's 7.4/8.0/8.1 rebuilds keep their version; the compile date read from the binary decides.
4. **Package changelog** names CVE-2026-109618/109619 (`changelog.Debian.gz`, `rpm -q --changelog`).
5. **Fix fingerprint** — code only the patch adds (the new hard memory-limit message) is in the binary.
6. Otherwise: *likely vulnerable* if evidence was expected but absent (for example Alpine, whose secdb records no stable-branch backport), or **unknown**, never a guess.

The same engine runs in the browser on the [online check](https://larptard.github.io/bastion/check/);
Go and JS are tested against one shared set of vectors ([testdata/](testdata/)).
Vulnerabilities are **data**: [`internal/advisory/data/*.json`](internal/advisory/data/) — the next
PHP bug is a JSON file (or `--db <dir>` at run time), not new code.
Full explanation with annotated source: [How it works](https://larptard.github.io/bastion/how-it-works/).

## Principles

- **Read-only.** Never writes, restarts, quarantines or deletes. Fixes are printed, not run. `--no-exec` disables even `php -v`/`docker exec`.
- **Local.** No telemetry, no network calls, no account.
- **Honest.** Every verdict shows its evidence; what can't be proven is `unknown`.
- **Tested on real things.** Integration tests run against real PHP images (official, Ubuntu, Debian, Alpine, mod_php); trace signatures are checked in CI against WordPress, Drupal, Laravel and phpseclib for false positives.

## Roadmap

| Module | | Status |
|---|---|---|
| **Sense** · perception | inventory, exposure, image scanning, mitigation audit (`scan`, `check`, `report`) | ✅ available |
| **Trace** · intrusion forensics | indicators + timeline (`trace`) | ✅ available |
| **Forge** · patch forging | reproducible patched packages for EOL PHP from official backport branches | 🗺 roadmap |
| **Shift** · safe migration | compatibility checks and rehearsed upgrades to supported branches | 🗺 roadmap |
| **Guard** · runtime protection | detect exploitation attempts as they happen | 🗺 roadmap |

## Develop

```sh
make test          # go vet, go test -race, JS engine parity tests
make integration   # real PHP images; needs Docker + root/sudo
make site-serve    # website on http://localhost:4321/bastion/
make demo          # re-record terminal demos and the sample report
```

Layout: `cmd/bastion` CLI · `internal/advisory` data + decision engine · `internal/discover`
finding PHP · `internal/pkgdb` dpkg/rpm/apk · `internal/scan` · `internal/trace` (+ `rules/`) ·
`internal/imagefs` image extraction · `internal/phpini` config reading · `internal/sarif` ·
`internal/report` · `design/` shared CSS and icons (Lucide, ISC) · `site/` website (zero-dependency Node build).

Security issues: see [SECURITY.md](SECURITY.md). License: [MIT](LICENSE).
