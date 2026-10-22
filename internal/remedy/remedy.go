// Package remedy turns an assessment into concrete next steps for the
// environment the PHP build came from. It only produces text; Bastion never
// runs these commands itself.
package remedy

import (
	"fmt"
	"strings"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/version"
)

// Input is the subset of an instance remedy needs.
type Input struct {
	Environment string
	SAPI        string
	Version     string
	Package     *advisory.Package
	Stale       bool
	TargetKind  string
	Image       string
	Assessment  advisory.Assessment
	Advisory    *advisory.Advisory
}

// Steps returns ordered remediation steps, or nil when nothing is needed.
func Steps(in Input) []string {
	st := in.Assessment.Status
	if st == advisory.Fixed && !in.Stale {
		return nil
	}
	var steps []string
	branch := ""
	if v, err := version.ParsePHP(in.Version); err == nil {
		branch = v.Branch()
	}
	fixedRelease := ""
	if in.Advisory != nil {
		for _, b := range in.Advisory.Branches {
			if b.Branch == branch {
				fixedRelease = b.Fixed
			}
		}
	}
	noUpstreamFix := fixedRelease == "" && in.Assessment.VendorFix == nil

	if in.Stale {
		steps = append(steps, "Restart the service that runs this process (e.g. systemctl restart php"+branch+"-fpm / apache2 / httpd / lsws); the code on disk is newer than the code in memory.")
		if st == advisory.Fixed {
			return steps
		}
	}

	pkg := ""
	if in.Package != nil {
		pkg = in.Package.Source
		if pkg == "" {
			pkg = in.Package.Name
		}
	}
	env := in.Environment
	switch {
	case strings.HasPrefix(env, "System package (apt)"), strings.HasPrefix(env, "Sury"):
		vf := in.Assessment.VendorFix
		if vf != nil && strings.Contains(vf.Channel, "Pro") {
			steps = append(steps, fmt.Sprintf("The fix (%s) ships through %s: attach the machine with `sudo pro attach <token>` and enable esm-infra/esm-apps.", vf.Fixed, vf.Channel))
		}
		steps = append(steps, fmt.Sprintf("sudo apt update && sudo apt install --only-upgrade '%s*'", pkgGlob(pkg, "php"+branch)))
		if vf != nil {
			steps = append(steps, fmt.Sprintf("Confirm: dpkg-query -W %s  → expect %s or later.", in.Package.Name, vf.Fixed))
		} else if noUpstreamFix {
			steps = append(steps, "PHP "+branch+" gets no upstream release. If your vendor has not published a backport, migrate to PHP 8.2+.")
		}
	case strings.HasPrefix(env, "System package (dnf/yum)"), strings.HasPrefix(env, "Remi"):
		steps = append(steps, fmt.Sprintf("sudo dnf upgrade --refresh '%s*'   (yum on older releases)", pkgGlob(pkg, "php")))
		steps = append(steps, "Confirm with: rpm -q --changelog "+orDefault(in.Package, "php")+" | grep -E 'CVE-2026-10961[89]'")
	case strings.HasPrefix(env, "System package (apk)"):
		steps = append(steps, fmt.Sprintf("apk update && apk upgrade %s", pkgGlob(pkg, "php")))
	case env == "Docker official image":
		tag := branch
		if noUpstreamFix {
			tag = "8.4"
		}
		img := "php:" + tag + "-<variant>"
		if variant := imageVariant(in.Image); variant != "" {
			img = "php:" + tag + "-" + variant
		}
		steps = append(steps, fmt.Sprintf("Rebuild on a patched base image: docker pull %s (needs %s or later), then rebuild and redeploy. Running containers keep the old binary until they are replaced.", img, orStr(fixedRelease, "8.4.27")))
	case env == "BaoTa / aaPanel":
		steps = append(steps, "宝塔/aaPanel: App Store → PHP-"+branch+" → Update (or reinstall the newest build). Then restart PHP from the panel.")
		if noUpstreamFix {
			steps = append(steps, "PHP "+branch+" has no upstream fix; switch the site to PHP 8.2+ in Website → PHP version.")
		}
	case env == "cPanel EasyApache 4":
		steps = append(steps, fmt.Sprintf("sudo dnf upgrade 'ea-php%s*'   (or yum; WHM » EasyApache 4 shows the same packages)", strings.ReplaceAll(branch, ".", "")))
	case env == "CloudLinux alt-php":
		steps = append(steps, fmt.Sprintf("sudo yum update 'alt-php%s*'   (CloudLinux ships backports for end-of-life alt-php versions)", strings.ReplaceAll(branch, ".", "")))
	case env == "Plesk":
		steps = append(steps, "Plesk: Tools & Settings → Updates → update the PHP "+branch+" component, or run `plesk installer --select-release-current --upgrade-installed-components`.")
	case env == "LiteSpeed":
		steps = append(steps, fmt.Sprintf("Upgrade the lsphp%s packages from the LiteSpeed repository (apt/dnf), then restart lsws.", strings.ReplaceAll(branch, ".", "")))
	case env == "Homebrew":
		steps = append(steps, "brew update && brew upgrade php")
	default:
		if fixedRelease != "" {
			steps = append(steps, fmt.Sprintf("Rebuild from php-%s or later (https://www.php.net/downloads).", fixedRelease))
		} else if in.Advisory != nil {
			for _, b := range in.Advisory.Branches {
				if b.Branch == branch && b.SourceBackport != "" {
					steps = append(steps, "Upgrade to PHP 8.2+; if you must stay on "+branch+", rebuild from the official source backport "+b.SourceBackport+".")
				}
			}
			if len(steps) == 0 || (in.Stale && len(steps) == 1) {
				steps = append(steps, "No fix exists for PHP "+branch+" upstream. Upgrade to PHP 8.2+ or use a vendor that backports security fixes.")
			}
		}
	}
	if !in.Stale && in.SAPI != "cli" && env != "Docker official image" {
		steps = append(steps, "Restart every worker after upgrading (php-fpm, Apache, LiteSpeed); running processes keep the old code.")
	}
	if st == advisory.Unknown {
		steps = append([]string{"Bastion could not verify this build. Ask the vendor whether CVE-2026-109618/109619 are fixed in the installed package."}, steps...)
	}
	return steps
}

func pkgGlob(pkg, fallback string) string {
	if pkg == "" {
		return fallback
	}
	return pkg
}

func orDefault(p *advisory.Package, d string) string {
	if p == nil {
		return d
	}
	return p.Name
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// imageVariant extracts the variant from an official image reference:
// "php:8.3.35-fpm-alpine" → "fpm-alpine", "php:8.1-apache" → "apache".
func imageVariant(image string) string {
	_, tag, ok := strings.Cut(image, ":")
	if !ok {
		return ""
	}
	parts := strings.SplitN(tag, "-", 2)
	if len(parts) != 2 || parts[0] == "" || parts[0][0] < '0' || parts[0][0] > '9' {
		return ""
	}
	return parts[1]
}
