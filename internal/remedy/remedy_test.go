package remedy

import (
	"strings"
	"testing"

	"github.com/larptard/bastion/internal/advisory"
)

func TestSteps(t *testing.T) {
	db, _ := advisory.Builtin()
	a := db.Advisories[0]
	vuln := advisory.Assessment{Status: advisory.Vulnerable}
	cases := []struct {
		in   Input
		want string
	}{
		{Input{Environment: "System package (apt)", Version: "8.3.6", SAPI: "fpm", Package: &advisory.Package{Name: "php8.3-fpm", Source: "php8.3"}}, "apt install --only-upgrade 'php8.3*'"},
		{Input{Environment: "Docker official image", Version: "8.3.35", SAPI: "fpm", Image: "php:8.3.35-fpm-alpine"}, "docker pull php:8.3-fpm-alpine"},
		{Input{Environment: "BaoTa / aaPanel", Version: "7.4.33", SAPI: "fpm"}, "PHP 8.2+"},
		{Input{Environment: "cPanel EasyApache 4", Version: "8.2.34", SAPI: "fpm"}, "ea-php82"},
		{Input{Environment: "Source build", Version: "8.3.35", SAPI: "cli"}, "php-8.3.36"},
		{Input{Environment: "Source build", Version: "8.1.34", SAPI: "cli"}, "PHP-8.1-CVE-2026-109618-109619"},
		{Input{Environment: "Source build", Version: "7.2.34", SAPI: "cli"}, "No fix exists"},
		{Input{Environment: "System package (apt)", Version: "8.3.6", Stale: true}, "Restart"},
	}
	for _, c := range cases {
		c.in.Assessment, c.in.Advisory = vuln, a
		got := strings.Join(Steps(c.in), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%+v:\n%s\nwant %q", c.in.Environment, got, c.want)
		}
	}
	if Steps(Input{Assessment: advisory.Assessment{Status: advisory.Fixed}}) != nil {
		t.Error("fixed needs no steps")
	}
}
