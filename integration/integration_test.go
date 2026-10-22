//go:build integration

// Integration tests run the real bastion binary against real PHP container
// images. They need Docker and root (or passwordless sudo) because container
// filesystems are read through /proc/<pid>/root.
//
//	go test -tags integration -v ./integration/
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var bin string

type instance struct {
	Target      string `json:"target"`
	TargetKind  string `json:"target_kind"`
	Path        string `json:"path"`
	SAPI        string `json:"sapi"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
	Stale       bool   `json:"stale"`
	PIDs        []int  `json:"pids"`
	Package     *struct {
		Manager, Name, Version string
	} `json:"package"`
	Assessments []struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"assessments"`
}

type scanResult struct {
	Instances []instance `json:"instances"`
	Targets   []struct {
		Kind, Name, Access string
	} `json:"targets"`
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bastion-it")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "bastion")
	out, err := exec.Command("go", "build", "-o", bin, "../cmd/bastion").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// start runs a container and waits until ready succeeds inside it.
func start(t *testing.T, name, image, script, ready string) {
	t.Helper()
	exec.Command("docker", "rm", "-f", name).Run()
	docker(t, "run", "-d", "--name", name, image, "sh", "-c", script)
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		if exec.Command("docker", "exec", name, "sh", "-c", ready).Run() == nil {
			return
		}
		if st, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output(); strings.TrimSpace(string(st)) != "true" {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput()
			t.Fatalf("%s exited during setup:\n%s", name, logs)
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s not ready after setup", name)
}

func scan(t *testing.T, asRoot bool, extra ...string) scanResult {
	t.Helper()
	args := append([]string{"scan", "--json", "-q"}, extra...)
	var cmd *exec.Cmd
	if asRoot && os.Geteuid() != 0 {
		cmd = exec.Command("sudo", append([]string{"-n", bin}, args...)...)
	} else {
		cmd = exec.Command(bin, args...)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); err != nil && (!ok || ee.ExitCode() > 2) {
		t.Fatalf("scan failed: %v\n%s", err, stderr.String())
	}
	var r scanResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out)
	}
	return r
}

func find(r scanResult, target, path string) *instance {
	for i := range r.Instances {
		if r.Instances[i].Target == target && r.Instances[i].Path == path {
			return &r.Instances[i]
		}
	}
	return nil
}

func dump(t *testing.T, r scanResult, target string) {
	for _, i := range r.Instances {
		if i.Target == target {
			t.Logf("  %s %s %s %s %+v", i.Path, i.Version, i.Environment, i.Assessments[0].Status, i.Package)
		}
	}
}

type want struct {
	path, status, env, sapi string
	pkgManager              string
	running                 bool
}

func check(t *testing.T, r scanResult, target string, ws ...want) {
	t.Helper()
	for _, w := range ws {
		i := find(r, target, w.path)
		if i == nil {
			dump(t, r, target)
			t.Errorf("%s: %s not found", target, w.path)
			continue
		}
		if got := i.Assessments[0].Status; got != w.status {
			t.Errorf("%s %s: status %s (%s), want %s", target, w.path, got, i.Assessments[0].Reason, w.status)
		}
		if w.env != "" && i.Environment != w.env {
			t.Errorf("%s %s: environment %q, want %q", target, w.path, i.Environment, w.env)
		}
		if w.sapi != "" && i.SAPI != w.sapi {
			t.Errorf("%s %s: sapi %q, want %q", target, w.path, i.SAPI, w.sapi)
		}
		if w.pkgManager != "" && (i.Package == nil || i.Package.Manager != w.pkgManager) {
			t.Errorf("%s %s: package %+v, want manager %s", target, w.path, i.Package, w.pkgManager)
		}
		if w.running && len(i.PIDs) == 0 {
			t.Errorf("%s %s: expected running pids", target, w.path)
		}
	}
}

const sleep = "sleep 3600"

func TestOfficialImages(t *testing.T) {
	start(t, "bx-it-old", "php:8.3.35-fpm", "exec php-fpm", "cat /proc/[0-9]*/comm | grep -q php-fpm")
	start(t, "bx-it-new", "php:8.4-cli", sleep, "true")
	start(t, "bx-it-eol", "php:7.4-cli", sleep, "true")
	start(t, "bx-it-apache", "php:8.3-apache", "exec apache2-foreground", "cat /proc/[0-9]*/comm | grep -q apache2")
	r := scan(t, true)
	check(t, r, "bx-it-old",
		want{path: "/usr/local/sbin/php-fpm", status: "vulnerable", env: "Docker official image", sapi: "fpm", running: true},
		want{path: "/usr/local/bin/php", status: "vulnerable"})
	check(t, r, "bx-it-new", want{path: "/usr/local/bin/php", status: "fixed", env: "Docker official image"})
	check(t, r, "bx-it-eol", want{path: "/usr/local/bin/php", status: "likely-vulnerable"})
	// mod_php is found both on disk and through Apache's memory maps.
	var mod *instance
	for i := range r.Instances {
		in := &r.Instances[i]
		if in.Target == "bx-it-apache" && in.SAPI == "apache2handler" {
			mod = in
		}
	}
	if mod == nil || mod.Assessments[0].Status != "fixed" || len(mod.PIDs) == 0 {
		dump(t, r, "bx-it-apache")
		t.Errorf("mod_php in php:8.3-apache: %+v", mod)
	}
}

func TestUbuntuVendorBackport(t *testing.T) {
	// The current noble-security package is the vendor fix (8.3.6-0ubuntu0.24.04.13 or later)
	// while PHP_VERSION still says 8.3.6.
	start(t, "bx-it-noble", "ubuntu:24.04",
		"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends php8.3-cli >/dev/null && touch /ready && "+sleep,
		"test -f /ready")
	r := scan(t, true)
	check(t, r, "bx-it-noble", want{path: "/usr/bin/php8.3", status: "fixed", env: "System package (apt)", pkgManager: "dpkg"})
	if i := find(r, "bx-it-noble", "/usr/bin/php8.3"); i != nil && !strings.HasPrefix(i.Version, "8.3.6") {
		t.Errorf("expected upstream 8.3.6, got %s", i.Version)
	}
}

func TestDebianBookworm(t *testing.T) {
	// Without the security suite bookworm installs 8.2.32 (vulnerable); with it,
	// 8.2.35-1~deb12u1 (fixed per DLA-4848-1).
	noSec := `printf 'Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' > /etc/apt/sources.list.d/debian.sources && `
	install := "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends php8.2-cli >/dev/null && touch /ready && " + sleep
	start(t, "bx-it-bookworm-main", "debian:bookworm", noSec+install, "test -f /ready")
	start(t, "bx-it-bookworm-sec", "debian:bookworm", install, "test -f /ready")
	r := scan(t, true)
	check(t, r, "bx-it-bookworm-main", want{path: "/usr/bin/php8.2", status: "vulnerable", pkgManager: "dpkg"})
	check(t, r, "bx-it-bookworm-sec", want{path: "/usr/bin/php8.2", status: "fixed", pkgManager: "dpkg"})
}

func TestAlpinePackage(t *testing.T) {
	start(t, "bx-it-alpine", "alpine:3.20", "sed -i 's#^https://#http://#' /etc/apk/repositories && apk add --no-cache php83 >/dev/null && touch /ready && "+sleep, "test -f /ready")
	r := scan(t, true)
	i := find(r, "bx-it-alpine", "/usr/bin/php83")
	if i == nil || i.Package == nil || i.Package.Manager != "apk" {
		dump(t, r, "bx-it-alpine")
		t.Fatalf("alpine php83 not attributed to apk: %+v", i)
	}
	// Alpine ships no changelogs; anything below 8.3.36 must not be called fixed.
	if strings.HasPrefix(i.Version, "8.3.") && i.Assessments[0].Status == "fixed" && i.Version < "8.3.36" {
		t.Errorf("alpine %s reported fixed", i.Version)
	}
}

func TestReplacedBinaryStillRunning(t *testing.T) {
	// Copy the old (vulnerable) CLI, start it, then delete it: the process
	// keeps running code that no longer exists on disk.
	start(t, "bx-it-stale", "php:8.3.35-cli",
		`cp /usr/local/bin/php /usr/local/bin/php83 && (/usr/local/bin/php83 -r 'sleep(3600);' &) && sleep 1 && rm /usr/local/bin/php83 && touch /ready && `+sleep,
		"test -f /ready")
	r := scan(t, true)
	var stale *instance
	for i := range r.Instances {
		if r.Instances[i].Target == "bx-it-stale" && r.Instances[i].Stale {
			stale = &r.Instances[i]
		}
	}
	if stale == nil || stale.Version != "8.3.35" || stale.Assessments[0].Status != "vulnerable" || len(stale.PIDs) == 0 {
		dump(t, r, "bx-it-stale")
		t.Fatalf("replaced binary not detected: %+v", stale)
	}
}

func TestExecFallbackWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this case covers the unprivileged path; run the suite as a normal user with docker access")
	}
	start(t, "bx-it-exec", "php:8.3.35-cli", sleep, "true")
	r := scan(t, false)
	check(t, r, "bx-it-exec", want{path: "php (container PATH)", status: "vulnerable"})
}

func TestNoExecReadsStatically(t *testing.T) {
	start(t, "bx-it-static", "php:8.4-cli", sleep, "true")
	r := scan(t, true, "--no-exec")
	check(t, r, "bx-it-static", want{path: "/usr/local/bin/php", status: "fixed"})
}

func TestTraceLab(t *testing.T) {
	lab := t.TempDir()
	if out, err := exec.Command("bash", "../scripts/demo/lab.sh", lab).CombinedOutput(); err != nil {
		t.Fatalf("lab: %v\n%s", err, out)
	}
	out, _ := exec.Command(bin, "trace", "--sysroot", lab, "--since", "87600h", "--json", "-q").Output()
	var r struct {
		Verdict  string `json:"verdict"`
		Findings []struct{ Rule, Severity string }
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "compromised" {
		t.Fatalf("verdict %s", r.Verdict)
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.Rule] = true
	}
	for _, rule := range []string{"log.flagged-file-access", "persist.cron", "config.auto-prepend", "php.eval-decoded", "log.early-oom", "log.worker-crash"} {
		if !seen[rule] {
			t.Errorf("missing %s", rule)
		}
	}
}

func TestImagesAreScannedWithoutRunning(t *testing.T) {
	r := scan(t, false, "--no-containers", "--image", "php:8.3.35-cli", "--image", "php:8.4-cli")
	got := map[string]string{}
	for _, i := range r.Instances {
		if i.TargetKind == "image" && i.Path == "/usr/local/bin/php" {
			got[i.Target] = i.Assessments[0].Status
		}
	}
	if got["php:8.3.35-cli"] != "vulnerable" || got["php:8.4-cli"] != "fixed" {
		t.Fatalf("image verdicts %v", got)
	}
	// Reading an image must not create containers.
	if out, _ := exec.Command("docker", "ps", "-a", "--filter", "ancestor=php:8.3.35-cli", "-q").Output(); len(bytes.TrimSpace(out)) != 0 {
		t.Fatalf("image scan created containers: %s", out)
	}
}
