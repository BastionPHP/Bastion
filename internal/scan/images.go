package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/BastionPHP/Bastion/internal/imagefs"
	"github.com/BastionPHP/Bastion/internal/sysroot"
)

// imageRuntime returns the first container CLI on PATH.
func imageRuntime() string {
	for _, rt := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(rt); err == nil {
			return rt
		}
	}
	return ""
}

// listImages returns one reference per local image (by ID), skipping
// dangling ones.
func listImages(ctx context.Context, rt string) ([]string, error) {
	out, err := exec.CommandContext(ctx, rt, "image", "ls", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}").Output()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		id, ref, ok := strings.Cut(line, " ")
		if !ok || seen[id] || strings.Contains(ref, "<none>") {
			continue
		}
		seen[id] = true
		refs = append(refs, ref)
	}
	return refs, nil
}

// imageTarget streams `<rt> save ref` and rebuilds the files a scan needs in
// a temporary directory. Nothing is run from the image.
func imageTarget(ctx context.Context, rt, ref string) (*Target, error) {
	dir, err := os.MkdirTemp("", "bastion-imgroot-")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, rt, "save", ref)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	env, xerr := imagefs.Extract(stdout, dir)
	werr := cmd.Wait()
	if xerr != nil || werr != nil {
		os.RemoveAll(dir)
		if werr != nil {
			return nil, fmt.Errorf("%s save %s: %s", rt, ref, strings.TrimSpace(stderr.String()))
		}
		return nil, xerr
	}
	r := sysroot.Root{Dir: dir}
	t := &Target{Kind: "image", Name: ref, Image: ref, Runtime: rt, OS: r.OSRelease(), Access: "filesystem", root: r, env: env, tmpDir: dir}
	t.db = newDB(r, nil, false)
	return t, nil
}

func imageTargets(ctx context.Context, opt Options, res *Result) []*Target {
	if !opt.AllImages && len(opt.Images) == 0 {
		return nil
	}
	rt := imageRuntime()
	if rt == "" {
		res.Warnings = append(res.Warnings, "images: no docker or podman CLI found")
		return nil
	}
	refs := opt.Images
	if opt.AllImages {
		all, err := listImages(ctx, rt)
		if err != nil {
			res.Warnings = append(res.Warnings, "images: "+err.Error())
		}
		refs = append(refs, all...)
	}
	var out []*Target
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		opt.progress("reading image %s", ref)
		t, err := imageTarget(ctx, rt, ref)
		if err != nil {
			res.Warnings = append(res.Warnings, "image "+ref+": "+err.Error())
			continue
		}
		out = append(out, t)
	}
	return out
}
