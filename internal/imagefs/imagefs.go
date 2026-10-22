// Package imagefs rebuilds the parts of a container image that Bastion needs
// (PHP binaries, package databases, os-release, PHP changelogs) from an image
// archive such as the output of `docker save`. It never runs the image and
// never writes outside the destination directory.
package imagefs

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// maxFile caps the size of a single extracted file.
const maxFile = 256 << 20

var phpName = regexp.MustCompile(`^(php|php-fpm|php-cgi|lsphp|frankenphp)(-?[0-9][0-9.]*)?$|^libphp[0-9.]*\.so$`)

// Wanted reports whether a regular file at the in-image path rel (no leading
// slash) is needed for a scan.
func Wanted(rel string) bool {
	base := path.Base(rel)
	switch {
	case rel == "etc/os-release", rel == "usr/lib/os-release", rel == "var/lib/dpkg/status", rel == "lib/apk/db/installed":
		return true
	case strings.HasPrefix(rel, "var/lib/dpkg/info/") && strings.HasSuffix(rel, ".list") && strings.Contains(base, "php"):
		return true
	case strings.HasPrefix(rel, "var/lib/rpm/"), strings.HasPrefix(rel, "usr/lib/sysimage/rpm/"):
		return true
	case strings.HasPrefix(rel, "usr/share/doc/") && strings.Contains(rel, "php") && strings.HasPrefix(base, "changelog"):
		return true
	case phpName.MatchString(base):
		return true
	}
	return false
}

// Extract reads an image archive (docker save / podman save, legacy or OCI
// layout) from r and materialises the wanted files of the final filesystem
// under dst. It returns the image's configured environment.
func Extract(r io.Reader, dst string) (map[string]string, error) {
	stage, err := os.MkdirTemp("", "bastion-image-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)

	// docker save does not guarantee that manifest.json comes first, so the
	// archive's members are staged once and then applied in manifest order.
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading image archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := safeRel(h.Name)
		if !ok {
			continue
		}
		p := filepath.Join(stage, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(f, tr)
		f.Close()
		if err != nil {
			return nil, err
		}
	}

	var manifest []struct {
		Config string   `json:"Config"`
		Layers []string `json:"Layers"`
	}
	mb, err := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if err != nil {
		return nil, errors.New("image archive has no manifest.json")
	}
	if err := json.Unmarshal(mb, &manifest); err != nil || len(manifest) == 0 {
		return nil, errors.New("image archive has an unreadable manifest.json")
	}
	env := map[string]string{}
	if c, ok := safeRel(manifest[0].Config); ok {
		var cfg struct {
			Config struct {
				Env []string `json:"Env"`
			} `json:"config"`
		}
		if b, err := os.ReadFile(filepath.Join(stage, c)); err == nil && json.Unmarshal(b, &cfg) == nil {
			for _, e := range cfg.Config.Env {
				if k, v, ok := strings.Cut(e, "="); ok {
					env[k] = v
				}
			}
		}
	}
	for _, l := range manifest[0].Layers {
		rel, ok := safeRel(l)
		if !ok {
			return nil, fmt.Errorf("unsafe layer path %q", l)
		}
		if err := applyLayer(filepath.Join(stage, rel), dst); err != nil {
			return nil, fmt.Errorf("layer %s: %w", l, err)
		}
	}
	return env, nil
}

func applyLayer(file, dst string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel, ok := safeRel(h.Name)
		if !ok {
			continue
		}
		dir, base := path.Split(rel)
		dir = strings.TrimSuffix(dir, "/")
		// Whiteouts delete what lower layers put there.
		if base == ".wh..wh..opq" {
			if target, ok := inside(dst, dir); ok {
				entries, _ := os.ReadDir(target)
				for _, e := range entries {
					os.RemoveAll(filepath.Join(target, e.Name()))
				}
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			if target, ok := inside(dst, path.Join(dir, strings.TrimPrefix(base, ".wh."))); ok {
				os.RemoveAll(target)
			}
			continue
		}
		switch h.Typeflag {
		case tar.TypeSymlink:
			// Links are kept verbatim; sysroot resolves them inside the tree.
			target, ok := inside(dst, rel)
			if !ok {
				continue
			}
			os.RemoveAll(target)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				continue
			}
			os.Symlink(h.Linkname, target)
		case tar.TypeLink:
			src, ok1 := safeRel(h.Linkname)
			target, ok2 := inside(dst, rel)
			if !ok1 || !ok2 || !Wanted(rel) {
				continue
			}
			if from, ok := inside(dst, src); ok {
				os.Remove(target)
				os.MkdirAll(filepath.Dir(target), 0o755)
				os.Link(from, target)
			}
		case tar.TypeReg:
			if !Wanted(rel) || h.Size > maxFile {
				continue
			}
			if err := writeFile(dst, rel, tr, os.FileMode(h.Mode).Perm(), h.ModTime); err != nil {
				return err
			}
		}
	}
}

// writeFile creates dst/rel without following any symlink on the way, so a
// crafted image cannot redirect the write outside dst.
func writeFile(dst, rel string, r io.Reader, mode os.FileMode, mtime interface{ Unix() int64 }) error {
	target, ok := inside(dst, rel)
	if !ok {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil // a parent is a file or link: skip this entry
	}
	os.Remove(target)
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL|noFollow, mode|0o400)
	if err != nil {
		return nil
	}
	_, err = io.Copy(f, io.LimitReader(r, maxFile))
	f.Close()
	return err
}

// inside maps rel into dst and refuses paths whose parent directories
// inside dst are symlinks.
func inside(dst, rel string) (string, bool) {
	rel, ok := safeRel(rel)
	if !ok || rel == "" {
		return "", false
	}
	parts := strings.Split(rel, "/")
	cur := dst
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
	}
	return filepath.Join(dst, filepath.FromSlash(rel)), true
}

// safeRel cleans an archive member name and rejects absolute or escaping paths.
func safeRel(name string) (string, bool) {
	n := path.Clean("/" + strings.TrimPrefix(name, "./"))
	n = strings.TrimPrefix(n, "/")
	if n == "" || n == "." || strings.HasPrefix(n, "../") || strings.Contains(n, "/../") {
		return "", false
	}
	return n, true
}
