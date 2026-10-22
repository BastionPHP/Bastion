// Package sysroot reads a filesystem tree that may be the host ("/"), a
// container's root (/proc/<pid>/root) or a mounted image. Paths handed to
// callers are always the paths *inside* the tree; symlinks are resolved
// relative to the tree so an absolute link inside a container never escapes
// to the host.
package sysroot

import (
	"bufio"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Root is a filesystem tree.
type Root struct {
	// Dir is the host directory that holds the tree ("/" for the host).
	Dir string
}

// Host is the running system.
var Host = Root{Dir: "/"}

// Real maps an in-tree path to the host path that can be opened.
func (r Root) Real(p string) string {
	if r.Dir == "/" || r.Dir == "" {
		return path.Clean("/" + p)
	}
	return filepath.Join(r.Dir, path.Clean("/"+p))
}

// Resolve follows symlinks inside the tree and returns the canonical
// in-tree path.
func (r Root) Resolve(p string) (string, error) {
	p = path.Clean("/" + p)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		cur := "/"
		changed := false
		for i, part := range parts {
			next := path.Join(cur, part)
			fi, err := os.Lstat(r.Real(next))
			if err != nil {
				return "", err
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(r.Real(next))
				if err != nil {
					return "", err
				}
				if !path.IsAbs(target) {
					target = path.Join(cur, target)
				}
				p = path.Clean(path.Join(append([]string{target}, parts[i+1:]...)...))
				changed = true
				break
			}
			cur = next
		}
		if !changed {
			return cur, nil
		}
	}
	return "", errors.New("too many levels of symbolic links")
}

// Glob expands a pattern inside the tree and returns in-tree paths.
func (r Root) Glob(pattern string) []string {
	matches, _ := filepath.Glob(r.Real(pattern))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, r.Inner(m))
	}
	return out
}

// Inner converts a host path under the tree back into an in-tree path.
func (r Root) Inner(real string) string {
	if r.Dir == "/" || r.Dir == "" {
		return real
	}
	rel, err := filepath.Rel(r.Dir, real)
	if err != nil {
		return real
	}
	return "/" + filepath.ToSlash(rel)
}

// ReadFile reads an in-tree file.
func (r Root) ReadFile(p string) ([]byte, error) { return os.ReadFile(r.Real(p)) }

// Stat stats an in-tree path, following symlinks inside the tree.
func (r Root) Stat(p string) (os.FileInfo, error) {
	rp, err := r.Resolve(p)
	if err != nil {
		return nil, err
	}
	return os.Stat(r.Real(rp))
}

// OSRelease is the parsed /etc/os-release.
type OSRelease struct {
	ID        string   `json:"id"`
	IDLike    []string `json:"id_like,omitempty"`
	VersionID string   `json:"version_id"`
	Codename  string   `json:"codename,omitempty"`
	Pretty    string   `json:"pretty_name"`
}

// OSRelease reads os-release from the tree. Missing files yield an empty
// value, not an error: plenty of minimal images have none.
func (r Root) OSRelease() OSRelease {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := r.ReadFile(p)
		if err != nil {
			continue
		}
		return ParseOSRelease(string(b))
	}
	return OSRelease{}
}

// ParseOSRelease parses the os-release key=value format.
func ParseOSRelease(s string) OSRelease {
	var o OSRelease
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.ID = strings.ToLower(v)
		case "ID_LIKE":
			o.IDLike = strings.Fields(strings.ToLower(v))
		case "VERSION_ID":
			o.VersionID = v
		case "VERSION_CODENAME":
			o.Codename = v
		case "PRETTY_NAME":
			o.Pretty = v
		}
	}
	return o
}
