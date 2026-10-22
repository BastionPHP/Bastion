package advisory

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed data/*.json
var builtin embed.FS

// DB is a set of advisories.
type DB struct {
	Advisories []*Advisory
}

// Builtin returns the advisories compiled into the binary.
func Builtin() (*DB, error) {
	return loadFS(builtin, "data")
}

// LoadDir merges advisories from dir into db. Files in dir replace built-in
// advisories with the same ID.
func (db *DB) LoadDir(dir string) error {
	extra, err := loadFS(os.DirFS(dir), ".")
	if err != nil {
		return err
	}
	for _, a := range extra.Advisories {
		replaced := false
		for i, b := range db.Advisories {
			if b.ID == a.ID {
				db.Advisories[i] = a
				replaced = true
			}
		}
		if !replaced {
			db.Advisories = append(db.Advisories, a)
		}
	}
	return nil
}

func loadFS(fsys fs.FS, dir string) (*DB, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	db := &DB{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := fs.ReadFile(fsys, filepath.ToSlash(filepath.Join(dir, e.Name())))
		if err != nil {
			return nil, err
		}
		a, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		db.Advisories = append(db.Advisories, a)
	}
	sort.Slice(db.Advisories, func(i, j int) bool { return db.Advisories[i].Published > db.Advisories[j].Published })
	return db, nil
}

// Parse decodes and validates one advisory document.
func Parse(b []byte) (*Advisory, error) {
	var a Advisory
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, err
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Validate checks the invariants the engine relies on.
func (a *Advisory) Validate() error {
	if a.Schema != "bastion.advisory/v1" {
		return fmt.Errorf("unsupported schema %q", a.Schema)
	}
	if a.ID == "" || a.Product == "" {
		return fmt.Errorf("id and product are required")
	}
	if len(a.Branches) == 0 {
		return fmt.Errorf("%s: at least one branch is required", a.ID)
	}
	for _, s := range []string{a.OlderBranches, a.NewerBranches} {
		if s != "affected" && s != "fixed" {
			return fmt.Errorf("%s: older_branches/newer_branches must be affected or fixed", a.ID)
		}
	}
	for _, f := range a.VendorFixes {
		if f.Format != "dpkg" && f.Format != "rpm" && f.Format != "apk" {
			return fmt.Errorf("%s: vendor fix %s/%s: unknown format %q", a.ID, f.Distro, f.Release, f.Format)
		}
		if f.Distro == "" || f.Release == "" || f.Package == "" || f.Fixed == "" {
			return fmt.Errorf("%s: vendor fix missing fields: %+v", a.ID, f)
		}
	}
	return nil
}

// Find returns the advisory with the given ID or alias.
func (db *DB) Find(id string) *Advisory {
	for _, a := range db.Advisories {
		if strings.EqualFold(a.ID, id) || strings.EqualFold(a.Name, id) {
			return a
		}
		for _, al := range a.Aliases {
			if strings.EqualFold(al, id) {
				return a
			}
		}
	}
	return nil
}
