package discover

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Process is a running process that executes PHP, either as its own binary
// (php-fpm, php-cgi, lsphp, frankenphp) or through a loaded libphp (mod_php).
type Process struct {
	PID     int
	Comm    string
	Exe     string // in-namespace path of the executable
	Deleted bool   // the executable was replaced or removed on disk
	// Libs lists in-namespace paths of loaded libphp modules, with
	// LibDeleted marking modules replaced on disk.
	Libs       []string
	LibDeleted map[string]bool
	// RootKey identifies the process's filesystem root (device:inode of
	// /proc/<pid>/root); processes of one container share it.
	RootKey string
	Cgroup  string
}

// HostRootKey returns the root key of the host.
func HostRootKey() string { return rootKey("/") }

func rootKey(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10)
}

// RootKeyOf returns the root key of a process.
func RootKeyOf(pid int) string { return rootKey("/proc/" + strconv.Itoa(pid) + "/root/") }

var webServers = map[string]bool{"httpd": true, "apache2": true, "apache": true, "httpd-prefork": true, "httpd.worker": true, "lshttpd": true, "litespeed": true}

// Processes lists PHP processes from /proc. Unreadable processes (another
// user's, without root) are skipped; the caller reports that limitation.
func Processes(proc string) ([]Process, int) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, 0
	}
	var out []Process
	denied := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		base := filepath.Join(proc, e.Name())
		exe, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		deleted := strings.HasSuffix(exe, " (deleted)")
		exe = strings.TrimSuffix(exe, " (deleted)")
		name := path.Base(exe)
		p := Process{PID: pid, Exe: exe, Deleted: deleted, Comm: readComm(base)}
		switch {
		case LooksLikePHP(name):
		case webServers[name] || webServers[p.Comm]:
			p.Libs, p.LibDeleted = phpLibs(filepath.Join(base, "maps"))
			if len(p.Libs) == 0 {
				continue
			}
		default:
			continue
		}
		p.RootKey = RootKeyOf(pid)
		p.Cgroup = readCgroup(base)
		out = append(out, p)
	}
	return out, denied
}

func readComm(base string) string {
	b, _ := os.ReadFile(filepath.Join(base, "comm"))
	return strings.TrimSpace(string(b))
}

func readCgroup(base string) string {
	b, _ := os.ReadFile(filepath.Join(base, "cgroup"))
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.LastIndexByte(line, ':'); i >= 0 && len(line) > i+1 {
			return line[i+1:]
		}
	}
	return ""
}

func phpLibs(maps string) ([]string, map[string]bool) {
	f, err := os.Open(maps)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	seen := map[string]bool{}
	deleted := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		p := strings.Join(fields[5:], " ")
		del := strings.HasSuffix(p, " (deleted)")
		p = strings.TrimSuffix(p, " (deleted)")
		b := path.Base(p)
		if !(strings.HasPrefix(b, "libphp") || strings.HasPrefix(b, "mod_php")) || seen[p] {
			continue
		}
		seen[p] = true
		if del {
			deleted[p] = true
		}
		out = append(out, p)
	}
	return out, deleted
}

// ContainerHint extracts a container ID from a cgroup path, if any.
func ContainerHint(cgroup string) string {
	for _, part := range strings.Split(cgroup, "/") {
		part = strings.TrimSuffix(part, ".scope")
		for _, pre := range []string{"docker-", "libpod-", "cri-containerd-", "crio-"} {
			part = strings.TrimPrefix(part, pre)
		}
		if len(part) == 64 && isHex(part) {
			return part
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
