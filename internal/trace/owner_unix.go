//go:build linux || darwin || freebsd

package trace

import (
	"io/fs"
	"syscall"
	"time"
)

type timeT = time.Time

func ownerUID(fi fs.FileInfo) (int, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}
