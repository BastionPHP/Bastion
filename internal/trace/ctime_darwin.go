package trace

import (
	"io/fs"
	"syscall"
	"time"
)

func ctime(fi fs.FileInfo) time.Time {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec))
	}
	return time.Time{}
}
