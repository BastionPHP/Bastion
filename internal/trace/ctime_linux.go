package trace

import (
	"io/fs"
	"syscall"
	"time"
)

func ctime(fi fs.FileInfo) time.Time {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
	}
	return time.Time{}
}
