//go:build !(linux || darwin || freebsd)

package trace

import (
	"io/fs"
	"time"
)

type timeT = time.Time

func ownerUID(fs.FileInfo) (int, bool) { return 0, false }
