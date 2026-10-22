//go:build !linux && !darwin

package trace

import (
	"io/fs"
	"time"
)

func ctime(fs.FileInfo) time.Time { return time.Time{} }
