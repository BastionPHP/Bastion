//go:build linux || darwin || freebsd

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

type winsize struct{ Row, Col, X, Y uint16 }

func termWidth(f *os.File) int {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tiocgwinsz), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
