//go:build linux || darwin || freebsd

package imagefs

import "syscall"

const noFollow = syscall.O_NOFOLLOW
