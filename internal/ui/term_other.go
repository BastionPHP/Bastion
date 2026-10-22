//go:build !(linux || darwin || freebsd)

package ui

import "os"

func termWidth(*os.File) int { return 0 }
