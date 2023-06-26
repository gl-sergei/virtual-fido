//go:build linux && ffs

package main

import "os/exec"

// Execute USB IP attach for Linux
func platformUSBIPExec() *exec.Cmd {
	return exec.Command("cat", "/dev/null")
}
