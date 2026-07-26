//go:build unix

package main

import "syscall"

func setSecureFileCreationMask() {
	syscall.Umask(0077)
}

// fileModesEnforced reports whether os.Chmod on this platform actually keeps
// other local users out. It does on unix, so hardenDatabaseFilePermissions can
// treat a successful chmod as a real guarantee.
func fileModesEnforced() bool { return true }
