//go:build !unix

package main

// There is no umask outside unix, so this is intentionally a no-op.
func setSecureFileCreationMask() {}

// fileModesEnforced reports whether os.Chmod on this platform actually keeps
// other local users out. On Windows it does not: os.Chmod only toggles
// FILE_ATTRIBUTE_READONLY and cannot express an owner-only DACL, so chmod(0600)
// clears the read-only flag and otherwise changes nothing while still returning
// nil. Callers must not treat a successful chmod here as a guarantee.
func fileModesEnforced() bool { return false }
