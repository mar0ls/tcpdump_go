//go:build windows

package capture

import "fmt"

// DropPrivileges is explicit on Windows: silently ignoring -Z would promise a
// hardened capture while leaving the process fully privileged.
func DropPrivileges(username string) error {
	if username == "" {
		return nil
	}
	return fmt.Errorf("-Z is not supported on windows (user %q)", username)
}
