//go:build !linux

package capture

import "log"

// DisableOffloading is a no-op on non-Linux platforms; logs a warning.
func DisableOffloading(iface string) {
	log.Printf("Warning: -disable-offload supported only on Linux (ignoring for %s)", iface)
}
