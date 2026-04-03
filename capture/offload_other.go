//go:build !linux

package capture

import "log"

func DisableOffloading(iface string) {
	log.Printf("Warning: -disable-offload supported only on Linux (ignoring for %s)", iface)
}
