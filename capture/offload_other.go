//go:build !linux

package capture

import (
	"fmt"
	"runtime"
)

// DisableOffloading is explicit on unsupported systems: silently accepting
// the option would promise a wire-faithful capture while leaving offloads on.
func DisableOffloading(iface string) (func() error, error) {
	return nil, fmt.Errorf("disable-offload is not supported on %s (interface %q)", runtime.GOOS, iface)
}
