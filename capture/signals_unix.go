//go:build !windows

package capture

import (
	"os"
	"syscall"
)

// ShutdownSignals lists the OS signals that trigger a graceful capture shutdown.
// SIGHUP is here because an unhandled one skips the deferred offload restore.
// SIGQUIT is left out so it still dumps goroutines.
var ShutdownSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
