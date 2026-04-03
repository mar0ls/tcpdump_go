//go:build windows

package capture

import (
	"os"
	"syscall"
)

// ShutdownSignals lists the OS signals that trigger a graceful capture shutdown.
var ShutdownSignals = []os.Signal{syscall.SIGINT}
