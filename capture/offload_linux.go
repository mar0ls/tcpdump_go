//go:build linux

package capture

import (
	"log"
	"os/exec"
)

var offloadFeatures = []string{
	"rx", "tx", "tso", "gso", "gro", "tx-nocache-copy", "sg", "rxvlan",
}

func DisableOffloading(iface string) {
	if _, err := exec.LookPath("ethtool"); err != nil {
		log.Printf("Warning: ethtool not found (%v)", err)
		return
	}
	args := []string{"-K", iface}
	for _, feat := range offloadFeatures {
		args = append(args, feat, "off")
	}
	cmd := exec.Command("ethtool", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: ethtool -K %s: %v (output: %s)", iface, err, out)
	} else {
		log.Printf("Disabled NIC offloading on %s", iface)
	}
}
