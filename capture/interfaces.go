package capture

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/pcap"
)

// libpcap interface flags from pcap.h. gopacket surfaces the bits in
// pcap.Interface.Flags but does not name them.
const (
	ifLoopback            uint32 = 0x00000001
	ifUp                  uint32 = 0x00000002
	ifRunning             uint32 = 0x00000004
	ifWireless            uint32 = 0x00000008
	ifStatusMask          uint32 = 0x00000030
	ifStatusConnected     uint32 = 0x00000010
	ifStatusDisconnected  uint32 = 0x00000020
	ifStatusNotApplicable uint32 = 0x00000030
)

// interfaceFlagNames reproduces the bracketed list tcpdump -D prints, down to
// the wireless-specific wording for connection status.
func interfaceFlagNames(flags uint32) string {
	names := make([]string, 0, 4)
	if flags&ifUp != 0 {
		names = append(names, "Up")
	}
	if flags&ifRunning != 0 {
		names = append(names, "Running")
	}
	if flags&ifLoopback != 0 {
		names = append(names, "Loopback")
	}
	wireless := flags&ifWireless != 0
	if wireless {
		names = append(names, "Wireless")
	}
	switch flags & ifStatusMask {
	case ifStatusConnected:
		if wireless {
			names = append(names, "Associated")
		} else {
			names = append(names, "Connected")
		}
	case ifStatusDisconnected:
		if wireless {
			names = append(names, "Not associated")
		} else {
			names = append(names, "Disconnected")
		}
	case ifStatusNotApplicable:
	default:
		names = append(names, "Connection status unknown")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// ResolveInterface maps a -i value to a device name. tcpdump accepts the index
// printed by -D, so "2" selects the second device in that same listing.
func ResolveInterface(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	index, err := strconv.Atoi(value)
	if err != nil {
		return value, nil // an ordinary device name
	}
	if index < 1 {
		return "", fmt.Errorf("interface number %d is out of range: numbering starts at 1", index)
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}
	if index > len(devices) {
		return "", fmt.Errorf("interface number %d is out of range: only %d interfaces are available", index, len(devices))
	}
	return devices[index-1].Name, nil
}
