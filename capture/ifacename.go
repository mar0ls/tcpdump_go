package capture

import "fmt"

// maxInterfaceNameLen is IFNAMSIZ-1: what the kernel accepts for a device name.
const maxInterfaceNameLen = 15

// validateInterfaceName rejects anything that is not a plausible device name
// before it reaches an external command. Names starting with '-' would be
// parsed as options by ethtool, and the length/charset limits keep shell
// metacharacters and path separators out of the argument list.
func validateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name is empty")
	}
	if len(name) > maxInterfaceNameLen {
		return fmt.Errorf("interface name %q is longer than %d bytes", name, maxInterfaceNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '.' || c == '-' || c == '_' || c == ':') && i > 0:
		default:
			return fmt.Errorf("interface name %q contains an unsupported character %q", name, string(c))
		}
	}
	return nil
}
