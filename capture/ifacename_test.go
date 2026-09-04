package capture

import "testing"

func TestValidateInterfaceName(t *testing.T) {
	valid := []string{"eth0", "en0", "wlp3s0", "eth0.100", "br-lan", "lo", "veth_a", "eth0:1", "abcdefghijklmno"}
	for _, name := range valid {
		if err := validateInterfaceName(name); err != nil {
			t.Errorf("validateInterfaceName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",                 // empty
		"-K",               // would be read as an ethtool option
		"-eth0",            // same, with a plausible tail
		"abcdefghijklmnop", // 16 bytes, one over IFNAMSIZ-1
		"eth0;reboot",      // shell metacharacter
		"eth0 up",          // argument splitting
		"../../etc/passwd", // path traversal
		"eth0\n-K",         // newline smuggling
		".eth0",            // separator in leading position
	}
	for _, name := range invalid {
		if err := validateInterfaceName(name); err == nil {
			t.Errorf("validateInterfaceName(%q) = nil, want an error", name)
		}
	}
}
