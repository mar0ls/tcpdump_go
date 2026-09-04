//go:build linux

package capture

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ethtoolFeature maps the stable feature name printed by `ethtool -k` to the
// switch accepted by `ethtool -K`.  LRO and hardware GRO are included because
// disabling only TSO/GSO/GRO is not sufficient for wire-faithful captures on
// all drivers.
var ethtoolFeatures = []struct {
	name       string
	switchName string
}{
	{name: "rx-checksumming", switchName: "rx"},
	{name: "tx-checksumming", switchName: "tx"},
	{name: "scatter-gather", switchName: "sg"},
	{name: "tcp-segmentation-offload", switchName: "tso"},
	{name: "generic-segmentation-offload", switchName: "gso"},
	{name: "generic-receive-offload", switchName: "gro"},
	{name: "large-receive-offload", switchName: "lro"},
	{name: "rx-vlan-offload", switchName: "rxvlan"},
	{name: "tx-nocache-copy", switchName: "tx-nocache-copy"},
	{name: "rx-gro-hw", switchName: "rx-gro-hw"},
}

type featureState struct {
	on    bool
	fixed bool
}

// DisableOffloading disables mutable receive/transmit offloads and returns an
// idempotent restoration closure.  The caller must invoke the closure on every
// path after success because ethtool settings are global to the interface.
func DisableOffloading(iface string) (func() error, error) {
	if err := validateInterfaceName(iface); err != nil {
		return nil, err
	}
	ethtool, err := exec.LookPath("ethtool")
	if err != nil {
		return nil, fmt.Errorf("find ethtool: %w", err)
	}
	output, err := ethtoolCommand(ethtool, "-k", iface).CombinedOutput()
	if err != nil {
		return nil, commandError("query offload features", err, output)
	}
	initial := parseFeatureStates(string(output))

	changed := make([]struct {
		switchName string
		on         bool
	}, 0, len(ethtoolFeatures))
	for _, feature := range ethtoolFeatures {
		state, ok := initial[feature.name]
		if !ok || state.fixed || !state.on {
			continue
		}
		if err := setFeature(ethtool, iface, feature.switchName, false); err != nil {
			return nil, errors.Join(err, restoreFeatures(ethtool, iface, changed))
		}
		changed = append(changed, struct {
			switchName string
			on         bool
		}{switchName: feature.switchName, on: true})
	}

	restored := false
	return func() error {
		if restored {
			return nil
		}
		restored = true
		return restoreFeatures(ethtool, iface, changed)
	}, nil
}

func parseFeatureStates(output string) map[string]featureState {
	states := make(map[string]featureState)
	for _, line := range strings.Split(output, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 || (fields[0] != "on" && fields[0] != "off") {
			continue
		}
		state := featureState{on: fields[0] == "on"}
		for _, field := range fields[1:] {
			if strings.Trim(field, "[]") == "fixed" {
				state.fixed = true
			}
		}
		states[name] = state
	}
	return states
}

// ethtoolCommand builds an ethtool invocation from an absolute path resolved
// by LookPath. No shell is involved and the process is constructed from that
// path directly, so nothing in args can select a different executable.
// Interface names reach this only after validateInterfaceName.
func ethtoolCommand(ethtool string, args ...string) *exec.Cmd {
	// nosemgrep: go.lang.security.audit.dangerous-exec-cmd.dangerous-exec-cmd, go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	return &exec.Cmd{Path: ethtool, Args: append([]string{"ethtool"}, args...)}
}

func setFeature(ethtool, iface, feature string, on bool) error {
	value := "off"
	if on {
		value = "on"
	}
	output, err := ethtoolCommand(ethtool, "-K", iface, feature, value).CombinedOutput()
	if err != nil {
		return commandError(fmt.Sprintf("set %s %s", feature, value), err, output)
	}
	return nil
}

func restoreFeatures(ethtool, iface string, changed []struct {
	switchName string
	on         bool
},
) error {
	var errs []error
	for i := len(changed) - 1; i >= 0; i-- {
		if err := setFeature(ethtool, iface, changed[i].switchName, changed[i].on); err != nil {
			errs = append(errs, fmt.Errorf("restore interface %s: %w", iface, err))
		}
	}
	return errors.Join(errs...)
}

func commandError(action string, err error, output []byte) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, message)
}
