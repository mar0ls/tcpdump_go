//go:build !windows

package capture

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestDropPrivilegesEmptyUserIsNoOp(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	if err := DropPrivileges(""); err != nil {
		t.Fatalf("DropPrivileges(\"\") = %v, want nil", err)
	}
	if os.Getuid() != uid || os.Getgid() != gid {
		t.Fatalf("identity changed to uid %d gid %d, want uid %d gid %d", os.Getuid(), os.Getgid(), uid, gid)
	}
}

func TestDropPrivilegesUnknownUserFails(t *testing.T) {
	if err := DropPrivileges("no-such-account-cf19a4"); err == nil {
		t.Fatal("DropPrivileges with an unknown user returned nil")
	}
}

// TestDropPrivilegesToCurrentUserIsNoOp covers the path where the process
// already runs as the requested account, which must succeed without root.
func TestDropPrivilegesToCurrentUserIsNoOp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: -Z root is rejected on purpose, see TestDropPrivilegesRefusesRoot")
	}
	current, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine the current user: %v", err)
	}
	if err := DropPrivileges(current.Username); err != nil {
		t.Fatalf("DropPrivileges(%q) = %v, want nil", current.Username, err)
	}
	if got := strconv.Itoa(os.Getuid()); got != current.Uid {
		t.Fatalf("uid = %s, want %s", got, current.Uid)
	}
}

func TestDropPrivilegesRefusesRoot(t *testing.T) {
	root, err := user.LookupId("0")
	if err != nil {
		t.Skipf("no uid 0 on this system: %v", err)
	}
	if err := DropPrivileges(root.Username); err == nil {
		t.Fatalf("DropPrivileges(%q) = nil, want a refusal", root.Username)
	}
}

// An unprivileged process has nothing to drop. tcpdump treats that as a no-op,
// so the result must be the ErrNotPrivileged sentinel the callers downgrade to
// a warning — never a silent success, and never a hard failure.
func TestDropPrivilegesReportsMissingRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the drop would succeed")
	}
	target := otherAccount(t)
	err := DropPrivileges(target)
	if err == nil {
		t.Fatalf("DropPrivileges(%q) = nil while unprivileged", target)
	}
	if !errors.Is(err, ErrNotPrivileged) {
		t.Fatalf("DropPrivileges(%q) = %v, want it to wrap ErrNotPrivileged", target, err)
	}
	if os.Geteuid() == 0 {
		t.Fatal("process unexpectedly became root")
	}
}

// A missing account stays a hard error: that is a typo, not a no-op.
func TestUnknownUserIsNotDowngradedToAWarning(t *testing.T) {
	err := DropPrivileges("no-such-account-cf19a4")
	if err == nil {
		t.Fatal("unknown user returned nil")
	}
	if errors.Is(err, ErrNotPrivileged) {
		t.Fatalf("unknown user reported as ErrNotPrivileged: %v", err)
	}
}

// otherAccount returns an existing non-root account that is not the caller.
func otherAccount(t *testing.T) string {
	t.Helper()
	self := strconv.Itoa(os.Getuid())
	for _, candidate := range []string{"nobody", "daemon", "bin", "sys"} {
		account, err := user.Lookup(candidate)
		if err == nil && account.Uid != self && account.Uid != "0" {
			return candidate
		}
	}
	t.Skip("no suitable unprivileged account to test against")
	return ""
}
