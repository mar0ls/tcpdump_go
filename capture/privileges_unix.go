//go:build !windows

package capture

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// DropPrivileges implements tcpdump's -Z. Call it after the handle is active
// (the only step needing root) and before creating output files, so captures
// are owned by the target user. A partial drop is an error, not a success.
func DropPrivileges(username string) error {
	if username == "" {
		return nil
	}
	account, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("look up user %q: %w", username, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return fmt.Errorf("user %q has a non-numeric uid %q: %w", username, account.Uid, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return fmt.Errorf("user %q has a non-numeric gid %q: %w", username, account.Gid, err)
	}
	if uid == 0 {
		return fmt.Errorf("refusing to drop privileges to %q because it is uid 0", username)
	}
	if os.Getuid() == uid && os.Geteuid() == uid {
		// Already running as the requested account; nothing to drop.
		return nil
	}
	if os.Geteuid() != 0 {
		// Matching tcpdump: an unprivileged process has nothing to drop. The
		// caller reports this rather than failing.
		return fmt.Errorf("cannot switch to %q: %w", username, ErrNotPrivileged)
	}

	if err := setSupplementaryGroups(account, gid); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("switch to group %d of user %q: %w", gid, username, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("switch to user %q (uid %d): %w", username, uid, err)
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("privilege drop to %q did not take effect (uid %d/%d, gid %d)",
			username, os.Getuid(), os.Geteuid(), os.Getegid())
	}
	return nil
}

// setSupplementaryGroups mirrors initgroups(3). Some systems cap the group
// list (macOS allows 16), so a rejected full list falls back to the primary
// group alone, which grants strictly fewer privileges and is therefore safe.
func setSupplementaryGroups(account *user.User, gid int) error {
	groupIDs, err := account.GroupIds()
	if err != nil {
		groupIDs = nil
	}
	groups := make([]int, 0, len(groupIDs)+1)
	groups = append(groups, gid)
	for _, id := range groupIDs {
		parsed, convErr := strconv.Atoi(id)
		if convErr != nil || parsed == gid {
			continue
		}
		groups = append(groups, parsed)
	}
	if err := syscall.Setgroups(groups); err == nil {
		return nil
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("reset supplementary groups for user %q: %w", account.Username, err)
	}
	return nil
}
