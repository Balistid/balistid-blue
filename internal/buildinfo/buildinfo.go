// Package buildinfo reports what this binary is, for status output and records.
package buildinfo

import (
	"errors"
	"fmt"
	"regexp"
)

// Version is set at release build time with -ldflags "-X"; a development build says so.
var Version = "dev"

var commitID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// String returns the name and version printed by `balistid version`.
func String() string {
	return fmt.Sprintf("balistid %s", Version)
}

// IsCommitID reports whether s is a full lower-case commit id.
func IsCommitID(s string) bool { return commitID.MatchString(s) }

// Commit returns Version if it is a full lower-case commit id, which CI sets for the range runner
// (ADR 0011, point 2), and an error for any other build.
func Commit() (string, error) {
	if !IsCommitID(Version) {
		return "", errors.New("this binary was not built with a full commit id as its version")
	}
	return Version, nil
}
