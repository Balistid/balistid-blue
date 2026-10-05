// Package buildinfo reports what this binary is, for status output and records.
package buildinfo

import "fmt"

// Version is set at release build time with -ldflags "-X"; a development build says so.
var Version = "dev"

// String returns the name and version printed by `balistid version`.
func String() string {
	return fmt.Sprintf("balistid %s", Version)
}
