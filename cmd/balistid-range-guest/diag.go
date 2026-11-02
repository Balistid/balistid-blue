package main

// Exp only, never merged: DIAG lines on the serial console for the status trial's restore.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
)

func diagUnit(ctx context.Context, unit string) {
	for _, args := range [][]string{
		{"/usr/bin/systemctl", "show", "--property=ActiveState,SubState,Result,ExecMainStatus,LoadState", unit},
		{"/usr/bin/journalctl", "-q", "--no-pager", "-o", "cat", "-n", "40", "-u", unit},
		{"/usr/bin/ip", "-br", "link"},
		{"/usr/bin/systemctl", "list-units", "--no-legend", "--plain", "--all", "balistid-*"},
	} {
		for _, line := range strings.Split(output(ctx, args[0], args[1:]...), "\n") {
			fmt.Printf("DIAG %s\n", base64.StdEncoding.EncodeToString([]byte(args[0]+": "+line))) //nolint:forbidigo // exp only
		}
	}
}
