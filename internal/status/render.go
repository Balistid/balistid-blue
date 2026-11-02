package status

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Scope is what the result does not cover yet, said on every text result (ADR 0048, point 3).
const Scope = "mode, history and alerts: shown from the local-mode install on"

// WriteText writes res for a person: the verdict first, then each part, a hint under each that is not OK.
func WriteText(w io.Writer, res Result) error {
	var b strings.Builder
	verdict := "NOT OK"
	if res.OK {
		verdict = OK
	}
	fmt.Fprintf(&b, "balistid status: %s\n", verdict)
	for _, p := range res.Parts {
		fmt.Fprintf(&b, "  %-8s %-27s %s\n", p.State, p.Name, p.Detail)
		if p.Hint != "" {
			fmt.Fprintf(&b, "  %-8s %-27s -> %s\n", "", "", p.Hint)
		}
	}
	b.WriteString(Scope + "\n")
	_, err := io.WriteString(w, b.String())
	return err //nolint:wrapcheck // the caller's writer
}

// WriteJSON writes res as one JSON object on one line.
func WriteJSON(w io.Writer, res Result) error {
	return json.NewEncoder(w).Encode(res) //nolint:wrapcheck // as above
}
