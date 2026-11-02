package status

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Unit is a floor-0 unit on the host and the SubStates systemd shows while it does its job.
type Unit struct {
	Name string
	Subs []string
}

// units are the floor-0 units status asks systemd about: the sensor, the collector and its socket, auditstat,
// the ledger, the relay, the tunnel's oneshot and the unit whose stop announces a shutdown (ADR 0048).
var units = []Unit{
	{"auditd.service", []string{"running"}},
	// Accept=no: once the service took the listening fd, systemd shows the socket running, not listening.
	{"balistid-collector.socket", []string{"listening", "running"}},
	{"balistid-collector.service", []string{"running"}},
	{"balistid-auditstat.service", []string{"running"}},
	{"balistid-ledger.service", []string{"running"}},
	{"balistid-relay.service", []string{"running"}},
	{"balistid-net.service", []string{"exited"}},
	{"balistid-announce.service", []string{"exited"}},
}

// UnitState is what systemd reports of one unit.
type UnitState struct{ ID, Load, Active, Sub string }

const (
	systemctl   = "/usr/bin/systemctl"
	showTimeout = 5 * time.Second
	maxShow     = 64 << 10
)

// showProps are the properties asked for, exactly one line each per unit.
var showProps = []string{"Id", "LoadState", "ActiveState", "SubState"}

// ShowUnits asks systemd for the state of names, in their order. systemctl runs by its absolute path with no
// environment but the C locale, so neither PATH nor a bus address of the caller's choosing is used.
func ShowUnits(ctx context.Context, names []string) ([]UnitState, error) {
	ctx, cancel := context.WithTimeout(ctx, showTimeout)
	defer cancel()
	args := append([]string{"show", "--property=" + strings.Join(showProps, ","), "--"}, names...)
	cmd := exec.CommandContext(ctx, systemctl, args...) //nolint:gosec // fixed binary and verb; names are units
	cmd.Env = []string{"LC_ALL=C"}
	out := &capped{limit: maxShow}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("status: systemctl show: %w", err)
	}
	return parseShow(out.b.Bytes(), names)
}

// capped keeps at most limit bytes and fails the write past them.
type capped struct {
	b     bytes.Buffer
	limit int
}

func (c *capped) Write(p []byte) (int, error) {
	if c.b.Len()+len(p) > c.limit {
		return 0, errors.New("status: systemctl output over its cap")
	}
	return c.b.Write(p) //nolint:wrapcheck // bytes.Buffer never fails a write
}

// stateValue is the form of every value systemd prints for these properties; nothing else reaches the output.
var stateValue = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)

// parseShow reads systemctl show's blocks, one per name in order, each exactly showProps once, the Id the name
// asked for. Anything else is refused whole: status reads no unit from output it cannot read (R6).
func parseShow(out []byte, names []string) ([]UnitState, error) {
	blocks := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n\n")
	if len(blocks) != len(names) {
		return nil, fmt.Errorf("status: systemctl show printed %d units for %d", len(blocks), len(names))
	}
	states := make([]UnitState, len(names))
	for i, block := range blocks {
		props := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if _, dup := props[k]; !ok || dup {
				return nil, fmt.Errorf("status: systemctl show: unit %d: a line that is not one new property", i)
			}
			props[k] = v
		}
		s := UnitState{ID: props["Id"], Load: props["LoadState"], Active: props["ActiveState"], Sub: props["SubState"]}
		switch {
		case len(props) != len(showProps) || s.ID != names[i]:
			return nil, fmt.Errorf("status: systemctl show: unit %d is not %s with its %d properties", i, names[i], len(showProps))
		case !stateValue.MatchString(s.Load) || !stateValue.MatchString(s.Active) || !stateValue.MatchString(s.Sub):
			return nil, fmt.Errorf("status: systemctl show: %s: a state of another form", names[i])
		}
		states[i] = s
	}
	return states, nil
}
