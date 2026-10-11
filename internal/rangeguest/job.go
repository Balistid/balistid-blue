package rangeguest

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"strconv"
	"strings"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// JobSerial is the virtio serial of the job disk (rangevm attaches it read-only).
const JobSerial = "balistid-job"

// JobDevice returns the device node of the job disk, found by its virtio serial in sys (a view of
// /sys), or "" when no job disk is attached. Two disks with that serial are an error: the guest
// must not choose which program it runs.
func JobDevice(sys fs.FS) (string, error) {
	entries, err := fs.ReadDir(sys, "block")
	if err != nil {
		return "", errors.New("cannot list block devices")
	}
	found := ""
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "vd") {
			continue
		}
		serial, err := fs.ReadFile(sys, "block/"+e.Name()+"/serial")
		if err != nil || strings.TrimSpace(string(serial)) != JobSerial {
			continue
		}
		if found != "" {
			return "", errors.New("more than one job disk")
		}
		found = "/dev/" + e.Name()
	}
	return found, nil
}

// TrialCredentials returns the trial name and boot phase the host passed as the systemd credentials
// balistid.trial and balistid.phase (ADR 0018, point 1), read from creds, the unit's credentials
// directory, or "" for both when creds is nil or holds neither. One without the other is an error.
func TrialCredentials(creds fs.FS) (name, phase string, err error) {
	if creds == nil {
		return "", "", nil
	}
	n, errName := fs.ReadFile(creds, "balistid.trial")
	p, errPhase := fs.ReadFile(creds, "balistid.phase")
	switch {
	case errors.Is(errName, fs.ErrNotExist) && errors.Is(errPhase, fs.ErrNotExist):
		return "", "", nil
	case errName != nil || errPhase != nil:
		return "", "", errors.New("trial credentials incomplete")
	}
	return string(n), string(p), nil
}

// TrialFor returns the table's trial called name and the boot phase, 1 up to the trial's boots.
func TrialFor(name, phase string) (rangejob.Trial, int, error) {
	tr, ok := rangejob.Lookup(name)
	p, err := strconv.Atoi(phase)
	if !ok || err != nil || strconv.Itoa(p) != phase || p < 1 || p > tr.Boots {
		return rangejob.Trial{}, 0, errors.New("not a trial and boot of this image")
	}
	return tr, p, nil
}

// Chunks splits data into base64 strings of at most size raw bytes each, so arbitrary program
// output and log bytes fit the results records unchanged.
func Chunks(data []byte, size int) []string {
	var out []string
	for len(data) > 0 {
		n := min(size, len(data))
		out = append(out, base64.StdEncoding.EncodeToString(data[:n]))
		data = data[n:]
	}
	return out
}
