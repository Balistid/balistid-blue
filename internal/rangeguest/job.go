package rangeguest

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"strings"
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
