// Command kordon-range-guest runs inside a range VM, writes what the guest sees to the results disk
// and exits; its systemd unit powers the VM off either way (ADR 0009, point 5).
package main

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/Kordon-Sec/kordon/internal/rangevm"
)

const resultsDisk = "/dev/disk/by-id/virtio-kordon-results"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kordon-range-guest:", err)
		os.Exit(1)
	}
}

func run() error {
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return fmt.Errorf("kernel release: %w", err)
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return fmt.Errorf("network interfaces: %w", err)
	}
	var ifaces []string
	for _, e := range entries {
		ifaces = append(ifaces, e.Name())
	}
	slices.Sort(ifaces)
	pciNet, err := networkPCIDevices()
	if err != nil {
		return err
	}

	facts := []rangevm.Record{
		{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindFact, Name: rangevm.FactKernel, Value: strings.TrimSpace(string(kernel))},
		{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindFact, Name: rangevm.FactNet, Value: strings.Join(ifaces, ",")},
		{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindFact, Name: rangevm.FactPCINet, Value: strings.Join(pciNet, ",")},
	}
	var buf bytes.Buffer
	for _, f := range facts {
		if err := rangevm.Append(&buf, f); err != nil {
			return fmt.Errorf("encode fact: %w", err)
		}
	}
	if err := rangevm.Append(&buf, rangevm.Record{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindEnd, Count: len(facts)}); err != nil {
		return fmt.Errorf("encode end record: %w", err)
	}

	disk, err := os.OpenFile(resultsDisk, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("results disk: %w", err)
	}
	if _, err := disk.Write(buf.Bytes()); err != nil {
		_ = disk.Close()
		return fmt.Errorf("write results: %w", err)
	}
	if err := disk.Sync(); err != nil {
		_ = disk.Close()
		return fmt.Errorf("sync results: %w", err)
	}
	if err := disk.Close(); err != nil {
		return fmt.Errorf("close results: %w", err)
	}
	return nil
}

// networkPCIDevices lists PCI devices of class 0x02 (network controller). They exist from PCI
// enumeration on, before a driver binds and an interface appears in /sys/class/net.
func networkPCIDevices() ([]string, error) {
	const dir = "/sys/bus/pci/devices"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pci devices: %w", err)
	}
	var found []string
	for _, e := range entries {
		class, err := os.ReadFile(dir + "/" + e.Name() + "/class")
		if err != nil {
			return nil, fmt.Errorf("pci device class: %w", err)
		}
		if strings.HasPrefix(strings.TrimSpace(string(class)), "0x02") {
			found = append(found, e.Name())
		}
	}
	return found, nil
}
