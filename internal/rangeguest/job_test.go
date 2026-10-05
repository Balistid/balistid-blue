package rangeguest

import (
	"bytes"
	"encoding/base64"
	"testing"
	"testing/fstest"
)

func TestJobDevice(t *testing.T) {
	sys := fstest.MapFS{
		"block/vda/serial": {Data: []byte("\n")},
		"block/vdb/serial": {Data: []byte("balistid-results\n")},
		"block/vdc/serial": {Data: []byte("balistid-job\n")},
		"block/sda/serial": {Data: []byte("balistid-job\n")},
	}
	if dev, err := JobDevice(sys); err != nil || dev != "/dev/vdc" {
		t.Fatalf("JobDevice = %q, %v; want /dev/vdc", dev, err)
	}
	delete(sys, "block/vdc/serial")
	if dev, err := JobDevice(sys); err != nil || dev != "" {
		t.Fatalf("without a job disk: %q, %v; want none", dev, err)
	}
	sys["block/vdc/serial"] = &fstest.MapFile{Data: []byte("balistid-job")}
	sys["block/vdd/serial"] = &fstest.MapFile{Data: []byte("balistid-job")}
	if dev, err := JobDevice(sys); err == nil {
		t.Fatalf("two job disks: %q accepted", dev)
	}
	if _, err := JobDevice(fstest.MapFS{}); err == nil {
		t.Fatal("missing /sys/block accepted")
	}
}

func TestChunks(t *testing.T) {
	data := bytes.Repeat([]byte{0, 0xff, 'a'}, 100)
	chunks := Chunks(data, 64)
	if len(chunks) != 5 {
		t.Fatalf("%d chunks, want 5", len(chunks))
	}
	var joined []byte
	for _, c := range chunks {
		b, err := base64.StdEncoding.DecodeString(c)
		if err != nil || len(b) > 64 {
			t.Fatalf("chunk %q: %d bytes, %v", c, len(b), err)
		}
		joined = append(joined, b...)
	}
	if !bytes.Equal(joined, data) || Chunks(nil, 64) != nil {
		t.Fatal("chunks do not rebuild the data")
	}
}
