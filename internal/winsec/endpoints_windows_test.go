package winsec

import (
	"net/netip"
	"testing"
)

func TestParseTableRejectsGarbage(t *testing.T) {
	k := tableKinds[0]
	if _, err := parseTable([]byte{1}, k, 1); err == nil {
		t.Error("short table accepted")
	}
	if _, err := parseTable([]byte{0xff, 0xff, 0, 0, 1, 2, 3}, k, 1); err == nil {
		t.Error("count larger than buffer accepted")
	}
	row := make([]byte, 4+24)
	row[0] = 1
	copy(row[4+4:], []byte{127, 0, 0, 1})
	row[4+8], row[4+9] = 0x22, 0x53 // port 8787
	row[4+20] = 42
	eps, err := parseTable(row, k, 42)
	if err != nil || len(eps) != 1 || eps[0].Addr != netip.MustParseAddrPort("127.0.0.1:8787") {
		t.Fatalf("eps=%v err=%v", eps, err)
	}
}
