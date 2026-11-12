package worker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Endpoint is one socket this process has bound for receiving: a listening
// TCP socket or any bound UDP socket.
type Endpoint struct {
	Proto string // "tcp" or "udp"
	Addr  netip.AddrPort
}

// iphlpapi.dll is loaded from System32 only (S-24).
var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet                   = windows.AF_INET
	afInet6                  = windows.AF_INET6
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	udpTableOwnerPID         = 1 // UDP_TABLE_OWNER_PID
)

// table layouts (iprtrmib.h / tcpmib.h / udpmib.h): a DWORD count, then rows
type tableKind struct {
	proc    *windows.LazyProc
	af      uint32
	class   uint32
	rowSize int
	proto   string
	// offsets inside a row
	addrOff, addrLen, portOff, pidOff int
}

var tableKinds = []tableKind{
	// MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
	{procGetExtendedTcpTable, afInet, tcpTableOwnerPIDListener, 24, "tcp", 4, 4, 8, 20},
	// MIB_TCP6ROW_OWNER_PID: localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid
	{procGetExtendedTcpTable, afInet6, tcpTableOwnerPIDListener, 56, "tcp", 0, 16, 20, 52},
	// MIB_UDPROW_OWNER_PID: localAddr, localPort, pid
	{procGetExtendedUdpTable, afInet, udpTableOwnerPID, 12, "udp", 0, 4, 4, 8},
	// MIB_UDP6ROW_OWNER_PID: localAddr[16], scope, localPort, pid
	{procGetExtendedUdpTable, afInet6, udpTableOwnerPID, 28, "udp", 0, 16, 20, 24},
}

// OwnEndpoints lists every listening TCP socket and bound UDP socket owned by
// this process.
func OwnEndpoints() ([]Endpoint, error) {
	pid := windows.GetCurrentProcessId()
	var out []Endpoint
	for _, k := range tableKinds {
		buf, err := readTable(k)
		if err != nil {
			return nil, err
		}
		eps, err := parseTable(buf, k, pid)
		if err != nil {
			return nil, err
		}
		out = append(out, eps...)
	}
	return out, nil
}

func readTable(k tableKind) ([]byte, error) {
	size := uint32(4096)
	for range 8 {
		buf := make([]byte, size)
		// #nosec G103 -- passing a Go buffer and its size to a Windows API, as its documentation requires
		r, _, _ := k.proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(k.af), uintptr(k.class), 0)
		switch windows.Errno(r) {
		case windows.ERROR_SUCCESS:
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 4096 // the table can grow between calls
			continue
		default:
			return nil, fmt.Errorf("reading %s socket table: %w", k.proto, windows.Errno(r))
		}
	}
	return nil, errors.New("socket table kept growing")
}

func parseTable(buf []byte, k tableKind, pid uint32) ([]Endpoint, error) {
	if len(buf) < 4 {
		return nil, errors.New("short socket table")
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if n < 0 || n > (len(buf)-4)/k.rowSize {
		return nil, errors.New("malformed socket table")
	}
	var out []Endpoint
	for i := range n {
		row := buf[4+i*k.rowSize : 4+(i+1)*k.rowSize]
		if binary.LittleEndian.Uint32(row[k.pidOff:]) != pid {
			continue
		}
		var addr netip.Addr
		if k.addrLen == 4 {
			addr = netip.AddrFrom4([4]byte(row[k.addrOff : k.addrOff+4]))
		} else {
			addr = netip.AddrFrom16([16]byte(row[k.addrOff : k.addrOff+16]))
		}
		// the port is in network byte order in the low 16 bits of the DWORD
		port := uint16(row[k.portOff])<<8 | uint16(row[k.portOff+1])
		out = append(out, Endpoint{Proto: k.proto, Addr: netip.AddrPortFrom(addr, port)})
	}
	return out, nil
}
