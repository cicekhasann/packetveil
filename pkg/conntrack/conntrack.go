package conntrack

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Protocol uint8

const (
	ProtoTCP Protocol = 6
	ProtoUDP Protocol = 17
)

type State uint8

const (
	StateNew         State = 0
	StateSynSent     State = 1
	StateEstablished State = 2
	StateFinWait     State = 3
	StateClosed      State = 4
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateSynSent:
		return "SYN_SENT"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

type FlowKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Proto   Protocol
}

func MakeKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto Protocol) FlowKey {
	var k FlowKey
	copy(k.SrcIP[:], srcIP.To4())
	copy(k.DstIP[:], dstIP.To4())
	k.SrcPort = srcPort
	k.DstPort = dstPort
	k.Proto = proto
	return k
}

type Flow struct {
	Key       FlowKey
	State     State
	Packets   uint64
	Bytes     uint64
	LastSeen  time.Time
	CreatedAt time.Time
}

type Table struct {
	mu    sync.RWMutex
	flows map[FlowKey]*Flow
	ttl   time.Duration
}

func NewTable(ttl time.Duration) *Table {
	return &Table{
		flows: make(map[FlowKey]*Flow),
		ttl:   ttl,
	}
}

// Track processes a packet tuple and advances the connection state machine.
func (t *Table) Track(key FlowKey, tcpFlags uint8, payloadLen uint32) (State, bool) {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	f, exists := t.flows[key]
	if !exists {
		// New outbound connection or SYN
		isSyn := (tcpFlags & 0x02) != 0
		st := StateNew
		if isSyn {
			st = StateSynSent
		}

		f = &Flow{
			Key:       key,
			State:     st,
			Packets:   1,
			Bytes:     uint64(payloadLen),
			LastSeen:  now,
			CreatedAt: now,
		}
		t.flows[key] = f
		return st, true
	}

	f.Packets++
	f.Bytes += uint64(payloadLen)
	f.LastSeen = now

	// Advance TCP state transitions
	isAck := (tcpFlags & 0x10) != 0
	isFin := (tcpFlags & 0x01) != 0
	isRst := (tcpFlags & 0x04) != 0

	if isRst {
		f.State = StateClosed
	} else if isFin {
		f.State = StateFinWait
	} else if isAck && f.State == StateSynSent {
		f.State = StateEstablished
	}

	return f.State, false
}

// PruneExpired evicts idle flows beyond TTL.
func (t *Table) PruneExpired() int {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	var pruned int
	for k, f := range t.flows {
		if now.Sub(f.LastSeen) > t.ttl || f.State == StateClosed {
			delete(t.flows, k)
			pruned++
		}
	}
	return pruned
}

func (t *Table) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

func (k FlowKey) String() string {
	src := net.IP(k.SrcIP[:]).String()
	dst := net.IP(k.DstIP[:]).String()
	return fmt.Sprintf("%s:%d -> %s:%d (proto %d)", src, k.SrcPort, dst, k.DstPort, k.Proto)
}
