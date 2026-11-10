package filter

import (
	"net"
	"sync"
	"time"

	"github.com/cicekhasann/packetveil/pkg/conntrack"
)

type Action uint8

const (
	ActionPass Action = iota
	ActionDrop
	ActionTarpit
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "PASS"
	case ActionDrop:
		return "DROP"
	case ActionTarpit:
		return "TARPIT"
	default:
		return "UNKNOWN"
	}
}

type Rule struct {
	ID       string
	DstPort  uint16
	Proto    conntrack.Protocol
	SrcNet   *net.IPNet
	Action   Action
	Priority int
}

type Engine struct {
	mu           sync.RWMutex
	rules        []Rule
	table        *conntrack.Table
	synCount     map[[4]byte]int
	synThreshold int
	lastReset    time.Time
}

func NewEngine(tableTTL time.Duration, synThreshold int) *Engine {
	return &Engine{
		table:        conntrack.NewTable(tableTTL),
		synCount:     make(map[[4]byte]int),
		synThreshold: synThreshold,
		lastReset:    time.Now(),
	}
}

func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// Inspect evaluates packet against stateful flows, anti-SYN flood thresholds, and ACL rules.
func (e *Engine) Inspect(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto conntrack.Protocol, tcpFlags uint8, payloadLen uint32) (Action, string) {
	key := conntrack.MakeKey(srcIP, dstIP, srcPort, dstPort, proto)

	// Anti-SYN flood rate limit check
	isSyn := (tcpFlags & 0x02) != 0
	if isSyn && (tcpFlags&0x10) == 0 { // pure SYN, not SYN-ACK
		e.mu.Lock()
		if time.Since(e.lastReset) > time.Second {
			e.synCount = make(map[[4]byte]int)
			e.lastReset = time.Now()
		}
		e.synCount[key.SrcIP]++
		cnt := e.synCount[key.SrcIP]
		e.mu.Unlock()

		if cnt > e.synThreshold {
			return ActionTarpit, "anti-syn-flood: rate limit triggered"
		}
	}

	// Connection tracking
	st, isNew := e.table.Track(key, tcpFlags, payloadLen)
	if !isNew && st == conntrack.StateEstablished {
		return ActionPass, "conntrack: established flow"
	}

	// ACL evaluation
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, r := range e.rules {
		if r.Proto != 0 && r.Proto != proto {
			continue
		}
		if r.DstPort != 0 && r.DstPort != dstPort {
			continue
		}
		if r.SrcNet != nil && !r.SrcNet.Contains(srcIP) {
			continue
		}
		return r.Action, r.ID
	}

	// Default policy: Allow
	return ActionPass, "default"
}

func (e *Engine) ActiveFlows() int {
	return e.table.ActiveCount()
}
