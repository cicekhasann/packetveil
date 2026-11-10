package filter

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cicekhasann/packetveil/pkg/conntrack"
)

func TestEngine_HandshakeAndEstablishedPass(t *testing.T) {
	eng := NewEngine(10*time.Second, 100)

	src := net.ParseIP("192.168.1.50")
	dst := net.ParseIP("10.0.0.1")

	// 1. Client SYN
	action, _ := eng.Inspect(src, dst, 54321, 443, conntrack.ProtoTCP, 0x02, 0)
	if action != ActionPass {
		t.Fatalf("expected initial SYN to pass, got %s", action)
	}

	// 2. Client ACK to establish
	action, _ = eng.Inspect(src, dst, 54321, 443, conntrack.ProtoTCP, 0x10, 32)
	if action != ActionPass {
		t.Fatalf("expected ACK to establish, got %s", action)
	}

	// 3. Established data packet fast path
	action, reason := eng.Inspect(src, dst, 54321, 443, conntrack.ProtoTCP, 0x10, 1024)
	if action != ActionPass || reason != "conntrack: established flow" {
		t.Fatalf("expected established flow pass, got %s (%s)", action, reason)
	}
}

func TestEngine_RuleDrop(t *testing.T) {
	eng := NewEngine(10*time.Second, 100)

	// Block Telnet port 23
	eng.AddRule(Rule{
		ID:      "BLOCK_TELNET",
		DstPort: 23,
		Proto:   conntrack.ProtoTCP,
		Action:  ActionDrop,
	})

	src := net.ParseIP("192.168.1.100")
	dst := net.ParseIP("10.0.0.5")

	action, id := eng.Inspect(src, dst, 49152, 23, conntrack.ProtoTCP, 0x02, 0)
	if action != ActionDrop || id != "BLOCK_TELNET" {
		t.Fatalf("expected ActionDrop on port 23, got %s (%s)", action, id)
	}
}

func TestEngine_AntiSynFloodTarpit(t *testing.T) {
	eng := NewEngine(10*time.Second, 5) // threshold = 5 SYNs

	src := net.ParseIP("203.0.113.88")
	dst := net.ParseIP("10.0.0.1")

	// Send 5 SYNs (below limit)
	for i := 0; i < 5; i++ {
		action, _ := eng.Inspect(src, dst, uint16(50000+i), 80, conntrack.ProtoTCP, 0x02, 0)
		if action != ActionPass {
			t.Fatalf("expected pass under threshold at index %d", i)
		}
	}

	// 6th SYN must trigger Tarpit
	action, reason := eng.Inspect(src, dst, 50006, 80, conntrack.ProtoTCP, 0x02, 0)
	if action != ActionTarpit {
		t.Fatalf("expected ActionTarpit, got %s (%s)", action, reason)
	}
}

func TestEngine_ConcurrentTraffic_RaceDetector(t *testing.T) {
	eng := NewEngine(10*time.Second, 5000)

	const workers = 16
	const packets = 500

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer wg.Done()
			src := net.ParseIP(fmt.Sprintf("10.1.%d.5", workerID))
			dst := net.ParseIP("172.16.0.1")

			for j := 0; j < packets; j++ {
				_ = eng.ActiveFlows()
				_, _ = eng.Inspect(src, dst, uint16(10000+j), 443, conntrack.ProtoTCP, 0x02, 0)
				_, _ = eng.Inspect(src, dst, uint16(10000+j), 443, conntrack.ProtoTCP, 0x10, 64)
			}
		}(i)
	}

	wg.Wait()
}

func BenchmarkInspect_EstablishedFlow(b *testing.B) {
	eng := NewEngine(time.Minute, 1_000_000)
	src := net.ParseIP("10.0.0.2")
	dst := net.ParseIP("10.0.0.1")

	// Establish flow
	_, _ = eng.Inspect(src, dst, 54321, 443, conntrack.ProtoTCP, 0x02, 0)
	_, _ = eng.Inspect(src, dst, 54321, 443, conntrack.ProtoTCP, 0x10, 0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = eng.Inspect(src, dst, 54321, 443, conntrack.ProtoTCP, 0x10, 128)
	}
}
