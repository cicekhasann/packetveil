package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cicekhasann/packetveil/pkg/conntrack"
	"github.com/cicekhasann/packetveil/pkg/filter"
)

var globalEngine *filter.Engine

func main() {
	synLimit := flag.Int("syn-limit", 1000, "Anti-SYN flood trigger threshold per IP")
	httpAddr := flag.String("http", "", "Serve HTTP telemetry dashboard (e.g. :8083)")
	simulate := flag.Bool("sim", true, "Run continuous packet traffic simulator")
	flag.Parse()

	eng := filter.NewEngine(30*time.Second, *synLimit)
	globalEngine = eng

	// Setup default firewall rules
	eng.AddRule(filter.Rule{
		ID:      "RULE_DROP_TELNET",
		DstPort: 23,
		Proto:   conntrack.ProtoTCP,
		Action:  filter.ActionDrop,
	})
	eng.AddRule(filter.Rule{
		ID:      "RULE_DROP_SMB",
		DstPort: 445,
		Proto:   conntrack.ProtoTCP,
		Action:  filter.ActionDrop,
	})

	if *httpAddr != "" {
		go startHTTPServer(*httpAddr)
	}

	fmt.Printf("\033[1;34m=== packetveil // Stateful L4/L7 Packet Inspection Engine ===\033[0m\n")
	fmt.Printf("Conntrack TTL: 30s | SYN Flood Threshold: %d/s\n", *synLimit)
	if *httpAddr != "" {
		fmt.Printf("Web Telemetry: http://localhost%s\n", *httpAddr)
	}

	if *simulate {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		runTrafficSimulator(ctx, eng)
	}
}

func runTrafficSimulator(ctx context.Context, eng *filter.Engine) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	dst := net.ParseIP("10.0.0.1")
	var passed, dropped, tarpitted int64

	fmt.Println("Simulating network flows (press Ctrl+C to stop)...")

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\nSimulator terminated. Total Active Flows: %d\n", eng.ActiveFlows())
			return
		case <-ticker.C:
			// Generate random traffic
			port := uint16(80)
			if rand.Float32() < 0.15 {
				port = 23 // Trigger drop rule
			} else if rand.Float32() < 0.3 {
				port = 443
			}

			src := net.IPv4(192, 168, byte(rand.Intn(10)), byte(rand.Intn(250)+1))
			action, reason := eng.Inspect(src, dst, uint16(30000+rand.Intn(20000)), port, conntrack.ProtoTCP, 0x02, 0)

			switch action {
			case filter.ActionPass:
				passed++
			case filter.ActionDrop:
				dropped++
			case filter.ActionTarpit:
				tarpitted++
			}

			fmt.Printf("\r\033[K[FLOWS: %4d] \033[32mPASS: %6d\033[0m | \033[31mDROP: %4d\033[0m | \033[33mTARPIT: %4d\033[0m | Last: %s:%d [%s - %s]",
				eng.ActiveFlows(), passed, dropped, tarpitted, src.String(), port, action, reason)
		}
	}
}

func startHTTPServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/flows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active_flows": globalEngine.ActiveFlows(),
			"status":       "running",
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:monospace;background:#030712;color:#38bdf8;padding:2rem;">
<h1>packetveil // Packet Inspection & Flow Monitor</h1>
<p>Engine active.</p></body></html>`))
	})
	_ = http.ListenAndServe(addr, mux)
}
