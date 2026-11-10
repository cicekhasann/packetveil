# packetveil

Stateful L4/L7 packet inspection and anti-SYN flood mitigation engine written in Go.

Performs connection tracking, TCP state machine modeling, and ACL rule evaluation with zero allocations on established traffic paths.

```
       [ Ingress Network Interface ]
                     |
            ( Anti-SYN Rate Limiter )
             /                     \
       [ > Threshold ]        [ Within Rate ]
             |                      |
       [ Action: TARPIT ]    ( 4-Tuple Conntrack Table )
                               /               \
                        [ Established ]    [ SYN / New ]
                              |                  |
                        ( 0-Alloc PASS )    ( ACL Rule Match )
                                                /        \
                                          [ PASS ]     [ DROP ]
```

## Features

- **Connection Tracking (Conntrack):** Maintains state across TCP handshakes (`SYN`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`).
- **Zero-Allocation Fast Path:** Evaluates established flows at `0 B/op, 0 allocs/op` with microsecond latency.
- **Anti-SYN Flood Defense:** Dynamic sliding-window rate tracking per source IPv4 subnet; tarpits or drops volumetric connection floods before socket exhaustion.
- **ACL Rule Engine:** Prioritized matching for destination port, protocol, and CIDR subnet boundaries.

## Benchmarks

Benchmarked on AMD Ryzen 9 6900HX (Linux 6.x):

```
goos: linux
goarch: amd64
pkg: github.com/cicekhasann/packetveil/pkg/filter
cpu: AMD Ryzen 9 6900HX with Radeon Graphics
BenchmarkInspect_EstablishedFlow-16   12906974   94.99 ns/op   0 B/op   0 allocs/op
```

## Building & Testing

```bash
make test    # Run unit tests
make race    # Run concurrency race detector
make bench   # Run benchmarks
make build   # Compile static binary to bin/packetveil
```

## License

MIT License.
