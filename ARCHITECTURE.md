# Architecture & Design

## System Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                          Host OS (Linux)                           │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     Docker network (host mode)               │  │
│  │                                                              │  │
│  │  ┌───────────────┐  JSON/stdout  ┌────────────────────────┐ │  │
│  │  │  C Sniffer    │ ────────────► │  FastAPI Backend        │ │  │
│  │  │               │               │                         │ │  │
│  │  │  libpcap      │               │  • Subprocess manager   │ │  │
│  │  │  pcap_loop()  │               │  • aiosqlite (SQLite)   │ │  │
│  │  │               │               │  • REST endpoints       │ │  │
│  │  │  JSON per     │               │  • WebSocket broadcaster│ │  │
│  │  │  packet +     │               │                         │ │  │
│  │  │  stats every  │               └──────────┬─────────────┘ │  │
│  │  │  N seconds    │                          │ REST + WS      │  │
│  │  └───────────────┘               ┌──────────▼─────────────┐ │  │
│  │                                  │  React Dashboard        │ │  │
│  │                                  │                         │ │  │
│  │  ┌───────────────┐               │  • Protocol pie chart   │ │  │
│  │  │  SQLite DB    │ ◄─────────────│  • Top talkers bar      │ │  │
│  │  │  (WAL mode)   │               │  • Live packet feed     │ │  │
│  │  └───────────────┘               │  • Packets/sec line     │ │  │
│  │                                  └─────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  NIC ──► kernel ring buffer ──► libpcap ──► sniffer.c             │
└────────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Kernel → C sniffer:** libpcap registers a BPF filter with the kernel, receives raw frames via `pcap_loop()` callback.
2. **C sniffer → Python backend:** Sniffer writes one JSON line per packet plus periodic stats to stdout. Parent process reads via pipe.
3. **Python backend → SQLite:** Each packet/stats record is stored in SQLite (WAL mode for concurrent read performance).
4. **Python backend → WebSocket clients:** Every packet JSON is broadcast to all connected WebSocket clients in real time.
5. **React dashboard → API:** Dashboard polls REST endpoints for historical data; listens on WebSocket for live updates.

## Design Decisions

### Decision 1: C for packet capture (not Python scapy)

**Trade-off:** Complexity vs. performance

- **Pro:** Direct libpcap access, minimal overhead, capable of 10k+ pps without dropping
- **Con:** Manual memory management, no garbage collection, harder to debug
- **Alternative considered:** Python `scapy` — significantly easier to write, but ~10x slower due to Python overhead per packet
- **Chosen because:** At high traffic rates, scapy saturates a CPU core long before C does. For a portfolio project demonstrating systems knowledge, C is also the right signal.

### Decision 2: Subprocess + JSON pipe (not ctypes/cffi)

**Trade-off:** Coupling vs. simplicity

- **Pro:** Clean process boundary — crash in C doesn't take down the Python backend; easy to restart independently
- **Con:** Slight latency overhead from JSON serialization; pipe buffering adds ~ms of delay
- **Alternative considered:** `ctypes` to call sniffer as a shared library — tighter coupling, lower latency, but a crash in C would crash the Python process
- **Chosen because:** Process isolation is more important than microsecond latency for a dashboard use case. The watchdog can restart a crashed sniffer without losing API availability.

### Decision 3: SQLite over PostgreSQL

**Trade-off:** Simplicity vs. scalability

- **Pro:** Zero extra services, ships inside the Docker image, WAL mode gives good concurrent read performance
- **Con:** Single writer, no horizontal scaling, not suitable for multi-node deployment
- **Alternative considered:** PostgreSQL — more scalable, better for large datasets, but adds operational complexity for a single-node demo
- **Chosen because:** This is a portfolio demo. SQLite with WAL mode handles thousands of inserts/sec easily on a single node.

### Decision 4: WebSocket for live feed

**Trade-off:** Connection state vs. latency

- **Pro:** Sub-100ms packet visibility in the dashboard, no polling overhead
- **Con:** Stateful connections require cleanup; doesn't work through all proxies
- **Alternative considered:** Server-Sent Events (SSE) — simpler, one-directional, but less interactive
- **Chosen because:** Bidirectional WebSocket fits better with future features (e.g., sending filter commands from dashboard to backend).

## Rolling Statistics Algorithm

The sniffer maintains a ring buffer of size 64 (seconds) to compute rolling bytes/packets-per-second:

```c
g_ring_bytes[now % RING_SIZE]   += packet.length;
g_ring_packets[now % RING_SIZE] += 1;

// At flush time:
sum_bytes   = sum(g_ring_bytes[t % RING_SIZE] for t in [now-window, now])
bytes_per_sec = sum_bytes / window
```

This gives an O(window) computation at flush time with O(RING_SIZE) memory — no sliding window list needed.

## Packet Parsing Stack

```
Raw frame (bytes)
  └─ Ethernet header (14 bytes)
       ├─ ARP (ethertype 0x0806)
       ├─ IPv4 (ethertype 0x0800)
       │    ├─ ICMP (proto 1)
       │    ├─ TCP (proto 6)
       │    │    ├─ HTTP  (port 80)  → extract Host header
       │    │    └─ HTTPS (port 443)
       │    └─ UDP (proto 17)
       │         └─ DNS (port 53) → parse query name labels
       └─ IPv6 (ethertype 0x86DD)
            └─ TCP/UDP/ICMPv6 (next header field)
```

## Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Sniffer crashes | `proc.poll() != None` in watchdog | Auto-restart within 5 seconds |
| Sniffer produces bad JSON | `json.JSONDecodeError` in reader | Log & skip line, continue |
| WebSocket client disconnects | `WebSocketDisconnect` exception | Remove from broadcast list |
| SQLite write error | Exception in `insert_packet` | Log error, packet is dropped |

## Security Considerations

- The C sniffer requires `CAP_NET_RAW` (or root). In Docker this is granted via `cap_add: NET_RAW`.
- The API has no authentication — this is a portfolio demo, not a production deployment.
- CORS is set to `allow_origins=["*"]` for development convenience.
- **Not production-hardened.** For a real deployment: add API auth, restrict CORS, run sniffer as a dedicated low-privilege user with only the network capability.

## Scaling

If this were production:

- **Multiple capture nodes:** Run N sniffer+backend instances, aggregate metrics in a shared PostgreSQL database
- **Kafka for the pipe:** Replace stdout pipe with Kafka topic for durability and fan-out
- **TimescaleDB:** Replace SQLite with TimescaleDB for time-series query performance at scale
- **Prometheus + Grafana:** Export metrics endpoint and replace the custom dashboard
