# Network Traffic Analyzer

> Real-time network packet capture, protocol parsing, and traffic visualization — built with C + libpcap, FastAPI, and React.

**Status:** Active development &nbsp;|&nbsp; **License:** MIT &nbsp;|&nbsp; **Author:** [RashidAmer](https://github.com/RashidAmer)

---

## Overview

This project captures raw network packets at the system level using a C/libpcap sniffer, parses them by protocol layer (Ethernet → IP → TCP/UDP → DNS/HTTP), aggregates statistics, and streams them to a React dashboard in real time via WebSockets.

It was built to demonstrate:
- **Systems programming** — low-level packet capture in C, protocol dissection, rolling statistics
- **Backend engineering** — async Python API, SQLite persistence, WebSocket broadcasting
- **Full-stack delivery** — containerized with Docker, one-command local setup

## Features

- Packet capture on any network interface using libpcap (promiscuous mode)
- Protocol identification: TCP, UDP, DNS, HTTP, HTTPS, ICMP, ARP
- DNS query name extraction and HTTP Host header parsing
- Rolling 10-second bytes/packets-per-second calculation
- Top talkers by byte volume (source IP ranking)
- Network flow aggregation (src IP → dst IP:port pairs)
- Live WebSocket stream for real-time dashboard updates
- SQLite persistence (survives backend restarts)
- Auto-restart if sniffer subprocess crashes

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Linux host (packet sniffing requires `NET_RAW` capability)

### One-command setup

```bash
git clone https://github.com/RashidAmer/network-analyzer.git
cd network-analyzer

cp .env.example .env          # optional: set INTERFACE=eth0

docker-compose up
```

| Service   | URL                        |
|-----------|---------------------------|
| Dashboard | http://localhost:3000      |
| API       | http://localhost:8000      |
| API docs  | http://localhost:8000/docs |

### Development setup (without Docker)

```bash
# 1. Compile the C sniffer
cd src/c
sudo apt install libpcap-dev   # Debian/Ubuntu
make
cd ../..

# 2. Install Python dependencies
cd src/python
pip install -r requirements.txt

# 3. Start the backend (needs root for packet capture)
sudo uvicorn app:app --reload --port 8000

# 4. Start the frontend
cd src/frontend
npm install && npm start
```

## Architecture

```
┌─────────────┐   JSON lines   ┌──────────────────┐   REST/WS   ┌──────────────┐
│  C Sniffer  │ ─────────────► │  FastAPI Backend  │ ──────────► │ React Dashboard│
│  (libpcap)  │   (stdout)     │  + SQLite DB      │             │  (Recharts)   │
└─────────────┘                └──────────────────┘             └──────────────┘
```

The C sniffer runs as a child process of the Python backend. It writes one JSON line per packet to stdout and periodic aggregated stats every N seconds. The backend reads this stream, stores records in SQLite, and broadcasts to all connected WebSocket clients.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design decisions and trade-offs.

## Tech Stack

| Layer       | Technology              | Why                                      |
|-------------|------------------------|------------------------------------------|
| Capture     | C + libpcap             | Direct kernel access, zero overhead      |
| Backend     | Python 3.11 + FastAPI   | Async WebSocket support, clean API       |
| Database    | SQLite + aiosqlite      | Zero-config, sufficient for single-node  |
| Frontend    | React 18 + Recharts     | Interactive real-time charts             |
| Deployment  | Docker + Compose        | Reproducible, one-command setup          |

## API

See [docs/API.md](docs/API.md) for full endpoint reference.

```bash
# Current traffic metrics
curl http://localhost:8000/api/metrics

# Top 10 source IPs by byte volume
curl http://localhost:8000/api/top-talkers?limit=10

# Protocol breakdown
curl http://localhost:8000/api/protocols

# Live WebSocket stream
wscat -c ws://localhost:8000/ws/live
```

## Performance

Target: capture 10,000+ packets/second without dropping packets.

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for detailed results.

## Testing

```bash
# Python tests
pytest tests/ -v

# C unit tests
cd src/c && make test
```

## What I Learned

- How libpcap hooks into the kernel packet capture path and what promiscuous mode actually does at the hardware level
- The complexity of protocol dissection — especially DNS label compression and variable-length IP/TCP headers
- How to bridge a C subprocess with an async Python event loop cleanly (stdout pipe + asyncio executor)

## Future Enhancements

- [ ] IPv6 TCP/UDP port parsing (currently classified as "other")
- [ ] GeoIP enrichment for source/destination IPs
- [ ] Prometheus metrics export endpoint
- [ ] Packet capture to PCAP file for offline analysis
- [ ] Alert rules (e.g., notify when a source exceeds X bytes/sec)

## License

MIT — see [LICENSE](LICENSE)

## Contact

Questions or feedback? Open an issue or reach out at amerrashid755@gmail.com
