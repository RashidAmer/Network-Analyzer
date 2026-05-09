# API Reference

Base URL: `http://localhost:8000`

Interactive docs (Swagger UI): `http://localhost:8000/docs`

---

## Health

### `GET /health`

Returns sniffer status.

**Response**
```json
{
  "status": "ok",
  "sniffer_running": true,
  "interface": "eth0"
}
```

---

## Metrics

### `GET /api/metrics`

Aggregated traffic statistics, optionally filtered to a time window.

**Query parameters**

| Param    | Type | Default | Description                        |
|----------|------|---------|------------------------------------|
| `window` | int  | `0`     | Seconds to look back (0 = all time) |

**Example**
```bash
curl "http://localhost:8000/api/metrics?window=60"
```

**Response**
```json
{
  "metrics": {
    "total_packets": 15243,
    "total_bytes": 18204800,
    "unique_sources": 12,
    "protocols": {
      "TCP": 8200,
      "UDP": 4100,
      "DNS": 1900,
      "HTTPS": 850,
      "HTTP": 120,
      "ICMP": 73
    }
  },
  "latest_stats": {
    "bytes_per_sec": 182400.0,
    "packets_per_sec": 152.4,
    "total_packets": 15243
  },
  "timeseries": [
    { "second": 1715270400, "packet_count": 143, "byte_count": 171600 }
  ]
}
```

---

## Flows

### `GET /api/flows`

Unique network flows (src_ip → dst_ip:port) sorted by packet count.

**Query parameters**

| Param   | Type | Default | Max  |
|---------|------|---------|------|
| `limit` | int  | `100`   | 1000 |

**Example**
```bash
curl "http://localhost:8000/api/flows?limit=20"
```

**Response**
```json
{
  "flows": [
    {
      "src_ip": "192.168.1.10",
      "dst_ip": "8.8.8.8",
      "dst_port": 53,
      "protocol": "DNS",
      "packet_count": 420,
      "byte_count": 50400
    }
  ],
  "count": 1
}
```

---

## Protocols

### `GET /api/protocols`

Protocol breakdown with percentages.

**Example**
```bash
curl http://localhost:8000/api/protocols
```

**Response**
```json
{
  "protocols": [
    { "protocol": "TCP",   "count": 8200, "pct": 53.8 },
    { "protocol": "UDP",   "count": 4100, "pct": 26.9 },
    { "protocol": "DNS",   "count": 1900, "pct": 12.5 },
    { "protocol": "HTTPS", "count": 850,  "pct": 5.6  },
    { "protocol": "HTTP",  "count": 120,  "pct": 0.8  },
    { "protocol": "ICMP",  "count": 73,   "pct": 0.5  }
  ],
  "total_packets": 15243
}
```

---

## Top Talkers

### `GET /api/top-talkers`

Source IPs ranked by total bytes sent.

**Query parameters**

| Param   | Type | Default | Max |
|---------|------|---------|-----|
| `limit` | int  | `10`    | 100 |

**Example**
```bash
curl "http://localhost:8000/api/top-talkers?limit=5"
```

**Response**
```json
{
  "top_talkers": [
    {
      "src_ip": "192.168.1.5",
      "packet_count": 3200,
      "byte_count": 4096000
    }
  ]
}
```

---

## Packets

### `GET /api/packets`

Recent individual packets, optionally filtered by protocol.

**Query parameters**

| Param      | Type   | Default | Max | Description              |
|------------|--------|---------|-----|--------------------------|
| `limit`    | int    | `50`    | 500 | Number of packets        |
| `protocol` | string | `null`  | —   | Filter: TCP, UDP, DNS, … |

**Example**
```bash
curl "http://localhost:8000/api/packets?limit=10&protocol=DNS"
```

**Response**
```json
{
  "packets": [
    {
      "id": 15243,
      "ts": 1715270461.123456,
      "src_ip": "192.168.1.10",
      "dst_ip": "8.8.8.8",
      "src_mac": "aa:bb:cc:dd:ee:ff",
      "dst_mac": "11:22:33:44:55:66",
      "src_port": 54321,
      "dst_port": 53,
      "length": 74,
      "protocol": "DNS",
      "dns_query": "example.com",
      "http_host": ""
    }
  ],
  "count": 1
}
```

---

## WebSocket

### `WS /ws/live`

Real-time packet and stats stream.

**Connect**
```bash
# Using wscat
wscat -c ws://localhost:8000/ws/live
```

**Message types**

#### Packet event
```json
{
  "type": "packet",
  "timestamp": 1715270461.123456,
  "src_ip": "192.168.1.10",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 53,
  "length": 74,
  "protocol": "DNS",
  "dns_query": "example.com",
  "http_host": ""
}
```

#### Stats event (every N seconds)
```json
{
  "type": "stats",
  "timestamp": 1715270465.0,
  "total_packets": 15243,
  "total_bytes": 18204800,
  "bytes_per_sec": 182400.0,
  "packets_per_sec": 152.4,
  "tcp_count": 8200, "tcp_pct": 53.8,
  "udp_count": 4100, "udp_pct": 26.9,
  "dns_count": 1900, "dns_pct": 12.5,
  "http_count": 120,  "http_pct": 0.8,
  "https_count": 850, "https_pct": 5.6,
  "icmp_count": 73,   "icmp_pct": 0.5,
  "other_count": 0,   "other_pct": 0.0
}
```
