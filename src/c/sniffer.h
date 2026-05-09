#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>

/* ── Protocol constants ───────────────────────────────────────────────── */
#define PROTO_OTHER   0
#define PROTO_TCP     1
#define PROTO_UDP     2
#define PROTO_DNS     3
#define PROTO_HTTP    4
#define PROTO_HTTPS   5
#define PROTO_ICMP    6
#define PROTO_ARP     7

#define MAX_IP_STR    40   /* enough for IPv6 */
#define MAX_FLOWS     4096
#define MAX_TALKERS   256
#define ROLLING_SECS  10

/* ── Per-packet summary (written to stdout as JSON) ───────────────────── */
typedef struct {
    double    timestamp;
    char      src_ip[MAX_IP_STR];
    char      dst_ip[MAX_IP_STR];
    char      src_mac[18];
    char      dst_mac[18];
    uint16_t  src_port;
    uint16_t  dst_port;
    uint32_t  length;          /* bytes */
    int       protocol;        /* PROTO_* constant */
    char      protocol_str[16];
    char      dns_query[256];  /* only if DNS */
    int       http_method;     /* 1=GET,2=POST,etc.; 0 if not HTTP */
    char      http_host[256];  /* only if HTTP */
} PacketSummary;

/* ── Aggregated statistics (flushed periodically) ─────────────────────── */
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    double   bytes_per_sec;     /* rolling ROLLING_SECS-second window */
    double   packets_per_sec;

    /* Protocol counts */
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t dns_count;
    uint64_t http_count;
    uint64_t https_count;
    uint64_t icmp_count;
    uint64_t other_count;
} Stats;

/* ── Public API ───────────────────────────────────────────────────────── */

/**
 * Start capturing on the given interface.
 * Outputs one JSON line per packet to stdout.
 * Also writes a "stats" JSON line every flush_interval_sec seconds.
 *
 * @param interface       Network interface name (e.g. "eth0", "any")
 * @param flush_interval  How often (seconds) to print aggregated stats
 * @param rolling_window  Window (seconds) for bytes/packets-per-second
 * @return                0 on clean shutdown, -1 on error
 */
int sniffer_start(const char *interface,
                  int flush_interval_sec,
                  int rolling_window_sec);

/**
 * Signal the sniffer to stop cleanly.
 * Safe to call from a signal handler.
 */
void sniffer_stop(void);

#endif /* SNIFFER_H */
