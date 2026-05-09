/*
 * sniffer.c — libpcap-based network packet sniffer
 *
 * Outputs one JSON line per packet to stdout:
 *   {"type":"packet", "timestamp":..., "src_ip":..., ...}
 *
 * Also outputs aggregated stats every flush_interval seconds:
 *   {"type":"stats", "total_packets":..., "bytes_per_sec":..., ...}
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o sniffer sniffer.c -lpcap
 *
 * Usage:
 *   sudo ./sniffer [interface] [flush_interval_sec] [rolling_window_sec]
 *   sudo ./sniffer any 5 10
 */

#include "sniffer.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

/* ── Globals ──────────────────────────────────────────────────────────── */
static volatile int    g_running      = 1;
static pcap_t         *g_handle       = NULL;
static Stats           g_stats        = {0};
static int             g_flush_sec    = 5;
static int             g_rolling_sec  = 10;

/* Rolling window ring buffer for per-second byte counts */
#define RING_SIZE 64
static uint64_t g_ring_bytes[RING_SIZE]   = {0};
static uint64_t g_ring_packets[RING_SIZE] = {0};
static time_t   g_last_flush             = 0;
static time_t   g_ring_start             = 0;

/* ── Signal handler ───────────────────────────────────────────────────── */
void sniffer_stop(void) {
    g_running = 0;
    if (g_handle) pcap_breakloop(g_handle);
}

static void handle_signal(int sig) {
    (void)sig;
    sniffer_stop();
}

/* ── Helpers ──────────────────────────────────────────────────────────── */
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void escape_json_string(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
        }
        if (j < out_size - 1) out[j++] = (char)c;
    }
    out[j] = '\0';
}

static const char *proto_to_str(int proto) {
    switch (proto) {
        case PROTO_TCP:   return "TCP";
        case PROTO_UDP:   return "UDP";
        case PROTO_DNS:   return "DNS";
        case PROTO_HTTP:  return "HTTP";
        case PROTO_HTTPS: return "HTTPS";
        case PROTO_ICMP:  return "ICMP";
        case PROTO_ARP:   return "ARP";
        default:          return "OTHER";
    }
}

/* ── Stats output ─────────────────────────────────────────────────────── */
static void flush_stats(void) {
    /* Compute rolling averages */
    time_t now = time(NULL);
    int    elapsed = (int)(now - g_ring_start);
    int    window  = elapsed < g_rolling_sec ? elapsed : g_rolling_sec;

    uint64_t ring_bytes   = 0;
    uint64_t ring_packets = 0;
    for (int i = 0; i < window && i < RING_SIZE; i++) {
        int idx = (int)((now - i) % RING_SIZE);
        if (idx < 0) idx += RING_SIZE;
        ring_bytes   += g_ring_bytes[idx];
        ring_packets += g_ring_packets[idx];
    }

    double bps = window > 0 ? (double)ring_bytes   / window : 0.0;
    double pps = window > 0 ? (double)ring_packets / window : 0.0;

    uint64_t total = g_stats.total_packets;
    double   pct_tcp   = total ? 100.0 * g_stats.tcp_count   / total : 0;
    double   pct_udp   = total ? 100.0 * g_stats.udp_count   / total : 0;
    double   pct_dns   = total ? 100.0 * g_stats.dns_count   / total : 0;
    double   pct_http  = total ? 100.0 * g_stats.http_count  / total : 0;
    double   pct_https = total ? 100.0 * g_stats.https_count / total : 0;
    double   pct_icmp  = total ? 100.0 * g_stats.icmp_count  / total : 0;
    double   pct_other = total ? 100.0 * g_stats.other_count / total : 0;

    printf("{\"type\":\"stats\","
           "\"timestamp\":%.3f,"
           "\"total_packets\":%llu,"
           "\"total_bytes\":%llu,"
           "\"bytes_per_sec\":%.2f,"
           "\"packets_per_sec\":%.2f,"
           "\"tcp_count\":%llu,\"tcp_pct\":%.1f,"
           "\"udp_count\":%llu,\"udp_pct\":%.1f,"
           "\"dns_count\":%llu,\"dns_pct\":%.1f,"
           "\"http_count\":%llu,\"http_pct\":%.1f,"
           "\"https_count\":%llu,\"https_pct\":%.1f,"
           "\"icmp_count\":%llu,\"icmp_pct\":%.1f,"
           "\"other_count\":%llu,\"other_pct\":%.1f}\n",
           now_seconds(),
           (unsigned long long)g_stats.total_packets,
           (unsigned long long)g_stats.total_bytes,
           bps, pps,
           (unsigned long long)g_stats.tcp_count,   pct_tcp,
           (unsigned long long)g_stats.udp_count,   pct_udp,
           (unsigned long long)g_stats.dns_count,   pct_dns,
           (unsigned long long)g_stats.http_count,  pct_http,
           (unsigned long long)g_stats.https_count, pct_https,
           (unsigned long long)g_stats.icmp_count,  pct_icmp,
           (unsigned long long)g_stats.other_count, pct_other);
    fflush(stdout);
}

/* ── DNS query parser (minimal) ───────────────────────────────────────── */
static void parse_dns_query(const uint8_t *dns_payload, size_t len,
                            char *out, size_t out_size) {
    if (len < 12) { out[0] = '\0'; return; }

    const uint8_t *p   = dns_payload + 12; /* skip DNS header */
    const uint8_t *end = dns_payload + len;
    size_t j = 0;

    while (p < end) {
        uint8_t label_len = *p++;
        if (label_len == 0) break;
        if (p + label_len > end) break;
        if (j > 0 && j < out_size - 1) out[j++] = '.';
        for (uint8_t i = 0; i < label_len && j < out_size - 1; i++) {
            out[j++] = (char)*p++;
        }
    }
    out[j] = '\0';
}

/* ── Packet callback ──────────────────────────────────────────────────── */
static void packet_handler(uint8_t *user,
                            const struct pcap_pkthdr *pkthdr,
                            const uint8_t *packet) {
    (void)user;
    if (!g_running) return;

    PacketSummary ps;
    memset(&ps, 0, sizeof(ps));

    ps.timestamp = (double)pkthdr->ts.tv_sec +
                   (double)pkthdr->ts.tv_usec / 1e6;
    ps.length    = pkthdr->len;

    /* Update rolling ring buffer */
    time_t now_t = (time_t)pkthdr->ts.tv_sec;
    int    idx   = (int)(now_t % RING_SIZE);
    if (idx < 0) idx += RING_SIZE;
    g_ring_bytes[idx]   += pkthdr->len;
    g_ring_packets[idx] += 1;

    /* ── Ethernet header ── */
    if (pkthdr->caplen < sizeof(struct ether_header)) goto emit;
    const struct ether_header *eth = (const struct ether_header *)packet;
    snprintf(ps.src_mac, sizeof(ps.src_mac),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    snprintf(ps.dst_mac, sizeof(ps.dst_mac),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    uint16_t ether_type = ntohs(eth->ether_type);

    /* ── ARP ── */
    if (ether_type == ETHERTYPE_ARP) {
        ps.protocol = PROTO_ARP;
        g_stats.other_count++;
        goto emit;
    }

    /* ── IPv4 ── */
    const uint8_t *ip_start = packet + sizeof(struct ether_header);
    size_t         ip_avail = pkthdr->caplen - sizeof(struct ether_header);

    if (ether_type == ETHERTYPE_IP) {
        if (ip_avail < sizeof(struct ip)) goto emit;
        const struct ip *iph = (const struct ip *)ip_start;
        inet_ntop(AF_INET, &iph->ip_src, ps.src_ip, sizeof(ps.src_ip));
        inet_ntop(AF_INET, &iph->ip_dst, ps.dst_ip, sizeof(ps.dst_ip));

        size_t ip_hdr_len = (size_t)(iph->ip_hl) * 4;
        const uint8_t *transport = ip_start + ip_hdr_len;
        size_t         transport_avail = ip_avail - ip_hdr_len;

        if (iph->ip_p == IPPROTO_ICMP) {
            ps.protocol = PROTO_ICMP;
            g_stats.icmp_count++;

        } else if (iph->ip_p == IPPROTO_TCP) {
            if (transport_avail < sizeof(struct tcphdr)) goto emit;
            const struct tcphdr *tcph = (const struct tcphdr *)transport;
            ps.src_port = ntohs(tcph->th_sport);
            ps.dst_port = ntohs(tcph->th_dport);

            if (ps.dst_port == 443 || ps.src_port == 443) {
                ps.protocol = PROTO_HTTPS;
                g_stats.https_count++;
            } else if (ps.dst_port == 80 || ps.src_port == 80) {
                ps.protocol = PROTO_HTTP;
                g_stats.http_count++;

                /* Try to extract HTTP Host header */
                size_t tcp_hdr_len = (size_t)(tcph->th_off) * 4;
                const uint8_t *payload = transport + tcp_hdr_len;
                size_t payload_len     = transport_avail - tcp_hdr_len;
                if (payload_len > 4 &&
                    (memcmp(payload, "GET ", 4) == 0 ||
                     memcmp(payload, "POST", 4) == 0 ||
                     memcmp(payload, "HEAD", 4) == 0)) {
                    const char *host_hdr = "Host: ";
                    const char *p = (const char *)payload;
                    const char *found = strstr(p, host_hdr);
                    if (found) {
                        found += strlen(host_hdr);
                        size_t i = 0;
                        while (found[i] && found[i] != '\r' && found[i] != '\n'
                               && i < sizeof(ps.http_host) - 1) {
                            ps.http_host[i] = found[i];
                            i++;
                        }
                        ps.http_host[i] = '\0';
                    }
                }
            } else {
                ps.protocol = PROTO_TCP;
                g_stats.tcp_count++;
            }

        } else if (iph->ip_p == IPPROTO_UDP) {
            if (transport_avail < sizeof(struct udphdr)) goto emit;
            const struct udphdr *udph = (const struct udphdr *)transport;
            ps.src_port = ntohs(udph->uh_sport);
            ps.dst_port = ntohs(udph->uh_dport);

            if (ps.dst_port == 53 || ps.src_port == 53) {
                ps.protocol = PROTO_DNS;
                g_stats.dns_count++;

                /* Parse DNS query name */
                const uint8_t *dns_payload = transport + sizeof(struct udphdr);
                size_t dns_len = transport_avail - sizeof(struct udphdr);
                parse_dns_query(dns_payload, dns_len,
                                ps.dns_query, sizeof(ps.dns_query));
            } else {
                ps.protocol = PROTO_UDP;
                g_stats.udp_count++;
            }
        } else {
            g_stats.other_count++;
        }

    } else if (ether_type == ETHERTYPE_IPV6) {
        if (ip_avail < sizeof(struct ip6_hdr)) goto emit;
        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)ip_start;
        inet_ntop(AF_INET6, &ip6h->ip6_src, ps.src_ip, sizeof(ps.src_ip));
        inet_ntop(AF_INET6, &ip6h->ip6_dst, ps.dst_ip, sizeof(ps.dst_ip));
        /* Simplified: classify by next header only */
        if (ip6h->ip6_nxt == IPPROTO_TCP)       ps.protocol = PROTO_TCP;
        else if (ip6h->ip6_nxt == IPPROTO_UDP)  ps.protocol = PROTO_UDP;
        else if (ip6h->ip6_nxt == IPPROTO_ICMPV6) ps.protocol = PROTO_ICMP;
        else                                     ps.protocol = PROTO_OTHER;
        g_stats.other_count++;  /* counted under 'other' for IPv6 simplicity */
    } else {
        g_stats.other_count++;
    }

emit:
    /* Update totals */
    g_stats.total_packets++;
    g_stats.total_bytes += pkthdr->len;
    strncpy(ps.protocol_str, proto_to_str(ps.protocol),
            sizeof(ps.protocol_str) - 1);

    /* Emit packet JSON */
    char esc_dns[512], esc_host[512];
    escape_json_string(ps.dns_query,  esc_dns,  sizeof(esc_dns));
    escape_json_string(ps.http_host,  esc_host, sizeof(esc_host));

    printf("{\"type\":\"packet\","
           "\"timestamp\":%.6f,"
           "\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
           "\"src_mac\":\"%s\",\"dst_mac\":\"%s\","
           "\"src_port\":%d,\"dst_port\":%d,"
           "\"length\":%u,"
           "\"protocol\":\"%s\","
           "\"dns_query\":\"%s\","
           "\"http_host\":\"%s\"}\n",
           ps.timestamp,
           ps.src_ip, ps.dst_ip,
           ps.src_mac, ps.dst_mac,
           ps.src_port, ps.dst_port,
           ps.length,
           ps.protocol_str,
           esc_dns,
           esc_host);
    fflush(stdout);

    /* Periodic stats flush */
    time_t cur = time(NULL);
    if (cur - g_last_flush >= g_flush_sec) {
        flush_stats();
        g_last_flush = cur;
    }
}

/* ── Main capture loop ────────────────────────────────────────────────── */
int sniffer_start(const char *interface,
                  int flush_interval_sec,
                  int rolling_window_sec) {
    char errbuf[PCAP_ERRBUF_SIZE];

    g_flush_sec   = flush_interval_sec  > 0 ? flush_interval_sec  : 5;
    g_rolling_sec = rolling_window_sec  > 0 ? rolling_window_sec  : 10;
    g_ring_start  = time(NULL);
    g_last_flush  = g_ring_start;

    /* Open capture device */
    g_handle = pcap_open_live(interface,
                              65536,  /* snaplen: full packet */
                              1,      /* promiscuous mode */
                              100,    /* read timeout ms */
                              errbuf);
    if (!g_handle) {
        fprintf(stderr, "{\"type\":\"error\",\"msg\":\"pcap_open_live: %s\"}\n",
                errbuf);
        return -1;
    }

    /* Emit ready signal so Python backend knows we're up */
    fprintf(stdout, "{\"type\":\"ready\",\"interface\":\"%s\"}\n", interface);
    fflush(stdout);

    /* Capture loop */
    pcap_loop(g_handle, 0, packet_handler, NULL);

    pcap_close(g_handle);
    g_handle = NULL;

    /* Final stats flush on shutdown */
    flush_stats();
    fprintf(stdout, "{\"type\":\"shutdown\"}\n");
    fflush(stdout);

    return 0;
}

/* ── Entry point ──────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    const char *iface   = (argc > 1) ? argv[1] : "any";
    int flush_sec       = (argc > 2) ? atoi(argv[2]) : 5;
    int rolling_sec     = (argc > 3) ? atoi(argv[3]) : 10;

    return sniffer_start(iface, flush_sec, rolling_sec);
}
