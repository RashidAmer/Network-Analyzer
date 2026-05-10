"""
database.py — async SQLite helpers for network-analyzer backend.

Schema
------
packets     : raw per-packet records (capped at MAX_PACKETS rows)
stats       : periodic aggregated snapshots from the sniffer
flows       : (src_ip, dst_ip, dst_port, protocol) aggregation
top_talkers : per-source-IP byte/packet totals
"""

import os
import aiosqlite
from contextlib import asynccontextmanager
from pathlib import Path

DB_PATH    = os.getenv("DB_PATH", "./data/metrics.db")
MAX_PACKETS = 50_000   # rolling cap — older rows pruned automatically


@asynccontextmanager
async def get_db():
    """Async context manager that yields a configured aiosqlite connection."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        yield db


async def init_db():
    async with get_db() as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS packets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL    NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                src_mac     TEXT,
                dst_mac     TEXT,
                src_port    INTEGER,
                dst_port    INTEGER,
                length      INTEGER,
                protocol    TEXT,
                dns_query   TEXT,
                http_host   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_packets_ts       ON packets(ts);
            CREATE INDEX IF NOT EXISTS idx_packets_src_ip   ON packets(src_ip);
            CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);

            CREATE TABLE IF NOT EXISTS stats_snapshots (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts              REAL    NOT NULL,
                total_packets   INTEGER,
                total_bytes     INTEGER,
                bytes_per_sec   REAL,
                packets_per_sec REAL,
                tcp_count       INTEGER,
                udp_count       INTEGER,
                dns_count       INTEGER,
                http_count      INTEGER,
                https_count     INTEGER,
                icmp_count      INTEGER,
                other_count     INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats_snapshots(ts);
        """)
        await db.commit()


async def insert_packet(db: aiosqlite.Connection, pkt: dict):
    await db.execute("""
        INSERT INTO packets
            (ts, src_ip, dst_ip, src_mac, dst_mac,
             src_port, dst_port, length, protocol, dns_query, http_host)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        pkt.get("timestamp"), pkt.get("src_ip"), pkt.get("dst_ip"),
        pkt.get("src_mac"),   pkt.get("dst_mac"),
        pkt.get("src_port"),  pkt.get("dst_port"),
        pkt.get("length"),    pkt.get("protocol"),
        pkt.get("dns_query"), pkt.get("http_host"),
    ))

    # Prune oldest rows when we exceed the cap
    await db.execute(f"""
        DELETE FROM packets WHERE id IN (
            SELECT id FROM packets ORDER BY id ASC
            LIMIT MAX(0, (SELECT COUNT(*) FROM packets) - {MAX_PACKETS})
        )
    """)


async def insert_stats(db: aiosqlite.Connection, s: dict):
    await db.execute("""
        INSERT INTO stats_snapshots
            (ts, total_packets, total_bytes, bytes_per_sec, packets_per_sec,
             tcp_count, udp_count, dns_count, http_count, https_count,
             icmp_count, other_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        s.get("timestamp"),       s.get("total_packets"),
        s.get("total_bytes"),     s.get("bytes_per_sec"),
        s.get("packets_per_sec"), s.get("tcp_count"),
        s.get("udp_count"),       s.get("dns_count"),
        s.get("http_count"),      s.get("https_count"),
        s.get("icmp_count"),      s.get("other_count"),
    ))


async def query_metrics(db: aiosqlite.Connection, window: int = 0) -> dict:
    """
    Return aggregated metrics.
    window=0  → all time
    window=60 → last 60 seconds
    """
    where = f"WHERE ts >= strftime('%s','now') - {window}" if window else ""
    async with db.execute(f"""
        SELECT
            COUNT(*)          AS total_packets,
            SUM(length)       AS total_bytes,
            COUNT(DISTINCT src_ip) AS unique_sources
        FROM packets {where}
    """) as cur:
        row = await cur.fetchone()
        metrics = dict(row) if row else {}

    # Protocol breakdown
    async with db.execute(f"""
        SELECT protocol, COUNT(*) AS cnt
        FROM packets {where}
        GROUP BY protocol
    """) as cur:
        rows = await cur.fetchall()
        metrics["protocols"] = {r["protocol"]: r["cnt"] for r in rows}

    return metrics


async def query_flows(db: aiosqlite.Connection, limit: int = 100) -> list:
    async with db.execute("""
        SELECT src_ip, dst_ip, dst_port, protocol,
               COUNT(*)   AS packet_count,
               SUM(length) AS byte_count
        FROM packets
        GROUP BY src_ip, dst_ip, dst_port, protocol
        ORDER BY packet_count DESC
        LIMIT ?
    """, (limit,)) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def query_top_talkers(db: aiosqlite.Connection, limit: int = 10) -> list:
    async with db.execute("""
        SELECT src_ip,
               COUNT(*)    AS packet_count,
               SUM(length) AS byte_count
        FROM packets
        WHERE src_ip != '' AND src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY byte_count DESC
        LIMIT ?
    """, (limit,)) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def query_recent_packets(db: aiosqlite.Connection, limit: int = 50,
                               protocol: str = None) -> list:
    if protocol:
        async with db.execute("""
            SELECT * FROM packets WHERE protocol = ?
            ORDER BY ts DESC LIMIT ?
        """, (protocol.upper(), limit)) as cur:
            return [dict(r) for r in await cur.fetchall()]
    else:
        async with db.execute("""
            SELECT * FROM packets ORDER BY ts DESC LIMIT ?
        """, (limit,)) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def query_timeseries(db: aiosqlite.Connection,
                           seconds: int = 60) -> list:
    """Return per-second packet/byte counts for the last `seconds` seconds."""
    async with db.execute("""
        SELECT
            CAST(ts AS INTEGER) AS second,
            COUNT(*)            AS packet_count,
            SUM(length)         AS byte_count
        FROM packets
        WHERE ts >= strftime('%s','now') - ?
        GROUP BY second
        ORDER BY second ASC
    """, (seconds,)) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def query_latest_stats(db: aiosqlite.Connection) -> dict:
    async with db.execute("""
        SELECT * FROM stats_snapshots ORDER BY ts DESC LIMIT 1
    """) as cur:
        row = await cur.fetchone()
        return dict(row) if row else {}
