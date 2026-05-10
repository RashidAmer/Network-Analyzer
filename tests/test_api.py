"""
test_api.py — basic tests for the FastAPI backend.

Run with:
    pytest tests/ -v
"""

import pytest
from httpx import AsyncClient, ASGITransport


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
async def client():
    """
    Returns an async test client.
    We import app inside the fixture to avoid starting the sniffer subprocess
    during test collection.
    """
    from src.python.app import app
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac


# ── Health check ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_endpoint(client):
    """Health endpoint should return 200 with a status field."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "sniffer_running" in data


# ── Metrics ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_metrics_endpoint(client):
    """Metrics endpoint should return expected keys."""
    response = await client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "timeseries" in data


@pytest.mark.asyncio
async def test_metrics_with_window(client):
    """Metrics endpoint accepts a window query parameter."""
    response = await client.get("/api/metrics?window=60")
    assert response.status_code == 200


# ── Flows ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flows_endpoint(client):
    """Flows endpoint should return a list."""
    response = await client.get("/api/flows")
    assert response.status_code == 200
    data = response.json()
    assert "flows" in data
    assert isinstance(data["flows"], list)


# ── Protocols ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_protocols_endpoint(client):
    """Protocols endpoint should return a protocols list and total."""
    response = await client.get("/api/protocols")
    assert response.status_code == 200
    data = response.json()
    assert "protocols" in data
    assert "total_packets" in data


# ── Top talkers ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_top_talkers_endpoint(client):
    """Top talkers endpoint should return a list."""
    response = await client.get("/api/top-talkers")
    assert response.status_code == 200
    data = response.json()
    assert "top_talkers" in data
    assert isinstance(data["top_talkers"], list)


# ── Packets ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_packets_endpoint(client):
    """Packets endpoint should return a list."""
    response = await client.get("/api/packets")
    assert response.status_code == 200
    data = response.json()
    assert "packets" in data
    assert isinstance(data["packets"], list)


@pytest.mark.asyncio
async def test_packets_protocol_filter(client):
    """Packets endpoint accepts a protocol filter."""
    response = await client.get("/api/packets?protocol=DNS")
    assert response.status_code == 200
