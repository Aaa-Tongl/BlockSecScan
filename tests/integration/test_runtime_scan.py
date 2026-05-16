"""Integration tests for runtime scanner. Requires Docker to be running."""

import pytest

from blocksec.api.public import scan
from blocksec.models.scan import ScanTarget
from blocksec.scanners.fabric_runtime.docker_check import get_docker_client, get_fabric_containers


def test_docker_client_available():
    client = get_docker_client()
    if client is None:
        pytest.skip("Docker not available")
    assert client.ping()


def test_get_fabric_containers():
    client = get_docker_client()
    if client is None:
        pytest.skip("Docker not available")
    containers = get_fabric_containers(client)
    assert isinstance(containers, list)


def test_runtime_scan_local():
    client = get_docker_client()
    if client is None:
        pytest.skip("Docker not available")

    target = ScanTarget(target_type="fabric_runtime", path="local", options={"local": True})
    result = scan(target)
    assert result.target.target_type == "fabric_runtime"
    assert result.scan_id
    assert result.summary.total >= 0
