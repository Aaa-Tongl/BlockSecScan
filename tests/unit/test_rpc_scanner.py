from blocksec.scanners.rpc.rpc_client import check_cors, check_tls
from blocksec.scanners.rpc.scanner import RpcScanner, _remediation


def test_remediation_known():
    assert "Disable admin namespace" in _remediation("rpc_admin_nodeInfo")
    assert "Disable personal namespace" in _remediation("rpc_personal_listAccounts")


def test_remediation_unknown():
    assert "Restrict RPC" in _remediation("some_unknown_check")


def test_scanner_can_handle():
    from blocksec.models.scan import ScanTarget

    s = RpcScanner()
    assert s.can_handle(ScanTarget(target_type="rpc", path="http://localhost:8545"))
    assert not s.can_handle(ScanTarget(target_type="web3", path="/test"))


def test_scanner_scan_invalid_url_returns_empty():
    from blocksec.models.scan import ScanTarget

    s = RpcScanner()
    result = s.scan(ScanTarget(target_type="rpc", path="http://127.0.0.1:19999"), [])
    # unreachable port may return findings about version not exposed but shouldn't crash
    assert isinstance(result, list)


def test_cors_check_invalid_url():
    result = check_cors("http://127.0.0.1:19999")
    assert result is None


def test_tls_check_invalid_host():
    result = check_tls("127.0.0.1", 19999)
    assert result["tls"] is False
