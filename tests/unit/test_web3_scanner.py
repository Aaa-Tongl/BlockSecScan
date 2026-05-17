import os
import tempfile

from blocksec.scanners.web3.scanner import WEB3_CHECKS, Web3Scanner, _match_check


def test_web3_all_checks_have_required_keys():
    required = {"id", "severity", "pattern", "title", "desc", "remediation"}
    for check in WEB3_CHECKS:
        assert required.issubset(check.keys()), f"Check {check.get('id')} missing keys"


def test_match_private_key_hardcoded():
    check = WEB3_CHECKS[0]
    content = 'const PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe512961708279d1bf6b2c43ee8f15ab"'
    finding = _match_check("app.js", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_PRIVATE_KEY_HARDCODED"
    assert finding.severity.value == "CRITICAL"


def test_no_match_clean_code():
    check = WEB3_CHECKS[0]
    content = 'const key = process.env.PRIVATE_KEY'
    finding = _match_check("app.js", content, check)
    assert finding is None


def test_match_mnemonic():
    check = WEB3_CHECKS[1]
    content = 'const MNEMONIC = "' + "abandon " * 11 + 'about"'
    finding = _match_check("config.js", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_MNEMONIC_HARDCODED"


def test_match_infura_key():
    check = WEB3_CHECKS[2]
    content = 'const INFURA_URL = "https://mainnet.infura.io/v3/abc123def456"'
    finding = _match_check(".env", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_INFURA_KEY_LEAK"


def test_match_unlimited_approve_ethers():
    check = WEB3_CHECKS[3]
    content = "token.approve(spender, ethers.MaxUint256)"
    finding = _match_check("swap.js", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_DANGEROUS_APPROVE"


def test_match_raw_sign_message():
    check = WEB3_CHECKS[4]
    content = 'await signer.signMessage("hello")'
    finding = _match_check("auth.ts", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_RAW_SIGN_MESSAGE"


def test_match_contract_address():
    check = WEB3_CHECKS[5]
    content = 'const CONTRACT_ADDRESS = "0x1234567890123456789012345678901234567890"'
    finding = _match_check("config.js", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_CONTRACT_ADDRESS_HARDCODED"


def test_missing_csp():
    check = WEB3_CHECKS[6]
    content = "<html><head><title>No CSP</title></head></html>"
    finding = _match_check("index.html", content, check)
    assert finding is not None
    assert finding.rule_id == "WEB3_MISSING_CSP"


def test_csp_present_returns_none():
    check = WEB3_CHECKS[6]
    content = '<meta http-equiv="Content-Security-Policy" content="default-src self">'
    finding = _match_check("index.html", content, check)
    assert finding is None


def test_scanner_can_handle():
    from blocksec.models.scan import ScanTarget

    s = Web3Scanner()
    assert s.can_handle(ScanTarget(target_type="web3", path="/test"))
    assert not s.can_handle(ScanTarget(target_type="rpc", path="http://localhost"))


def test_scanner_scan_directory():
    with tempfile.TemporaryDirectory() as d:
        js_file = os.path.join(d, "app.js")
        with open(js_file, "w") as f:
            f.write('const PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe512961708279d1bf6b2c43ee8f15ab"')

        from blocksec.models.scan import ScanTarget

        s = Web3Scanner()
        findings = s.scan(ScanTarget(target_type="web3", path=d), [])
        assert len(findings) >= 1
        assert findings[0].rule_id == "WEB3_PRIVATE_KEY_HARDCODED"


def test_scanner_scan_nonexistent():
    from blocksec.models.scan import ScanTarget

    s = Web3Scanner()
    findings = s.scan(ScanTarget(target_type="web3", path="/nonexistent/path"), [])
    assert findings == []
