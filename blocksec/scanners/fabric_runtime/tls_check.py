"""TCP + TLS handshake detection for Fabric runtime scanning."""

import socket
import ssl
from datetime import UTC, datetime

FABRIC_DEFAULT_PORTS = {
    "peer": 7051,
    "orderer": 7050,
    "couchdb": 5984,
    "ca": 7054,
    "operations": 9443,
}


def check_tcp_connectivity(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


def check_tls_handshake(host: str, port: int, timeout: float = 5.0) -> dict:
    """Attempt TLS handshake and return certificate info."""
    result = {"reachable": False, "tls_enabled": False, "certificate": None, "error": None}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result["reachable"] = True

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                result["tls_enabled"] = True
                cert_bin = tls_sock.getpeercert(binary_form=True)
                if cert_bin:
                    from cryptography import x509

                    cert = x509.load_der_x509_certificate(cert_bin)
                    now = datetime.now(UTC)
                    result["certificate"] = {
                        "subject": str(cert.subject.rfc4514_string()),
                        "issuer": str(cert.issuer.rfc4514_string()),
                        "not_after": cert.not_valid_after_utc.isoformat(),
                        "expired": now > cert.not_valid_after_utc,
                        "days_remaining": max(0, (cert.not_valid_after_utc - now).days),
                    }
        except (ssl.SSLError, OSError) as e:
            result["error"] = str(e)
        finally:
            sock.close()
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)

    return result


def check_couchdb_accessibility(host: str, port: int = 5984, timeout: float = 3.0) -> dict:
    """Check if CouchDB is reachable on the network."""
    result = {"reachable": False, "couchdb_detected": False, "error": None}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result["reachable"] = True

        http_req = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        sock.settimeout(timeout)
        sock.sendall(http_req)
        response = sock.recv(4096)
        sock.close()

        if b"couchdb" in response.lower():
            result["couchdb_detected"] = True
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)

    return result
