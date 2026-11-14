import socket
import ssl
from dataclasses import dataclass
from typing import List, Optional

MODBUS_TLS_PORT = 802
TLS_HANDSHAKE_TIMEOUT_S = 3.0

MODBUS_ECHO_PDU = (
    b"\x00\x01"
    b"\x00\x00"
    b"\x00\x06"
    b"\x01"
    b"\x03\x00\x00\x00\x01"
)


@dataclass
class TlsVariantResult:
    host: str
    port: int
    tls_port_open: bool = False
    tls_handshake_ok: bool = False
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_cert_cn: Optional[str] = None
    modbus_over_tls_responsive: Optional[bool] = None
    error: Optional[str] = None

    @property
    def any_finding(self) -> bool:
        return self.tls_port_open


def _extract_cn(cert: dict) -> Optional[str]:
    subject = cert.get("subject", ())
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def probe(host: str, port: int = MODBUS_TLS_PORT,
          timeout_s: float = TLS_HANDSHAKE_TIMEOUT_S) -> TlsVariantResult:
    result = TlsVariantResult(host=host, port=port)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout_s)
    try:
        raw.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        raw.close()
        return result

    result.tls_port_open = True

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, OSError) as exc:
        result.error = f"TLS handshake failed: {exc}"
        raw.close()
        return result

    try:
        result.tls_handshake_ok = True
        result.tls_version = tls_sock.version()
        cipher_info = tls_sock.cipher()
        result.tls_cipher = cipher_info[0] if cipher_info else None
        peer_cert = tls_sock.getpeercert()
        if peer_cert:
            result.tls_cert_cn = _extract_cn(peer_cert)

        tls_sock.settimeout(timeout_s)
        try:
            tls_sock.sendall(MODBUS_ECHO_PDU)
            resp = tls_sock.recv(256)
            result.modbus_over_tls_responsive = len(resp) >= 7
        except (socket.timeout, OSError):
            result.modbus_over_tls_responsive = False
    except (ssl.SSLError, OSError) as exc:
        result.error = f"post-handshake error: {exc}"
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass

    return result


def run(host: str, port: int = MODBUS_TLS_PORT, timeout_ms: int = 3000,
        logger=None) -> List[TlsVariantResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(f"modbus_tls_variant_check: {host}:{port}")
    return [probe(host, port, timeout_s)]
