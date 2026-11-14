import socket
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

FC_DIAGNOSTICS = 0x08
SUBFUNC_RETURN_QUERY_DATA = 0x0000
ECHO_PAYLOAD = b"\xAB\xCD"

EXCEPTION_CODES = {
    1: "ILLEGAL FUNCTION",
    2: "ILLEGAL DATA ADDRESS",
    3: "ILLEGAL DATA VALUE",
    4: "SLAVE DEVICE FAILURE",
    5: "ACKNOWLEDGE",
    6: "SLAVE DEVICE BUSY",
    7: "NEGATIVE ACKNOWLEDGE",
    8: "MEMORY PARITY ERROR",
    10: "GATEWAY PATH UNAVAILABLE",
    11: "GATEWAY TARGET DEVICE FAILED TO RESPOND",
}


@dataclass
class DiagnosticsResult:
    host: str
    port: int
    unit_id: int
    echo_matched: Optional[bool] = None
    echo_sent_hex: Optional[str] = None
    echo_received_hex: Optional[str] = None
    exception: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None

    @property
    def responsive(self) -> bool:
        return self.echo_matched is not None or self.exception is not None


def _decode_exception(resp_fc: int, payload: bytes) -> Optional[str]:
    if resp_fc & 0x80:
        code = payload[0] if payload else None
        if code is None:
            return "UNKNOWN(no code)"
        return EXCEPTION_CODES.get(code, f"UNKNOWN({code})")
    return None


def _mbap_request(sock: socket.socket, unit_id: int, function_code: int,
                  data: bytes, txn_id: int) -> Tuple[int, bytes]:
    pdu = bytes([function_code]) + data
    length = len(pdu) + 1
    mbap = (
        txn_id.to_bytes(2, "big")
        + b"\x00\x00"
        + length.to_bytes(2, "big")
        + bytes([unit_id])
    )
    sock.sendall(mbap + pdu)

    def recv_exact(n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    header = recv_exact(7)
    if header is None:
        raise OSError("no response (connection closed or timeout)")

    resp_txn = int.from_bytes(header[0:2], "big")
    proto_id = int.from_bytes(header[2:4], "big")
    resp_len = int.from_bytes(header[4:6], "big")

    if proto_id != 0x0000:
        raise OSError(f"unexpected protocol id 0x{proto_id:04x}")
    if resp_txn != txn_id:
        raise OSError(f"transaction id mismatch (sent {txn_id}, got {resp_txn})")
    if resp_len < 2:
        raise OSError("malformed response length")

    body = recv_exact(resp_len - 1)
    if body is None or len(body) != resp_len - 1:
        raise OSError("truncated response body")

    return body[0], body[1:]


def probe(host: str, port: int, unit_id: int, timeout_s: float) -> DiagnosticsResult:
    result = DiagnosticsResult(host=host, port=port, unit_id=unit_id)
    result.echo_sent_hex = ECHO_PAYLOAD.hex()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        sock.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        data = SUBFUNC_RETURN_QUERY_DATA.to_bytes(2, "big") + ECHO_PAYLOAD
        t0 = time.monotonic()
        resp_fc, payload = _mbap_request(sock, unit_id, FC_DIAGNOSTICS, data, txn_id=1)
        result.latency_ms = (time.monotonic() - t0) * 1000.0

        exc_name = _decode_exception(resp_fc, payload)
        if exc_name:
            result.exception = exc_name
            return result

        echoed = payload[2:] if len(payload) >= 2 else b""
        result.echo_received_hex = echoed.hex()
        result.echo_matched = (echoed == ECHO_PAYLOAD)
    except OSError as exc:
        result.error = str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def run(host: str, port: int, unit_id: int = 1, timeout_ms: int = 2500,
        logger=None) -> List[DiagnosticsResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(f"modbus_diagnostics: echo test {host}:{port} unit_id={unit_id}")
    return [probe(host, port, unit_id, timeout_s)]
