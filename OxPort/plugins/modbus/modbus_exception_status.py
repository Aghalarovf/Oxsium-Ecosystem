import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

FC_READ_EXCEPTION_STATUS = 0x07

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
class ExceptionStatusResult:
    host: str
    port: int
    unit_id: int
    status_byte: Optional[int] = None
    status_bits: Optional[str] = None
    exception: Optional[str] = None
    error: Optional[str] = None

    @property
    def responsive(self) -> bool:
        return self.status_byte is not None or self.exception is not None


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

    resp_len = int.from_bytes(header[4:6], "big")
    if resp_len < 2:
        raise OSError("malformed response length")

    body = recv_exact(resp_len - 1)
    if body is None or len(body) != resp_len - 1:
        raise OSError("truncated response body")

    return body[0], body[1:]


def probe(host: str, port: int, unit_id: int, timeout_s: float) -> ExceptionStatusResult:
    result = ExceptionStatusResult(host=host, port=port, unit_id=unit_id)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        sock.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        resp_fc, payload = _mbap_request(sock, unit_id, FC_READ_EXCEPTION_STATUS, b"", txn_id=1)
        exc_name = _decode_exception(resp_fc, payload)
        if exc_name:
            result.exception = exc_name
        elif payload:
            result.status_byte = payload[0]
            result.status_bits = f"{payload[0]:08b}"
    except OSError as exc:
        result.error = str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def run(host: str, port: int, unit_id: int = 1, timeout_ms: int = 2500,
        logger=None) -> List[ExceptionStatusResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(f"modbus_exception_status: FC07 {host}:{port} unit_id={unit_id}")
    return [probe(host, port, unit_id, timeout_s)]
