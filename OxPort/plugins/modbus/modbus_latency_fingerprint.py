import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

FC_DIAGNOSTICS = 0x08
SUBFUNC_ECHO = 0x0000
ECHO_PAYLOAD = b"\xBE\xEF"
SAMPLE_COUNT = 5

EXCEPTION_CODES = {
    1: "ILLEGAL FUNCTION",
    2: "ILLEGAL DATA ADDRESS",
    3: "ILLEGAL DATA VALUE",
    4: "SLAVE DEVICE FAILURE",
}


@dataclass
class LatencyFingerprintResult:
    host: str
    port: int
    unit_id: int
    samples_ms: List[float] = field(default_factory=list)
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    echo_consistent: Optional[bool] = None
    error: Optional[str] = None

    @property
    def responsive(self) -> bool:
        return bool(self.samples_ms)


def _decode_exception(resp_fc: int, payload: bytes) -> Optional[str]:
    if resp_fc & 0x80:
        code = payload[0] if payload else None
        if code is None:
            return "UNKNOWN(no code)"
        return EXCEPTION_CODES.get(code, f"UNKNOWN({code})")
    return None


class _Session:
    def __init__(self, host: str, port: int, timeout_s: float):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout_s)
        self.sock.connect((host, port))
        self._txn = 0

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def request(self, unit_id: int, fc: int, data: bytes) -> Tuple[int, bytes]:
        self._txn = (self._txn + 1) % 0xFFFF
        pdu = bytes([fc]) + data
        length = len(pdu) + 1
        mbap = (
            self._txn.to_bytes(2, "big")
            + b"\x00\x00"
            + length.to_bytes(2, "big")
            + bytes([unit_id])
        )
        self.sock.sendall(mbap + pdu)

        header = self._recv(7)
        if header is None:
            raise OSError("no response")
        resp_len = int.from_bytes(header[4:6], "big")
        if resp_len < 2:
            raise OSError("malformed length")
        body = self._recv(resp_len - 1)
        if body is None or len(body) != resp_len - 1:
            raise OSError("truncated body")
        return body[0], body[1:]

    def _recv(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf


def probe(host: str, port: int, unit_id: int, timeout_s: float,
          sample_count: int = SAMPLE_COUNT) -> LatencyFingerprintResult:
    result = LatencyFingerprintResult(host=host, port=port, unit_id=unit_id)
    echo_ok_count = 0

    try:
        session = _Session(host, port, timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        for _ in range(sample_count):
            data = SUBFUNC_ECHO.to_bytes(2, "big") + ECHO_PAYLOAD
            try:
                t0 = time.monotonic()
                resp_fc, payload = session.request(unit_id, FC_DIAGNOSTICS, data)
                elapsed_ms = (time.monotonic() - t0) * 1000.0
            except OSError as exc:
                result.error = str(exc)
                break

            exc_name = _decode_exception(resp_fc, payload)
            if exc_name:
                result.error = f"exception on echo: {exc_name}"
                break

            result.samples_ms.append(elapsed_ms)
            echoed = payload[2:] if len(payload) >= 2 else b""
            if echoed == ECHO_PAYLOAD:
                echo_ok_count += 1
    finally:
        session.close()

    if result.samples_ms:
        result.min_ms = min(result.samples_ms)
        result.max_ms = max(result.samples_ms)
        result.avg_ms = sum(result.samples_ms) / len(result.samples_ms)
        if len(result.samples_ms) > 1:
            mean = result.avg_ms
            variance = sum((x - mean) ** 2 for x in result.samples_ms) / len(result.samples_ms)
            result.jitter_ms = variance ** 0.5
        result.echo_consistent = (echo_ok_count == len(result.samples_ms))

    return result


def run(host: str, port: int, unit_id: int = 1, timeout_ms: int = 2500,
        sample_count: int = SAMPLE_COUNT, logger=None) -> List[LatencyFingerprintResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(
            f"modbus_latency_fingerprint: {host}:{port} unit_id={unit_id} samples={sample_count}"
        )
    return [probe(host, port, unit_id, timeout_s, sample_count=sample_count)]
