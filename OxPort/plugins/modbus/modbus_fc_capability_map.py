import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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

PROBE_FUNCTION_CODES: List[Tuple[int, str, bytes]] = [
    (0x01, "Read Coils",               b"\x00\x00\x00\x01"),
    (0x02, "Read Discrete Inputs",     b"\x00\x00\x00\x01"),
    (0x03, "Read Holding Registers",   b"\x00\x00\x00\x01"),
    (0x04, "Read Input Registers",     b"\x00\x00\x00\x01"),
    (0x07, "Read Exception Status",    b""),
    (0x08, "Diagnostics (echo)",       b"\x00\x00\xAB\xCD"),
    (0x11, "Report Slave ID",          b""),
    (0x14, "Read File Record",         b"\x07\x00\x01\x00\x00\x00\x01"),
    (0x18, "Read FIFO Queue",          b"\x00\x00"),
    (0x2B, "Encapsulated Interface",   b"\x0E\x01\x00"),
]

SUPPORTED = "supported"
ILLEGAL_FUNCTION = "ILLEGAL FUNCTION"


@dataclass
class FcCapabilityEntry:
    fc: int
    name: str
    result: str
    exception_code: Optional[int] = None


@dataclass
class FcCapabilityMapResult:
    host: str
    port: int
    unit_id: int
    capabilities: List[FcCapabilityEntry] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def supported_fcs(self) -> List[int]:
        return [e.fc for e in self.capabilities if e.result == SUPPORTED]

    @property
    def any_responsive(self) -> bool:
        return bool(self.capabilities) and self.error is None


def _decode_exception(resp_fc: int, payload: bytes) -> Tuple[bool, Optional[int], Optional[str]]:
    if resp_fc & 0x80:
        code = payload[0] if payload else None
        name = EXCEPTION_CODES.get(code, f"UNKNOWN({code})") if code is not None else "UNKNOWN(no code)"
        return True, code, name
    return False, None, None


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


def probe(host: str, port: int, unit_id: int, timeout_s: float) -> FcCapabilityMapResult:
    result = FcCapabilityMapResult(host=host, port=port, unit_id=unit_id)

    try:
        session = _Session(host, port, timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        for fc, name, probe_data in PROBE_FUNCTION_CODES:
            try:
                resp_fc, payload = session.request(unit_id, fc, probe_data)
                is_exc, exc_code, exc_name = _decode_exception(resp_fc, payload)
                if is_exc:
                    entry = FcCapabilityEntry(fc=fc, name=name, result=exc_name or "EXCEPTION",
                                              exception_code=exc_code)
                else:
                    entry = FcCapabilityEntry(fc=fc, name=name, result=SUPPORTED)
            except OSError as exc:
                entry = FcCapabilityEntry(fc=fc, name=name, result=f"error: {exc}")
            result.capabilities.append(entry)
    finally:
        session.close()

    return result


def run(host: str, port: int, unit_id: int = 1, timeout_ms: int = 2500,
        logger=None) -> List[FcCapabilityMapResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(f"modbus_fc_capability_map: probing {host}:{port} unit_id={unit_id}")
    return [probe(host, port, unit_id, timeout_s)]
