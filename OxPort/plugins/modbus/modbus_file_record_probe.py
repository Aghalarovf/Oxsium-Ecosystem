import socket
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

FC_READ_FILE_RECORD = 0x14
REFERENCE_TYPE = 0x06

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
class FileRecordEntry:
    file_number: int
    record_number: int
    record_length: int
    data_hex: Optional[str] = None
    exception: Optional[str] = None
    error: Optional[str] = None

    @property
    def responsive(self) -> bool:
        return self.data_hex is not None or self.exception is not None


@dataclass
class FileRecordProbeResult:
    host: str
    port: int
    unit_id: int
    entries: List[FileRecordEntry] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def any_responsive(self) -> bool:
        return any(e.responsive for e in self.entries)


PROBE_TARGETS = [
    (1, 0, 2),
    (1, 1, 2),
    (2, 0, 2),
]


def _decode_exception(resp_fc: int, payload: bytes) -> Optional[str]:
    if resp_fc & 0x80:
        code = payload[0] if payload else None
        if code is None:
            return "UNKNOWN(no code)"
        return EXCEPTION_CODES.get(code, f"UNKNOWN({code})")
    return None


def _build_subrequest(file_number: int, record_number: int, record_length: int) -> bytes:
    return (
        bytes([REFERENCE_TYPE])
        + file_number.to_bytes(2, "big")
        + record_number.to_bytes(2, "big")
        + record_length.to_bytes(2, "big")
    )


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


def probe(host: str, port: int, unit_id: int, timeout_s: float) -> FileRecordProbeResult:
    result = FileRecordProbeResult(host=host, port=port, unit_id=unit_id)

    try:
        session = _Session(host, port, timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        for file_number, record_number, record_length in PROBE_TARGETS:
            entry = FileRecordEntry(
                file_number=file_number,
                record_number=record_number,
                record_length=record_length,
            )
            try:
                sub = _build_subrequest(file_number, record_number, record_length)
                data = bytes([len(sub)]) + sub
                resp_fc, payload = session.request(unit_id, FC_READ_FILE_RECORD, data)
                exc_name = _decode_exception(resp_fc, payload)
                if exc_name:
                    entry.exception = exc_name
                else:
                    entry.data_hex = payload.hex()
            except OSError as exc:
                entry.error = str(exc)
            result.entries.append(entry)
    finally:
        session.close()

    return result


def run(host: str, port: int, unit_id: int = 1, timeout_ms: int = 2500,
        logger=None) -> List[FileRecordProbeResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(f"modbus_file_record_probe: FC14 {host}:{port} unit_id={unit_id}")
    return [probe(host, port, unit_id, timeout_s)]
