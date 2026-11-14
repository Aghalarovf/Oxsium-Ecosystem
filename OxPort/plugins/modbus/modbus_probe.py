import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from plugins.modbus.base import ModbusDiscoverResult

FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04

PROBE_START_ADDRESS = 0
PROBE_COUNT = 8

REGISTER_TYPE_NAMES = {
    FC_READ_COILS: "Coils",
    FC_READ_DISCRETE_INPUTS: "Discrete Inputs",
    FC_READ_HOLDING_REGISTERS: "Holding Registers",
    FC_READ_INPUT_REGISTERS: "Input Registers",
}

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
class RegisterProbeEntry:
    fc: int
    name: str
    start_address: int
    count: int
    data_hex: Optional[str] = None
    exception: Optional[str] = None
    error: Optional[str] = None

    @property
    def responsive(self) -> bool:
        return self.data_hex is not None or self.exception is not None


@dataclass
class RegisterProbeResult:
    host: str
    port: int
    unit_id: int
    entries: List[RegisterProbeEntry] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def any_responsive(self) -> bool:
        return any(e.responsive for e in self.entries)


class _ProbeSession:
    def __init__(self, host: str, port: int, timeout_s: float):
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        self.sock: Optional[socket.socket] = None
        self._txn_id = 0

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout_s)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _next_txn_id(self) -> int:
        self._txn_id = (self._txn_id + 1) % 0xFFFF
        return self._txn_id

    def request(self, unit_id: int, function_code: int, data: bytes) -> Tuple[int, bytes]:
        if self.sock is None:
            raise OSError("not connected")

        txn_id = self._next_txn_id()
        pdu = bytes([function_code]) + data
        length = len(pdu) + 1
        mbap = (
            txn_id.to_bytes(2, "big")
            + b"\x00\x00"
            + length.to_bytes(2, "big")
            + bytes([unit_id])
        )
        self.sock.sendall(mbap + pdu)

        header = self._recv_exact(7)
        if header is None:
            raise OSError("no response (connection closed or timeout)")

        resp_txn_id = int.from_bytes(header[0:2], "big")
        proto_id = int.from_bytes(header[2:4], "big")
        resp_len = int.from_bytes(header[4:6], "big")

        if proto_id != 0x0000:
            raise OSError(f"unexpected protocol id 0x{proto_id:04x}")
        if resp_txn_id != txn_id:
            raise OSError(f"transaction id mismatch (sent {txn_id}, got {resp_txn_id})")
        if resp_len < 2:
            raise OSError("malformed response length")

        remaining = self._recv_exact(resp_len - 1)
        if remaining is None or len(remaining) != resp_len - 1:
            raise OSError("truncated response body")

        return remaining[0], remaining[1:]

    def _recv_exact(self, n: int) -> Optional[bytes]:
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


def _build_read_request(start_address: int, count: int) -> bytes:
    return start_address.to_bytes(2, "big") + count.to_bytes(2, "big")


def _decode_exception(resp_fc: int, payload: bytes) -> Optional[str]:
    if resp_fc & 0x80:
        code = payload[0] if payload else None
        if code is None:
            return "UNKNOWN(no code)"
        return EXCEPTION_CODES.get(code, f"UNKNOWN({code})")
    return None


def probe(host: str, port: int, unit_id: int, timeout_s: float,
          start_address: int = PROBE_START_ADDRESS,
          count: int = PROBE_COUNT) -> RegisterProbeResult:
    result = RegisterProbeResult(host=host, port=port, unit_id=unit_id)
    session = _ProbeSession(host, port, timeout_s)

    try:
        session.connect()
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        for fc in (FC_READ_COILS, FC_READ_DISCRETE_INPUTS,
                   FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS):
            entry = RegisterProbeEntry(
                fc=fc,
                name=REGISTER_TYPE_NAMES[fc],
                start_address=start_address,
                count=count,
            )
            try:
                data = _build_read_request(start_address, count)
                resp_fc, payload = session.request(unit_id, fc, data)
                exc_name = _decode_exception(resp_fc, payload)
                if exc_name:
                    entry.exception = exc_name
                else:
                    byte_count = payload[0] if payload else 0
                    raw = payload[1:1 + byte_count]
                    entry.data_hex = raw.hex() if raw else ""
            except OSError as exc:
                entry.error = str(exc)
            result.entries.append(entry)
    finally:
        session.close()

    return result


def run(host: str, port: int, unit_id: int = 1, timeout_ms: int = 2500,
        start_address: int = PROBE_START_ADDRESS, count: int = PROBE_COUNT,
        logger=None) -> List[RegisterProbeResult]:
    timeout_s = timeout_ms / 1000.0
    if logger:
        logger.info(
            f"modbus_probe: probing {host}:{port} unit_id={unit_id} "
            f"address={start_address} count={count}"
        )
    result = probe(host, port, unit_id, timeout_s,
                   start_address=start_address, count=count)
    return [result]
