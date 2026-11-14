import socket
from typing import Dict, List, Optional, Tuple

from plugins.modbus.base import ModbusDiscoverResult

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

DEVICE_ID_OBJECT_NAMES = {
    0x00: "VendorName",
    0x01: "ProductCode",
    0x02: "MajorMinorRevision",
    0x03: "VendorUrl",
    0x04: "ProductName",
    0x05: "ModelName",
    0x06: "UserApplicationName",
}

READ_DEVID_CODE = {"basic": 0x01, "regular": 0x02, "extended": 0x03}

FC_REPORT_SLAVE_ID = 0x11
FC_ENCAPSULATED_INTERFACE = 0x2B
MEI_READ_DEVICE_ID = 0x0E

QUICK_UNIT_IDS = (1, 0, 255)


class ModbusError(Exception):
    pass


class ModbusSession:
    """One TCP connection to a Modbus TCP endpoint, request/response only."""

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
            raise ModbusError("not connected")

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
        if not header:
            raise ModbusError("no response (connection closed / timeout)")

        resp_txn_id = int.from_bytes(header[0:2], "big")
        proto_id = int.from_bytes(header[2:4], "big")
        resp_len = int.from_bytes(header[4:6], "big")

        if proto_id != 0x0000:
            raise ModbusError(f"unexpected protocol id 0x{proto_id:04x} (not Modbus)")
        if resp_txn_id != txn_id:
            raise ModbusError(f"transaction id mismatch (sent {txn_id}, got {resp_txn_id})")
        if resp_len < 2:
            raise ModbusError("malformed length field in response")

        remaining = self._recv_exact(resp_len - 1)
        if remaining is None or len(remaining) != resp_len - 1:
            raise ModbusError("truncated response body")

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


def _decode_exception(resp_fc: int, payload: bytes) -> Optional[str]:
    if resp_fc & 0x80:
        code = payload[0] if payload else None
        if code is None:
            return "UNKNOWN(no code)"
        return EXCEPTION_CODES.get(code, f"UNKNOWN({code})")
    return None


def _try_report_slave_id(session: ModbusSession, unit_id: int, result: ModbusDiscoverResult):
    try:
        resp_fc, payload = session.request(unit_id, FC_REPORT_SLAVE_ID, b"")
    except ModbusError as exc:
        result.notes.append(f"report_slave_id failed: {exc}")
        return

    exc_name = _decode_exception(resp_fc, payload)
    if exc_name:
        result.report_slave_id_exception = exc_name
        return

    if len(payload) < 1:
        result.notes.append("report_slave_id: empty payload")
        return

    byte_count = payload[0]
    data = payload[1:1 + byte_count]
    result.report_slave_id_raw = data.hex()
    result.report_slave_id_text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _try_device_identification(session: ModbusSession, unit_id: int,
                                 result: ModbusDiscoverResult) -> Dict[str, str]:
    objects: Dict[str, str] = {}

    for level in ("basic", "regular", "extended"):
        read_code = READ_DEVID_CODE[level]
        next_object_id = 0x00
        more_follows = True
        seen_ids = set()
        guard = 0

        while more_follows and guard < 32:
            guard += 1
            data = bytes([MEI_READ_DEVICE_ID, read_code, next_object_id])
            try:
                resp_fc, payload = session.request(unit_id, FC_ENCAPSULATED_INTERFACE, data)
            except ModbusError as exc:
                result.notes.append(f"device_id[{level}] failed: {exc}")
                return objects

            exc_name = _decode_exception(resp_fc, payload)
            if exc_name:
                if level == "basic":
                    result.device_id_exception = exc_name
                return objects

            if len(payload) < 6:
                result.notes.append(f"device_id[{level}]: short response")
                return objects

            more_follows_byte = payload[3]
            next_object_id = payload[4]
            num_objects = payload[5]
            cursor = 6

            for _ in range(num_objects):
                if cursor + 2 > len(payload):
                    break
                obj_id = payload[cursor]
                obj_len = payload[cursor + 1]
                cursor += 2
                value = payload[cursor:cursor + obj_len]
                cursor += obj_len

                if obj_id in seen_ids:
                    continue
                seen_ids.add(obj_id)

                name = DEVICE_ID_OBJECT_NAMES.get(obj_id, f"Object_0x{obj_id:02x}")
                try:
                    objects[name] = value.decode("ascii").strip(" \x00")
                except UnicodeDecodeError:
                    objects[name] = value.hex()

            more_follows = more_follows_byte == 0xFF

    return objects


def probe_unit(host: str, port: int, unit_id: int, timeout_s: float) -> ModbusDiscoverResult:
    result = ModbusDiscoverResult(service="modbus", host=host, port=port, protocol="tcp", unit_id=unit_id)
    session = ModbusSession(host, port, timeout_s)

    try:
        session.connect()
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        _try_report_slave_id(session, unit_id, result)
        device_id = _try_device_identification(session, unit_id, result)
        result.device_identification = device_id

        result.responsive = (
            result.report_slave_id_raw is not None
            or result.report_slave_id_exception is not None
            or bool(device_id)
            or result.device_id_exception is not None
        )
    finally:
        session.close()

    return result


def _result_signature(r: ModbusDiscoverResult) -> tuple:
    return (
        tuple(sorted(r.device_identification.items())),
        r.device_id_exception,
        r.report_slave_id_text,
        r.report_slave_id_exception,
    )


def _consolidate_duplicates(results: List[ModbusDiscoverResult]) -> List[ModbusDiscoverResult]:
    groups: Dict[tuple, List[ModbusDiscoverResult]] = {}
    for r in results:
        groups.setdefault(_result_signature(r), []).append(r)

    consolidated: List[ModbusDiscoverResult] = []
    for group in groups.values():
        representative = group[0]
        representative.tested_unit_ids = sorted(r.unit_id for r in group)
        representative.unit_id_ignored = len(group) > 1
        if len(group) > 1:
            ids_text = ", ".join(f"0x{u:02x}" for u in representative.tested_unit_ids)
            representative.notes.append(
                f"identical response from {len(group)} unit ids ({ids_text}) - unit id appears to be ignored"
            )
        consolidated.append(representative)

    return consolidated


def discover(host: str, port: int, timeout_ms: int = 2500, full_unit_scan: bool = False,
              logger=None) -> List[ModbusDiscoverResult]:
    unit_ids = list(range(0, 248)) if full_unit_scan else list(QUICK_UNIT_IDS)
    timeout_s = timeout_ms / 1000.0

    results: List[ModbusDiscoverResult] = []
    for unit_id in unit_ids:
        if logger:
            logger.info(f"modbus_discover: probing {host}:{port} unit_id={unit_id}")
        results.append(probe_unit(host, port, unit_id, timeout_s))

    responsive = [r for r in results if r.responsive]
    if not responsive:
        return results[:1]
    return _consolidate_duplicates(responsive)