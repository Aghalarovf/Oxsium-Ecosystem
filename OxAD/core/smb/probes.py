from __future__ import annotations

import os
import socket
import struct

SMB_PORT = 445

_SMB2_MAGIC = b"\xfeSMB"
_SMB1_MAGIC = b"\xffSMB"

_SMB2_NEGOTIATE = 0x0000
_SMB2_SESSION_SETUP = 0x0001

_STATUS_SUCCESS = 0x00000000
_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016

_SMB2_SIGNING_ENABLED = 0x0001
_SMB2_SIGNING_REQUIRED = 0x0002
_SMB1_SIGNING_ENABLED = 0x04
_SMB1_SIGNING_REQUIRED = 0x08


_SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)

_NTLMSSP_SIG = b"NTLMSSP\x00"
_NTLMSSP_NEGOTIATE_VERSION = 0x02000000

_AV_NB_COMPUTER = 1
_AV_NB_DOMAIN = 2
_AV_DNS_COMPUTER = 3
_AV_DNS_DOMAIN = 4


class SMBProbeError(Exception):
    pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise SMBProbeError("connection closed by server")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_packet(sock: socket.socket, payload: bytes) -> None:

    sock.sendall(b"\x00" + struct.pack(">I", len(payload))[1:] + payload)


def _recv_packet(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    if header[0] != 0x00:
        raise SMBProbeError("unexpected transport header")
    length = int.from_bytes(header[1:], "big")
    if length < 4 or length > 1 << 20:
        raise SMBProbeError("invalid packet length")
    return _recv_exact(sock, length)


def _connect(host: str, timeout: float) -> socket.socket:
    return socket.create_connection((host, SMB_PORT), timeout=timeout)


def _smb2_header(command: int, message_id: int, credit_charge: int = 0, session_id: int = 0) -> bytes:
    return _SMB2_MAGIC + struct.pack(
        "<HHIHHIIQIIQ16s",
        64,
        credit_charge,
        0,
        command,
        1,
        0,
        0,
        message_id,
        0,
        0,
        session_id,
        b"\x00" * 16,
    )


def _smb2_negotiate_request() -> bytes:
    dialects = b"".join(struct.pack("<H", d) for d in _SMB2_DIALECTS)
    body = struct.pack(
        "<HHHHI16sQ",
        36,
        len(_SMB2_DIALECTS),
        _SMB2_SIGNING_ENABLED,
        0,
        0,
        os.urandom(16),
        0,
    )
    return _smb2_header(_SMB2_NEGOTIATE, 0) + body + dialects


def _smb2_parse_response(data: bytes, expected_command: int) -> tuple[int, bytes, bytes]:
    if len(data) < 64 or data[:4] != _SMB2_MAGIC:
        raise SMBProbeError("not an SMB2 response")
    command = struct.unpack_from("<H", data, 12)[0]
    status = struct.unpack_from("<I", data, 8)[0]
    if command != expected_command:
        raise SMBProbeError("unexpected SMB2 command in response")
    return status, data[:64], data[64:]


def _smb2_negotiate(sock: socket.socket) -> tuple[int, int]:
    _send_packet(sock, _smb2_negotiate_request())
    status, _hdr, body = _smb2_parse_response(_recv_packet(sock), _SMB2_NEGOTIATE)
    if status != _STATUS_SUCCESS:
        raise SMBProbeError(f"SMB2 negotiate failed (status 0x{status:08x})")
    if len(body) < 8:
        raise SMBProbeError("truncated SMB2 negotiate response")
    security_mode, dialect = struct.unpack_from("<HH", body, 2)
    return security_mode, dialect


def _smb1_negotiate_signing(sock: socket.socket) -> bool:
    dialect = b"\x02NT LM 0.12\x00"
    header = (
        _SMB1_MAGIC
        + struct.pack("<BI", 0x72, 0)
        + struct.pack("<BH", 0x18, 0xC843)
        + struct.pack("<H", 0)
        + b"\x00" * 8
        + struct.pack("<H", 0)
        + struct.pack("<HHHH", 0xFFFF, os.getpid() & 0xFFFF, 0, 0)
    )
    packet = header + b"\x00" + struct.pack("<H", len(dialect)) + dialect
    _send_packet(sock, packet)
    data = _recv_packet(sock)
    if data[:4] != _SMB1_MAGIC:
        raise SMBProbeError("not an SMB1 response")
    if len(data) < 36 or data[32] < 1:
        raise SMBProbeError("truncated SMB1 negotiate response")
    security_mode = data[35]
    return bool(security_mode & _SMB1_SIGNING_REQUIRED)


def _ntlmssp_negotiate_message() -> bytes:
    flags = (
        0x00000001
        | 0x00000004
        | 0x00000200
        | 0x00008000
        | 0x00080000
        | _NTLMSSP_NEGOTIATE_VERSION
        | 0x20000000
        | 0x80000000
    )
    version = struct.pack("<BBHBBBB", 10, 0, 19041, 0, 0, 0, 15)
    return (
        _NTLMSSP_SIG
        + struct.pack("<I", 1)
        + struct.pack("<I", flags)
        + struct.pack("<HHI", 0, 0, 0)
        + struct.pack("<HHI", 0, 0, 0)
        + version
    )


def _parse_ntlmssp_challenge(blob: bytes) -> dict:
    start = blob.find(_NTLMSSP_SIG + struct.pack("<I", 2))
    if start < 0:
        raise SMBProbeError("no NTLMSSP challenge in response")
    msg = blob[start:]
    if len(msg) < 48:
        raise SMBProbeError("truncated NTLMSSP challenge")

    flags = struct.unpack_from("<I", msg, 20)[0]
    info: dict = {}

    if flags & _NTLMSSP_NEGOTIATE_VERSION and len(msg) >= 56:
        major, minor, build = struct.unpack_from("<BBH", msg, 48)
        info["version"] = (major, minor, build)

    ti_len, _ti_max, ti_off = struct.unpack_from("<HHI", msg, 40)
    target_info = msg[ti_off:ti_off + ti_len]
    pos = 0
    names = {
        _AV_NB_COMPUTER: "netbios_name",
        _AV_NB_DOMAIN: "domain",
        _AV_DNS_COMPUTER: "dns_hostname",
        _AV_DNS_DOMAIN: "dns_domain",
    }
    while pos + 4 <= len(target_info):
        av_id, av_len = struct.unpack_from("<HH", target_info, pos)
        pos += 4
        if av_id == 0:
            break
        value = target_info[pos:pos + av_len]
        pos += av_len
        key = names.get(av_id)
        if key:
            info[key] = value.decode("utf-16-le", errors="replace")
    return info


def _smb2_ntlm_challenge(sock: socket.socket, dialect: int) -> dict:
    token = _ntlmssp_negotiate_message()
    body = struct.pack(
        "<HBBIIHHQ",
        25,
        0,
        _SMB2_SIGNING_ENABLED,
        0,
        0,
        64 + 24,
        len(token),
        0,
    )
    credit_charge = 0 if dialect == 0x0202 else 1
    _send_packet(sock, _smb2_header(_SMB2_SESSION_SETUP, 1, credit_charge) + body + token)

    status, _hdr, resp = _smb2_parse_response(_recv_packet(sock), _SMB2_SESSION_SETUP)
    if status != _STATUS_MORE_PROCESSING_REQUIRED:
        raise SMBProbeError(f"session setup rejected (status 0x{status:08x})")
    if len(resp) < 8:
        raise SMBProbeError("truncated session setup response")

    sec_off, sec_len = struct.unpack_from("<HH", resp, 4)

    blob = resp[sec_off - 64: sec_off - 64 + sec_len]
    return _parse_ntlmssp_challenge(blob)


def check_smb_signing(host: str, timeout: float = 5.0) -> dict:
    result: dict = {"signing_required": None, "error": None}
    try:
        try:
            with _connect(host, timeout) as sock:
                security_mode, _dialect = _smb2_negotiate(sock)
                result["signing_required"] = bool(security_mode & _SMB2_SIGNING_REQUIRED)
        except (SMBProbeError, ConnectionError, socket.timeout):

            with _connect(host, timeout) as sock:
                result["signing_required"] = _smb1_negotiate_signing(sock)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def get_os_info(host: str, timeout: float = 5.0) -> dict:
    result: dict = {"os": None, "error": None}
    try:
        with _connect(host, timeout) as sock:
            _security_mode, dialect = _smb2_negotiate(sock)
            info = _smb2_ntlm_challenge(sock, dialect)
        version = info.pop("version", None)
        if version:
            major, minor, build = version
            result["os"] = f"Windows {major}.{minor} Build {build}"
        result.update(info)
    except Exception as exc:
        result["error"] = str(exc)
    return result
