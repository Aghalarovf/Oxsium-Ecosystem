from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from plugins.modbus.modbus_diagnostics import DiagnosticsResult
    from plugins.modbus.modbus_exception_status import ExceptionStatusResult
    from plugins.modbus.modbus_fc_capability_map import FcCapabilityMapResult
    from plugins.modbus.modbus_fifo_probe import FifoProbeResult
    from plugins.modbus.modbus_file_record_probe import FileRecordProbeResult
    from plugins.modbus.modbus_latency_fingerprint import LatencyFingerprintResult
    from plugins.modbus.modbus_probe import RegisterProbeResult
    from plugins.modbus.modbus_tls_variant_check import TlsVariantResult


@dataclass
class ModbusDiscoverResult:
    service: str
    host: str
    port: int
    protocol: str
    unit_id: int
    responsive: bool = False
    unit_id_ignored: Optional[bool] = None
    report_slave_id_raw: Optional[str] = None
    report_slave_id_text: Optional[str] = None
    report_slave_id_exception: Optional[str] = None
    device_identification: Dict[str, str] = field(default_factory=dict)
    device_id_exception: Optional[str] = None
    tested_unit_ids: List[int] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    register_probe: Optional[RegisterProbeResult] = None
    diagnostics: Optional[DiagnosticsResult] = None
    exception_status: Optional[ExceptionStatusResult] = None
    fc_capability_map: Optional[FcCapabilityMapResult] = None
    file_record_probe: Optional[FileRecordProbeResult] = None
    fifo_probe: Optional[FifoProbeResult] = None
    latency_fingerprint: Optional[LatencyFingerprintResult] = None
    tls_variant: Optional[TlsVariantResult] = None


def failed(host: str, port: int, protocol: str, unit_id: int, error: str) -> ModbusDiscoverResult:
    return ModbusDiscoverResult(
        service="modbus",
        host=host,
        port=port,
        protocol=protocol,
        unit_id=unit_id,
        responsive=False,
        error=error,
    )
