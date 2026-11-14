from __future__ import annotations

from engine.base import RawProcessor

from . import esc1, esc10, esc11, esc12, esc13, esc14, esc15, esc2, esc3, esc4, esc5, esc6, esc7, esc8, esc9


class CertificateProcessor(RawProcessor):
    name = "cert"

    @property
    def domain_file(self) -> str:
        return "domain_certificates.jsonl"

    def subject(self, record):
        return record

    def process(self, records, context):
        templates = [item for item in records if item.get("record_type") == "template"]
        services = [item for item in records if item.get("record_type") == "enrollment_service"]
        authorities = [item for item in records if item.get("record_type") in {"certification_authority", "ntauth"}]
        oids = [item for item in records if item.get("record_type") == "oid"]
        users = [item for item in records if item.get("record_type") == "user_mapping"]
        self._attach_acl(records, context.aces)
        findings = []
        findings.extend(esc1.run(templates, services))
        findings.extend(esc2.run(templates, services))
        findings.extend(esc3.run(templates, services))
        findings.extend(esc4.run(templates, services))
        findings.extend(esc5.run(authorities + services + oids))
        findings.extend(esc6.run(services))
        findings.extend(esc7.run(services))
        findings.extend(esc8.run(services))
        findings.extend(esc9.run(templates, services))
        findings.extend(esc10.run([]))
        findings.extend(esc11.run(services))
        findings.extend(esc12.run(records))
        findings.extend(esc13.run(templates, oids))
        findings.extend(esc14.run(users))
        findings.extend(esc15.run(templates, services))
        by_target: dict[str, list[dict]] = {}
        for item in findings:
            by_target.setdefault(str(item["target"]).lower(), []).append(item)
        output = []
        for record in records:
            current = dict(record)
            current["esc_findings"] = by_target.get(str(record.get("dn") or record.get("name")).lower(), [])
            current["finding_count"] = len(current["esc_findings"])
            current["risk"] = "high" if current["finding_count"] else "informational"
            current["hygiene_findings"] = self._hygiene(record, services)
            output.append(current)
        return output

    @staticmethod
    def _hygiene(record, services):
        if record.get("record_type") != "template":
            return []
        raw = record.get("raw", {})
        findings = []
        if not any(
            str(value).lower() in {
                str(record.get("name") or "").lower(),
                f"cn={str(record.get('name') or '').lower()}",
            }
            for service in services
            for value in (service.get("raw", {}).get("certificateTemplates") or [])
        ):
            findings.append("Template is not published by an Enrollment Service")
        try:
            if int(raw.get("msPKI-Minimal-Key-Size") or 0) < 2048:
                findings.append("Minimum key size is below 2048 bits")
        except (TypeError, ValueError):
            pass
        algorithm = str(raw.get("signatureAlgorithm") or raw.get("signature_algorithm") or "").lower()
        if "sha1" in algorithm:
            findings.append("SHA-1 signature algorithm")
        return findings

    @staticmethod
    def _attach_acl(records, aces):
        by_dn: dict[str, list[dict]] = {}
        for ace in aces:
            target = str(ace.get("target_dn") or "").lower()
            if target:
                by_dn.setdefault(target, []).append(ace)
        for record in records:
            record["acl"] = by_dn.get(str(record.get("dn") or "").lower(), [])
