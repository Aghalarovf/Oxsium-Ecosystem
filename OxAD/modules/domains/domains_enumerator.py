from __future__ import annotations

import logging
import socket
import struct

from ldap3 import ALL, ANONYMOUS, BASE, Connection, Server

from core.config import Config
from core.models import ADDomain
from core.session import Session
from core.smb.probes import check_smb_signing, get_os_info
from modules.base import BaseModule, ModuleResult
from utils.adutils import normalize_value, safe_int
from utils.sid_utils import sid_bytes_to_str

logger = logging.getLogger(__name__)

_DOMAIN_ATTRS = [
    "name",
    "distinguishedName",
    "objectSid",
    "msDS-Behavior-Version",
    "maxPwdAge",
    "minPwdAge",
    "minPwdLength",
    "pwdHistoryLength",
    "pwdProperties",
    "lockoutThreshold",
    "lockoutDuration",
    "lockOutObservationWindow",
    "fSMORoleOwner",
]

_DC_ATTRS = ["name", "dNSHostName", "objectSid", "operatingSystem"]

_DNS_RECORD_HEADER_LEN = 24
_DNS_TYPE_A = 1

_FUNCTIONAL_LEVELS = {
    "0": "2000",
    "1": "2003 Mixed",
    "2": "2003",
    "3": "2008",
    "4": "2008 R2",
    "5": "2012",
    "6": "2012 R2",
    "7": "2016+",
}




def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _safe_search(ldap, base_dn, ldap_filter, attributes, scope="SUBTREE"):
    try:
        return ldap.search(base_dn, ldap_filter, attributes, scope=scope)
    except Exception as exc:
        logger.debug("domains collector sub-query against %s failed: %s", base_dn, exc)
        return []


def _parse_dns_a_records(raw_values):
    ips = []
    for raw in raw_values or []:
        if not raw or len(raw) < _DNS_RECORD_HEADER_LEN:
            continue
        data_length, record_type = struct.unpack_from("<HH", raw, 0)
        if record_type != _DNS_TYPE_A:
            continue
        data = raw[_DNS_RECORD_HEADER_LEN:_DNS_RECORD_HEADER_LEN + data_length]
        if len(data) == 4:
            ips.append(socket.inet_ntoa(data))
    return ips


def _lookup_dns_a_records(ldap, dns_hostname, domain_dn):
    if not dns_hostname or "." not in str(dns_hostname):
        return []
    label, zone = str(dns_hostname).split(".", 1)
    zone_containers = (
        f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}",
        f"DC={zone},CN=MicrosoftDNS,CN=System,{domain_dn}",
    )
    for zone_container in zone_containers:
        node_entries = _safe_search(
            ldap, f"DC={label},{zone_container}", "(objectClass=dnsNode)", ["dnsRecord"], scope="BASE"
        )
        if node_entries:
            ips = _parse_dns_a_records(node_entries[0]["dnsRecord"].raw_values)
            if ips:
                return ips
    return []


def _role_owner_name(dn_value):
    if not dn_value:
        return None
    parts = [part.strip() for part in str(dn_value).split(",")]
    for index, part in enumerate(parts):
        if part.lower() == "cn=ntds settings" and index + 1 < len(parts):
            return parts[index + 1].split("=", 1)[-1]
    return None


def _filetime_interval_to_minutes(raw):
    if not raw:
        return None
    return round(abs(raw) / 10_000_000 / 60, 2)


def _probe_anonymous_bind(host, port=389, timeout=Config.LDAP_CONNECT_TIMEOUT):
    probe = {"allowed": None, "visible_naming_contexts": [], "error": None}
    try:
        server = Server(host, port=port, use_ssl=False, get_info=ALL, connect_timeout=timeout)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
        if conn.bind():
            probe["allowed"] = True
            contexts = server.info.naming_contexts if server.info else None
            probe["visible_naming_contexts"] = list(contexts) if contexts else []
            conn.unbind()
        else:
            probe["allowed"] = False
            probe["error"] = (conn.result or {}).get("description")
    except Exception as exc:
        probe["error"] = str(exc)
    return probe


def _derive_ldap_signing(anonymous_probe):
    probe = {"required": None, "basis": None, "error": None}
    allowed = anonymous_probe.get("allowed")
    if allowed is True:
        probe["required"] = False
        probe["basis"] = "unsigned anonymous bind and search succeeded over plaintext LDAP"
    elif allowed is False:
        probe["basis"] = "anonymous bind rejected; signing requirement cannot be confirmed without an unsigned authenticated probe"
    else:
        probe["error"] = anonymous_probe.get("error")
    return probe


class DomainsModule(BaseModule):
    name = "domains"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(objectClass=domain)", _DOMAIN_ATTRS, scope=BASE)
        except Exception as exc:
            logger.warning("domains collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        if not entries:
            logger.warning("domains collector failed: domain object not found")
            return ModuleResult(
                [], {"success": False, "count": 0, "error": "domain object not found", "meta": {}}
            )

        entry = entries[0]
        domain_dn = str(entry["distinguishedName"].value)

        sid_raw = entry["objectSid"].raw_values
        sid = sid_bytes_to_str(sid_raw[0]) if sid_raw else None
        if sid:
            session.domain_sid = sid

        level_raw = str(safe_int(normalize_value(entry["msDS-Behavior-Version"].value)))
        pwd_properties = safe_int(normalize_value(entry["pwdProperties"].value))

        domain = ADDomain(
            name=str(normalize_value(entry["name"].value)),
            dn=domain_dn,
            sid=sid,
            functional_level=_FUNCTIONAL_LEVELS.get(level_raw, level_raw),
            password_policy={
                "max_pwd_age": safe_int(normalize_value(entry["maxPwdAge"].value)),
                "min_pwd_age": safe_int(normalize_value(entry["minPwdAge"].value)),
                "min_pwd_length": safe_int(normalize_value(entry["minPwdLength"].value)),
                "pwd_history_length": safe_int(normalize_value(entry["pwdHistoryLength"].value)),
                "lockout_threshold": safe_int(normalize_value(entry["lockoutThreshold"].value)),
                "lockout_duration_mins": _filetime_interval_to_minutes(
                    safe_int(normalize_value(entry["lockoutDuration"].value))
                ),
                "lockout_observation_mins": _filetime_interval_to_minutes(
                    safe_int(normalize_value(entry["lockOutObservationWindow"].value))
                ),
                "complexity_enabled": bool(pwd_properties & 0x1),
            },
        )

        domain.smb_signing_required = check_smb_signing(session.target).get("signing_required")
        os_info = get_os_info(session.target)
        domain.os_info = os_info

        info_other = ldap.server.info.other if ldap.server.info else {}
        config_dn = _first(info_other.get("configurationNamingContext"))
        schema_dn = _first(info_other.get("schemaNamingContext"))
        root_dn = _first(info_other.get("rootDomainNamingContext")) or domain_dn

        netbios_name = None
        if config_dn:
            partitions_entries = _safe_search(
                ldap,
                f"CN=Partitions,{config_dn}",
                f"(&(objectClass=crossRef)(nCName={domain_dn}))",
                ["nETBIOSName"],
            )
            if partitions_entries:
                netbios_name = normalize_value(partitions_entries[0]["nETBIOSName"].value)

        dc_entries = _safe_search(
            ldap,
            domain_dn,
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            _DC_ATTRS,
        )
        domain_controllers = []
        for dc_entry in dc_entries:
            dns_hostname = normalize_value(dc_entry["dNSHostName"].value)
            dc_sid_raw = dc_entry["objectSid"].raw_values
            dc_ips = _lookup_dns_a_records(ldap, dns_hostname, domain_dn)
            domain_controllers.append(
                {
                    "name": normalize_value(dc_entry["name"].value),
                    "dns_hostname": dns_hostname,
                    "ip_address": dc_ips[0] if dc_ips else None,
                    "ip_addresses": dc_ips,
                    "sid": sid_bytes_to_str(dc_sid_raw[0]) if dc_sid_raw else None,
                    "operating_system": normalize_value(dc_entry["operatingSystem"].value),
                }
            )

        fsmo = {"pdc_emulator": _role_owner_name(normalize_value(entry["fSMORoleOwner"].value))}

        rid_entries = _safe_search(
            ldap, f"CN=RID Manager$,CN=System,{domain_dn}", "(objectClass=*)", ["fSMORoleOwner"], scope="BASE"
        )
        fsmo["rid_master"] = (
            _role_owner_name(normalize_value(rid_entries[0]["fSMORoleOwner"].value)) if rid_entries else None
        )

        infra_entries = _safe_search(
            ldap, f"CN=Infrastructure,{domain_dn}", "(objectClass=*)", ["fSMORoleOwner"], scope="BASE"
        )
        fsmo["infrastructure_master"] = (
            _role_owner_name(normalize_value(infra_entries[0]["fSMORoleOwner"].value)) if infra_entries else None
        )

        if schema_dn:
            schema_role_entries = _safe_search(ldap, schema_dn, "(objectClass=*)", ["fSMORoleOwner"], scope="BASE")
            fsmo["schema_master"] = (
                _role_owner_name(normalize_value(schema_role_entries[0]["fSMORoleOwner"].value))
                if schema_role_entries
                else None
            )
        else:
            fsmo["schema_master"] = None

        if config_dn:
            naming_entries = _safe_search(
                ldap, f"CN=Partitions,{config_dn}", "(objectClass=*)", ["fSMORoleOwner"], scope="BASE"
            )
            fsmo["domain_naming_master"] = (
                _role_owner_name(normalize_value(naming_entries[0]["fSMORoleOwner"].value))
                if naming_entries
                else None
            )
        else:
            fsmo["domain_naming_master"] = None

        global_catalogs = []
        if config_dn:
            gc_entries = _safe_search(
                ldap,
                f"CN=Sites,{config_dn}",
                "(&(objectClass=nTDSDSA)(options:1.2.840.113556.1.4.803:=1))",
                ["distinguishedName"],
            )
            for gc_entry in gc_entries:
                owner_name = _role_owner_name(str(gc_entry["distinguishedName"].value))
                if owner_name:
                    global_catalogs.append(owner_name)

        dns_zones = []
        for partition_label, zones_base_dn in (
            ("domain", f"CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"),
            ("forest", f"CN=MicrosoftDNS,DC=ForestDnsZones,{root_dn}"),
            ("legacy", f"CN=MicrosoftDNS,CN=System,{domain_dn}"),
        ):
            zone_entries = _safe_search(ldap, zones_base_dn, "(objectClass=dnsZone)", ["name"])
            for zone_entry in zone_entries:
                zone_name = normalize_value(zone_entry["name"].value)
                if zone_name:
                    dns_zones.append({"name": zone_name, "partition": partition_label})

        laps = {
            "legacy_schema_present": False,
            "windows_schema_present": False,
            "legacy_deployed_count": 0,
            "windows_deployed_count": 0,
        }
        if schema_dn:
            laps_schema_entries = _safe_search(
                ldap, schema_dn, "(|(name=ms-Mcs-AdmPwd)(name=msLAPS-Password))", ["name"]
            )
            schema_names = {str(normalize_value(e["name"].value)) for e in laps_schema_entries}
            laps["legacy_schema_present"] = "ms-Mcs-AdmPwd" in schema_names
            laps["windows_schema_present"] = "msLAPS-Password" in schema_names

        if laps["legacy_schema_present"]:
            laps["legacy_deployed_count"] = len(
                _safe_search(ldap, domain_dn, "(ms-Mcs-AdmPwdExpirationTime=*)", ["distinguishedName"])
            )
        if laps["windows_schema_present"]:
            laps["windows_deployed_count"] = len(
                _safe_search(ldap, domain_dn, "(msLAPS-PasswordExpirationTime=*)", ["distinguishedName"])
            )

        enterprise_cas = []
        if config_dn:
            ca_entries = _safe_search(
                ldap,
                f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
                "(objectClass=pKIEnrollmentService)",
                ["cn", "dNSHostName"],
            )
            for ca_entry in ca_entries:
                enterprise_cas.append(
                    {
                        "name": normalize_value(ca_entry["cn"].value),
                        "dns_hostname": normalize_value(ca_entry["dNSHostName"].value),
                    }
                )

        kerberos_policy = {
            "max_ticket_age": None,
            "max_renew_age": None,
            "max_service_age": None,
            "max_clock_skew": None,
            "ticket_validate_client": None,
            "note": "not retrievable via domain object LDAP attributes; requires GPO/SYSVOL (GptTmpl.inf) parsing",
        }

        ntlm_supported = os_info.get("error") is None and bool(
            os_info.get("netbios_name") or os_info.get("domain") or os_info.get("os")
        )

        anonymous_bind = _probe_anonymous_bind(session.target)
        ldap_signing = _derive_ldap_signing(anonymous_bind)

        # Mirror the discovered data onto the ADDomain object's own fields too
        # (not just `meta`), so consumers reading the domain model directly
        # see domain_controllers / fsmo_roles / dns_zones / laps /
        # authentication_security / null_anonymous_access populated.
        domain.domain_controllers = domain_controllers
        domain.fsmo_roles = fsmo
        domain.dns_zones = [zone["name"] for zone in dns_zones if zone.get("name")]
        domain.laps = laps
        domain.authentication_security = {
            "ntlm_supported": ntlm_supported,
            "ldap_signing": ldap_signing,
        }
        domain.null_anonymous_access = anonymous_bind

        meta = {
            "netbios_name": netbios_name,
            "domain_controllers": domain_controllers,
            "fsmo": fsmo,
            "global_catalogs": global_catalogs,
            "dns_zones": dns_zones,
            "laps": laps,
            "enterprise_cas": enterprise_cas,
            "has_enterprise_ca": bool(enterprise_cas),
            "kerberos_policy": kerberos_policy,
            "ntlm_supported": ntlm_supported,
            "ldap_signing": ldap_signing,
            "anonymous_bind": anonymous_bind,
        }

        result = {"success": True, "count": 1, "error": None, "meta": meta}
        return ModuleResult([domain], result)