from __future__ import annotations

from modules.aces.aces_collector import AcesModule
from modules.certificates.certificates_collector import CertificatesModule
from modules.computers.computers_collector import ComputersModule
from modules.domains.domains_enumerator import DomainsModule
from modules.gpos.gpos_collector import GposModule
from modules.groups.groups_collector import GroupsModule
from modules.ous.ous_collector import OusModule
from modules.trusts.trusts_collector import TrustsModule
from modules.users.users_collector import UsersModule

SCAN_ORDER = ["domains", "aces", "groups", "ous", "gpos", "computers", "users", "trusts", "cert"]

REGISTRY = {
    "domains": DomainsModule,
    "aces": AcesModule,
    "groups": GroupsModule,
    "ous": OusModule,
    "gpos": GposModule,
    "computers": ComputersModule,
    "users": UsersModule,
    "trusts": TrustsModule,
    "cert": CertificatesModule,
}


def resolve_order(requested: list[str]) -> list[str]:
    if "all" in requested:
        return list(SCAN_ORDER)
    return [name for name in SCAN_ORDER if name in requested]


def run(session, requested: list[str], logger) -> dict[str, list]:
    results: dict[str, list] = {}

    for name in resolve_order(requested):
        module_cls = REGISTRY[name]
        logger.info(f"[{name}] starting")
        module = module_cls()
        records = module.run(session)
        results[name] = records
        logger.info(f"[{name}] collected {len(records)} records")

    return results
