from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ADDomain:
    name: str
    dn: str | None = None
    sid: str | None = None
    functional_level: str | None = None
    password_policy: dict = field(default_factory=dict)
    smb_signing_required: bool | None = None
    os_info: dict = field(default_factory=dict)
    domain_controllers: list[dict] = field(default_factory=list)
    dns_zones: list[str] = field(default_factory=list)
    fsmo_roles: dict = field(default_factory=dict)
    authentication_security: dict = field(default_factory=dict)
    laps: dict = field(default_factory=dict)
    null_anonymous_access: dict = field(default_factory=dict)


@dataclass
class ACE:
    object_dn: str
    object_type: str
    trustee_sid: str
    trustee_name: str | None
    rights: list[str]
    ace_type: str
    inherited: bool
    object_type_guid: str | None = None


@dataclass
class ADGroup:
    dn: str
    name: str
    sid: str | None
    members: list[dict] = field(default_factory=list)
    member_of: list[str] = field(default_factory=list)
    description: str | None = None
    sam_account_name: str | None = None
    group_type: int | None = None
    security_enabled: bool = True
    admin_count: int = 0
    is_critical_system_object: bool = False
    managed_by: str | None = None
    when_created: str | None = None
    when_changed: str | None = None
    info: str | None = None
    rid: int | None = None
    primary_group_token: int | None = None
    isaclprotected: bool = False
    is_privileged: bool = False
    is_protected: bool = False


@dataclass
class ADOU:
    dn: str
    name: str
    object_guid: str | None = None
    gplink: list[dict] = field(default_factory=list)
    blocks_inheritance: bool = False
    children: list[str] = field(default_factory=list)
    child_ous: list[str] = field(default_factory=list)
    description: str | None = None
    managed_by: str | None = None
    is_critical_system_object: bool = False
    when_created: str | None = None
    when_changed: str | None = None


@dataclass
class ADGPO:
    dn: str
    name: str
    guid: str | None
    file_system_path: str | None = None
    # One entry per container that links this GPO, e.g.
    # {"dn": ..., "link_enabled": bool, "enforced": bool}; enabled/enforced
    # are per-LINK (parsed from that container's own gPLink suffix), since
    # the same GPO can be enforced on one OU and not-enforced-but-linked on
    # another - there is no single enforced/enabled value for the GPO itself.
    linked_ous: list[dict] = field(default_factory=list)
    # True unless BOTH the user and computer halves of the GPO are disabled
    # (flags == 3). This reflects the GPO object's own "flags" attribute and
    # has nothing to do with link enforcement - see linked_ous for that.
    enabled: bool = True
    user_settings_disabled: bool = False
    computer_settings_disabled: bool = False
    # Convenience roll-up: True if ANY link enforces this GPO (see
    # linked_ous for the per-link detail).
    enforced: bool = False
    is_critical_system_object: bool = False
    version_number: int | None = None
    machine_extension_names: str | None = None
    user_extension_names: str | None = None
    wmi_filter: str | None = None
    when_created: str | None = None
    when_changed: str | None = None


@dataclass
class ADComputer:
    dn: str
    name: str
    sam_account_name: str
    sid: str | None
    operating_system: str | None = None
    dns_hostname: str | None = None
    enabled: bool = True
    trusted_for_delegation: bool = False
    spns: list[str] = field(default_factory=list)
    uac: int = 0
    operating_system_version: str | None = None
    last_logon: str | None = None
    pwd_last_set: str | None = None
    description: str | None = None
    primary_group_id: int | None = None
    is_critical_system_object: bool = False
    supported_encryption_types: int | None = None
    when_created: str | None = None
    when_changed: str | None = None
    allowed_to_delegate_to: list[str] = field(default_factory=list)
    rbcd_configured: bool = False
    rbcd_enabled: bool = False
    rbcd_sddl: str | None = None
    rbcd_principals: list[str] = field(default_factory=list)
    rbcd_principal_names: list[str] = field(default_factory=list)
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)


@dataclass
class ADUser:
    dn: str
    sam_account_name: str
    sid: str | None
    display_name: str | None = None
    enabled: bool = True
    admin_count: int = 0
    spns: list[str] = field(default_factory=list)
    uac: int = 0
    member_of: list[str] = field(default_factory=list)
    pwd_last_set: str | None = None
    last_logon: str | None = None
    description: str | None = None
    mail: str | None = None
    sid_history: list[str] = field(default_factory=list)
    account_expires: str | None = None
    lockout_time: str | None = None
    bad_pwd_count: int = 0
    when_created: str | None = None
    when_changed: str | None = None
    primary_group_id: int | None = None
    supported_encryption_types: int | None = None
    home_directory: str | None = None
    script_path: str | None = None
    allowed_to_delegate_to: list[str] = field(default_factory=list)
    rbcd_configured: bool = False
    rbcd_enabled: bool = False
    rbcd_sddl: str | None = None
    rbcd_principals: list[str] = field(default_factory=list)
    rbcd_principal_names: list[str] = field(default_factory=list)
    bad_pwd_time: str | None = None
    logon_count: int | None = None
    locked_out: bool = False


@dataclass
class ADTrust:
    dn: str
    source_domain: str
    target_domain: str
    trust_direction: str
    trust_type: str
    sid_filtering: bool = True
    transitive: bool = True
    target_sid: str | None = None
    flat_name: str | None = None
    when_created: str | None = None
    when_changed: str | None = None
    forest_transitive: bool = False
    within_forest: bool = False
    uses_rc4_encryption: bool = False
    trust_attributes: int = 0
    object_guid: str | None = None
    description: str | None = None
    trust_direction_raw: int = 0
    trust_type_raw: int = 0
    selective_auth: bool = False
    forest_wide_auth: bool = True
    treat_as_external: bool = False
    uplevel_only: bool = False
    uses_aes_keys: bool = False
    pim_trust: bool = False
    tgt_delegation_enabled: bool = False
    usn_created: int | None = None
    usn_changed: int | None = None
    supported_encryption_types: int | None = None
    attributes_decoded: list[str] = field(default_factory=list)
    forest_trust_info: list[dict] = field(default_factory=list)
    risk_controls: list[str] = field(default_factory=list)
    security_posture: list[str] = field(default_factory=list)
    dangerous: bool = False


@dataclass
class Finding:
    rule: str
    severity: str
    principal: str
    target: str | None
    detail: dict = field(default_factory=dict)