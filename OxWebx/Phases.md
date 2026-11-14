# OxWebx Phases

This file tracks the phases implemented by each OxWebx module. New phases must be added under the section for their owning module.

## whois_ip

The `whois_ip` selection is exposed by the CLI as `whois` and runs the `whois_dns` module.

Use `python oxwebx.py TARGET -m whois --phase PHASE` to run only one phase. For example, `python oxwebx.py example.com -m whois --phase records` runs only DNS Records.

Use `python oxwebx.py -i targets.txt -m whois --phase records` to run the selected phase for every domain or IP listed in the input file. Each Whois/DNS report is written as `{target}_whois_dns.json`.

### 1. DNS Records

Collects and analyzes the following DNS record types according to the active profile:

Core records:

`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`, `SRV`, `CAA`

Security records:

`DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `CDNSKEY`, `CDS`, `TLSA`, `SSHFP`, `SMIMEA`, `OPENPGPKEY`, `IPSECKEY`

Service records:

`HTTPS`, `SVCB`, `NAPTR`, `URI`, `LOC`, `HINFO`, `RP`

Legacy records:

`AFSDB`, `CERT`, `DNAME`, `HIP`, `KX`, `DHCID`, `CSYNC`, `ZONEMD`, `EUI48`, `EUI64`, `NID`, `L32`, `L64`, `LP`, `WKS`, `X25`, `ISDN`, `RT`, `NSAP`, `APL`, `GPOS`, `A6`

The module also performs SRV service discovery for SIP, XMPP, CalDAV, CardDAV, LDAP, Kerberos, Global Catalog, HTTP, HTTPS, Autodiscover, mail submission, IMAP, POP3, and Matrix service prefixes.

Checks for NXDOMAIN responses, missing CAA policy, exposed HINFO data, RP contact mailboxes, VoIP NAPTR records, directory-service records, service discovery records, and abnormal SOA negative caching values.

Additional record analysis:

- Address records: private or reserved addresses in public DNS, missing IPv6, CNAME at the zone apex, long CNAME chains.
- Nameservers: single nameserver, nameservers in one network prefix, lame delegations and inconsistent SOA serials when active checks are allowed.
- Mail exchangers: missing MX, null MX, MX pointing to an IP address, single self-managed MX.
- SOA: abnormal serials, timers outside RFC 1912 ranges, exposed administrator mailbox.
- TXT: third-party verification tokens matched against `signatures/dns/txt_vendors.json`, tokens of discontinued or unused services, credential-like data, internal hostnames and addresses, oversized and duplicated records.
- Service discovery: legacy collaboration targets, plaintext services, external autodiscover, non-standard ports (`signatures/dns/service_policy.json`).
- CAA: wildcard issuance open to many authorities, unrecognized authorities (`signatures/dns/caa_policy.json`), critical flag on unknown tags.
- Service and legacy records: HTTPS records without ECH, legacy ALPN, obsolete record types, exposed LOC and WKS data (`signatures/dns/legacy_records.json`).
- Wildcard behavior for address and MX records and unusually large record sets.

### 2. WHOIS and RDAP

Retrieves domain registration data from RDAP and WHOIS over port 43 when enabled.

Collects registrar information, IANA registrar ID, registration dates, expiry dates, domain status, nameservers, DNSSEC delegation state, WHOIS server references, contacts, privacy indicators, and raw registration data.

Checks for expired domains, imminent expiry, recently registered domains, missing registration data, weak registration security indicators, and exposed registration contacts.

Additional checks: untrusted or missing registrar (`signatures/dns/registrar_watchlist.json`), registry nameservers that differ from live delegation, DNSSEC state that disagrees with DS records, renewal prohibition statuses, and long registration terms.

### 3. Email Security

Analyzes SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI configuration.

Checks for missing policies, multiple SPF records, permissive SPF mechanisms, neutral or softfail policies, missing terminating mechanisms, excessive SPF DNS lookups, deprecated `ptr` usage, weak DMARC policies, missing reporting addresses, DKIM selector issues, and missing transport security policies.

Additional checks: SPF include loops, SPF void lookups, DMARC applied to a minority of mail, missing DKIM selectors for domains that receive mail, missing TLS-RPT, and invalid BIMI records.

### 4. Reverse DNS

Resolves target IP addresses to PTR hostnames and performs forward-confirmation.

For domain targets, it starts with A and AAAA records. For IP targets, it starts with the supplied address. It then resolves discovered PTR names back to A and AAAA records to identify related IP addresses.

Checks for private or reserved addresses in public DNS, PTR naming leaks, internal environment names, datacenter identifiers, sequential hostnames, and forward-confirmation mismatches.

Additional checks: missing PTR records and generic provider-assigned PTR names (`signatures/dns/hosting_providers.json`).

### 5. IP Intelligence

Collects ASN, autonomous system name, ISP, organization, country, region, city, coordinates, timezone, hosting classification, proxy/VPN indicators, mobile indicators, CIDR range, RDAP range, and RDAP remarks.

Uses the configured IP intelligence providers and shares normalized records with other checks.

Checks for addresses served from multiple countries, proxy or VPN classifications, hosting indicators, private addresses, and inconsistent provider information.

Additional checks: commodity hosting providers and addresses of one host spread across several networks, including mixed edge and origin networks.

### 6. CDN Detection

Identifies CDN and reverse-proxy usage through nameserver, ASN, IP, response header, and HTTP probe signals.

Collects the detected provider, matching indicators, resolved addresses, response headers, and origin-related evidence.

Checks for CDN misconfiguration, exposed origin addresses, inconsistent CDN signals, and direct origin accessibility when active probing is enabled.

### 7. Zone Transfer

Attempts AXFR and optionally IXFR requests against authoritative nameservers when active checks are allowed.

Collects nameserver attempt status, transfer errors, record counts, record samples, and legacy ANY query responses.

Checks for successful unauthenticated zone transfers and excessive DNS ANY response disclosure.

### 8. DNSSEC

Analyzes DNSKEY, DS, RRSIG, NSEC, NSEC3, SSHFP, and TLSA records.

Checks DNSSEC chain completeness, signing algorithms, DS digest algorithms, RRSIG expiration, NSEC zone walking, NSEC3 opt-out, NSEC3 iteration counts, SSHFP hash strength, and TLSA/DANE validation support.

### 9. TTL Anomaly

Probes repeated DNS responses to measure TTL behavior and address stability.

Collects observed TTL values, minimum and maximum TTLs, response samples, address changes, and probe timing.

Checks for very low TTL values, unusually low TTL values, excessive IP changes, and unstable DNS behavior.

Additional checks: short NS and MX TTLs and different TTLs for A and AAAA records.

### 10. Dangling Infrastructure

Checks candidate subdomains, CNAME chains, wildcard behavior, nameserver delegations, MX records, and SRV targets.

Collects dangling targets, service fingerprints, HTTP liveness results, wildcard results, nameserver registration state, mail exchanger resolution, and SRV reachability.

Checks for possible subdomain takeover, unregistered nameserver domains, unresolved MX hosts, unreachable SRV targets, and takeover service fingerprints.

Additional checks: wildcard CNAMEs to takeover-prone services and CNAME targets whose registered domain is unregistered.

### 11. Blacklist Reputation

Queries configured DNSBL and URIBL zones for target IP addresses and the registered domain.

Collects queried lists, zones, query names, response types, DNS responses, checked IP addresses, and reputation score.

Checks whether target infrastructure or domain data appears on configured reputation lists.

### 12. Historical Intelligence

Retrieves registration events from RDAP and archive presence from the Wayback Machine.

Optionally retrieves historical WHOIS snapshots through the configured WHOISFreaks API key.

Collects first and latest archive dates, archive age, registration events, registrar changes, historical expiry data, historical nameservers, registrants, and source metadata.

Checks for registrar changes, registrant changes, recent nameserver changes, and long gaps in archive activity.

### 13. Cross-Search

Pivots from nameservers, IP addresses, and ASN information to discover related domains and infrastructure.

Uses configured passive sources such as HackerTarget and RIPE Stat.

Collects pivot values, related domains, source attribution, announced prefixes, errors, and total related-domain counts.

Checks for unusually broad shared infrastructure footprints that may indicate shared hosting or common ownership, and for addresses shared with many unrelated domains.
