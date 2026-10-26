"""
Generate a synthetic tenant snapshot for the fictional Contoso Field Services.

  python data/generate.py

Each file mirrors the shape of the raw API response that collect/collect.sh saves
(Microsoft Graph v1.0 responses wrap results in "value"; Azure Resource Graph
results come back in "data"), so the same audit code runs on either.

The tenant is scripted, not random: every check has at least one resource that
passes and, for most checks, at least one that fails. Names, IDs and domains are
fictional; GUIDs are deterministic (uuid5) so the output never changes.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

OUT = Path(__file__).resolve().parent / "tenant"
NS = uuid.UUID("2b0c6f1e-7d3a-4c59-8e21-5a9f3d7b6c40")
SUB = "/subscriptions/" + str(uuid.uuid5(NS, "subscription"))
DOMAIN = "contosofield.example"
COLLECTED_AT = "2026-10-01T12:00:00Z"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# Microsoft Graph application permissions (app roles) used in the scenario.
GRAPH_ROLES = {
    "Directory.ReadWrite.All": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
    "Mail.ReadWrite": "e2a3a72e-5f79-4c64-b1b1-878b674786c9",
    "Mail.Send": "b633e1c5-b582-4048-a93e-9f11b44c7e96",
    "Mail.Read": "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
    "RoleManagement.ReadWrite.Directory": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "Application.ReadWrite.All": "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
}
ROLE_DEFS = {  # directory role template IDs are fixed across tenants
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Security Administrator": "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
}


def gid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "/".join(parts)))


def upn(name: str) -> str:
    return f"{name}@{DOMAIN}"


# name, type, enabled, last sign-in (None = never), MFA registered, methods
USERS = [
    ("maria.lopez", "Member", True, "2026-09-30T14:02:00Z", True, ["microsoftAuthenticatorPush", "fido2"]),
    ("dev.patel", "Member", True, "2026-09-29T09:15:00Z", True, ["fido2", "windowsHelloForBusiness"]),
    ("break-glass-01", "Member", True, "2026-08-15T10:00:00Z", True, ["fido2"]),
    ("tom.becker", "Member", True, "2026-09-28T16:40:00Z", True, ["microsoftAuthenticatorPush"]),
    ("aisha.khan", "Member", True, "2026-09-30T08:05:00Z", True, ["microsoftAuthenticatorPush"]),
    ("old.admin", "Member", True, "2026-03-02T11:20:00Z", True, ["mobilePhone"]),
    ("jenna.ortiz", "Member", True, "2026-09-27T13:00:00Z", True, ["microsoftAuthenticatorPush"]),
    ("sam.reed", "Member", True, "2026-05-10T07:45:00Z", True, ["microsoftAuthenticatorPush"]),
    ("former.contractor", "Member", False, "2026-01-12T09:00:00Z", True, ["mobilePhone"]),
    ("svc-scanner", "Member", True, None, False, []),
    ("partner.auditor_fabrikam.example#EXT#", "Guest", True, "2026-09-20T15:30:00Z", True, ["microsoftAuthenticatorPush"]),
    ("kim.nguyen", "Member", True, "2026-09-30T17:10:00Z", True, ["microsoftAuthenticatorPush"]),
]

# user, role, active (permanent) or eligible (PIM)
ROLE_ASSIGNMENTS = [
    ("maria.lopez", "Global Administrator", "active"),
    ("break-glass-01", "Global Administrator", "active"),
    ("tom.becker", "Global Administrator", "active"),
    ("old.admin", "Global Administrator", "active"),
    ("aisha.khan", "Global Administrator", "active"),
    ("dev.patel", "Privileged Role Administrator", "eligible"),
    ("jenna.ortiz", "Security Administrator", "eligible"),
    ("partner.auditor_fabrikam.example#EXT#", "Exchange Administrator", "active"),
    ("kim.nguyen", "User Administrator", "eligible"),
]

PHISH_RESISTANT = {"id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA"}
CA_POLICIES = [
    dict(name="CA001 Require MFA for all users", state="enabled",
         users={"includeUsers": ["All"], "excludeUsers": [gid("user", "break-glass-01")]},
         clientAppTypes=["all"], grant={"operator": "OR", "builtInControls": ["mfa"]}),
    dict(name="CA002 Block legacy authentication", state="enabledForReportingButNotEnforced",
         users={"includeUsers": ["All"], "excludeUsers": []},
         clientAppTypes=["exchangeActiveSync", "other"], grant={"operator": "OR", "builtInControls": ["block"]}),
    dict(name="CA003 Phishing-resistant MFA for administrators", state="enabled",
         users={"includeRoles": list(ROLE_DEFS.values()),
                "excludeUsers": [gid("user", "break-glass-01")]},
         clientAppTypes=["all"], grant={"operator": "OR", "builtInControls": [], "authenticationStrength": PHISH_RESISTANT}),
    dict(name="CA004 Require compliant device for Exchange Online", state="disabled",
         users={"includeUsers": ["All"]}, clientAppTypes=["all"],
         grant={"operator": "OR", "builtInControls": ["compliantDevice"]}),
]

# displayName, permissions requested and granted (app roles), secrets (start, end)
APPS = [
    ("Field Inspection Sync", ["User.Read.All"], [("2026-03-01T00:00:00Z", "2027-03-01T00:00:00Z")]),
    ("Legacy Mail Relay", ["Mail.ReadWrite", "Mail.Send"], [("2024-06-01T00:00:00Z", "2026-11-15T00:00:00Z")]),
    ("HR Directory Connector", ["Directory.ReadWrite.All"], [("2026-01-10T00:00:00Z", "2027-01-10T00:00:00Z")]),
    ("Reporting Dashboard", ["Mail.Read"], [("2026-04-01T00:00:00Z", "2027-04-01T00:00:00Z")]),
    ("Automation Runner", [], [("2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z")]),
]

STORAGE = [
    ("stfieldphotos01", dict(allowBlobPublicAccess=False, minimumTlsVersion="TLS1_2", supportsHttpsTrafficOnly=True,
                             allowSharedKeyAccess=False, publicNetworkAccess="Disabled")),
    ("stpublicforms01", dict(allowBlobPublicAccess=True, minimumTlsVersion="TLS1_2", supportsHttpsTrafficOnly=True,
                             allowSharedKeyAccess=False, publicNetworkAccess="Enabled")),
    ("stexport01", dict(allowBlobPublicAccess=False, minimumTlsVersion="TLS1_2", supportsHttpsTrafficOnly=True,
                        allowSharedKeyAccess=False, publicNetworkAccess="Disabled")),
    ("stauditlogs01", dict(allowBlobPublicAccess=False, minimumTlsVersion="TLS1_2", supportsHttpsTrafficOnly=True,
                           allowSharedKeyAccess=False, publicNetworkAccess="Disabled")),
]

NSGS = [
    ("nsg-web", [("AllowHttpsInbound", "Inbound", "Allow", "Internet", "443", []),
                 ("AllowSshFromBastion", "Inbound", "Allow", "10.20.0.0/27", "22", [])]),
    ("nsg-jump", [("AllowRdpAnywhere", "Inbound", "Allow", "*", "3389", [])]),
    ("nsg-build", [("AllowMgmtPorts", "Inbound", "Allow", "0.0.0.0/0", "", ["22", "8080-8090"]),
                   ("DenyAllInbound", "Inbound", "Deny", "*", "*", [])]),
]

KEY_VAULTS = [
    ("kv-fip-prod", dict(enableSoftDelete=True, enablePurgeProtection=True, publicNetworkAccess="Disabled")),
    ("kv-fip-dev", dict(enableSoftDelete=True, enablePurgeProtection=True, publicNetworkAccess="Disabled")),
    ("kv-automation", dict(enableSoftDelete=True, enablePurgeProtection=True, publicNetworkAccess="Disabled")),
]

SQL_SERVERS = [
    ("sql-fip-prod", dict(publicNetworkAccess="Disabled", minimalTlsVersion="1.2"), "Enabled"),
    ("sql-reporting", dict(publicNetworkAccess="Disabled", minimalTlsVersion="1.2"), "Enabled"),
]

DEFENDER = [("VirtualMachines", "Standard"), ("SqlServers", "Standard"), ("StorageAccounts", "Free"),
            ("KeyVaults", "Standard"), ("Arm", "Standard"), ("Containers", "Free")]


def arm(rtype: str, name: str, rg: str, props: dict) -> dict:
    return {"id": f"{SUB}/resourceGroups/{rg}/providers/{rtype}/{name}", "name": name, "type": rtype.lower(),
            "resourceGroup": rg, "location": "eastus2", "properties": props}


def write(name: str, obj) -> None:
    (OUT / name).write_text(json.dumps(obj, indent=2) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write("metadata.json", {"tenant": "Contoso Field Services (fictional)", "domain": DOMAIN,
                            "subscription": SUB, "collected_at": COLLECTED_AT, "synthetic": True})
    users = []
    for name, utype, enabled, last, _, _ in USERS:
        users.append({"id": gid("user", name), "userPrincipalName": upn(name), "displayName": name.split("_")[0],
                      "accountEnabled": enabled, "userType": utype, "createdDateTime": "2024-02-01T00:00:00Z",
                      "signInActivity": {"lastSignInDateTime": last, "lastNonInteractiveSignInDateTime": last}})
    write("users.json", {"value": users})
    write("user_registration_details.json", {"value": [
        {"id": gid("user", n), "userPrincipalName": upn(n), "isMfaRegistered": mfa, "methodsRegistered": methods,
         "isAdmin": any(a[0] == n for a in ROLE_ASSIGNMENTS)}
        for n, _, _, _, mfa, methods in USERS]})
    write("role_definitions.json", {"value": [{"id": rid, "templateId": rid, "displayName": nm}
                                              for nm, rid in ROLE_DEFS.items()]})
    write("role_assignments.json", {"value": [
        {"id": gid("assign", u, r), "principalId": gid("user", u), "roleDefinitionId": ROLE_DEFS[r], "directoryScopeId": "/"}
        for u, r, kind in ROLE_ASSIGNMENTS if kind == "active"]})
    write("role_eligibility_schedules.json", {"value": [
        {"id": gid("elig", u, r), "principalId": gid("user", u), "roleDefinitionId": ROLE_DEFS[r], "directoryScopeId": "/",
         "memberType": "Direct", "status": "Provisioned"}
        for u, r, kind in ROLE_ASSIGNMENTS if kind == "eligible"]})
    write("conditional_access_policies.json", {"value": [
        {"id": gid("ca", p["name"]), "displayName": p["name"], "state": p["state"],
         "conditions": {"users": {"includeUsers": [], "excludeUsers": [], "includeRoles": [], "excludeRoles": [], **p["users"]},
                        "applications": {"includeApplications": ["All"]}, "clientAppTypes": p["clientAppTypes"]},
         "grantControls": {"authenticationStrength": None, **p["grant"]}}
        for p in CA_POLICIES]})
    write("authorization_policy.json", {"id": "authorizationPolicy", "defaultUserRolePermissions": {
        "allowedToCreateApps": True,
        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}})
    write("graph_service_principal.json", {"appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appRoles": [
        {"id": rid, "value": nm, "allowedMemberTypes": ["Application"]} for nm, rid in GRAPH_ROLES.items()]})
    apps, grants = [], []
    for name, perms, secrets in APPS:
        app_id = gid("app", name)
        apps.append({"id": gid("appobj", name), "appId": app_id, "displayName": name,
                     "passwordCredentials": [{"keyId": gid("secret", name, s), "displayName": "client secret",
                                              "startDateTime": s, "endDateTime": e} for s, e in secrets],
                     "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": [
                         {"id": GRAPH_ROLES[p], "type": "Role"} for p in perms]}] if perms else []})
        for p in perms:  # admin consent granted for every requested permission in this tenant
            grants.append({"id": gid("grant", name, p), "principalDisplayName": name, "principalId": gid("sp", name),
                           "appId": app_id, "resourceDisplayName": "Microsoft Graph", "appRoleId": GRAPH_ROLES[p]})
    write("applications.json", {"value": apps})
    write("app_role_assignments.json", {"value": grants})
    write("storage_accounts.json", {"data": [arm("Microsoft.Storage/storageAccounts", n, "rg-fip-data", p)
                                             for n, p in STORAGE]})
    write("network_security_groups.json", {"data": [arm("Microsoft.Network/networkSecurityGroups", n, "rg-fip-network", {
        "securityRules": [{"name": rn, "properties": {"direction": d, "access": a, "sourceAddressPrefix": src,
                                                      "destinationPortRange": port, "destinationPortRanges": ranges,
                                                      "protocol": "Tcp", "priority": 100 + i * 10}}
                          for i, (rn, d, a, src, port, ranges) in enumerate(rules)]}) for n, rules in NSGS]})
    write("key_vaults.json", {"data": [arm("Microsoft.KeyVault/vaults", n, "rg-fip-security", p) for n, p in KEY_VAULTS]})
    write("sql_servers.json", {"data": [arm("Microsoft.Sql/servers", n, "rg-fip-data", p) for n, p, _ in SQL_SERVERS]})
    write("sql_auditing.json", [{"server": n, "state": a} for n, _, a in SQL_SERVERS])
    write("defender_pricing.json", {"value": [{"name": n, "pricingTier": t} for n, t in DEFENDER]})
    write("subscription_diagnostic_settings.json", {"value": [
        {"name": "to-sentinel", "storageAccountId": None,
         "workspaceId": f"{SUB}/resourceGroups/rg-fip-security/providers/Microsoft.OperationalInsights/workspaces/law-fip-sentinel", "logs": [{"category": "Administrative", "enabled": True}, {"category": "Security", "enabled": True}]}]})


if __name__ == "__main__":
    main()
