"""
Collect a read-only snapshot of an Azure subscription and its Entra ID tenant for tools/audit.py.

  az login                                   # an account with the read roles listed below
  az extension add --name resource-graph
  python collect/collect.py --out snapshot/  # then: python tools/audit.py --tenant snapshot/

Status: written against the documented Microsoft Graph v1.0 and Azure Resource Graph
response shapes and exercised only against the synthetic data in this repo. It has not yet
been run against a live tenant (lab-test-pending). Every call is a GET; nothing is changed.

Read access needed:
  Azure:     Reader on the subscription (plus Security Reader for Defender plans)
  Graph:     Directory.Read.All, Policy.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory
             (signInActivity and userRegistrationDetails need Entra ID P1 or P2)
If `az rest` is refused for a Graph endpoint, the Azure CLI's own app registration lacks that
permission in your tenant; run the same GETs with Microsoft Graph PowerShell or a read-only app.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

GRAPH = "https://graph.microsoft.com/v1.0/"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

GRAPH_LISTS = {
    "users.json": "users?$select=id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,signInActivity&$top=999",
    "user_registration_details.json": "reports/authenticationMethods/userRegistrationDetails",
    "role_definitions.json": "roleManagement/directory/roleDefinitions",
    "role_assignments.json": "roleManagement/directory/roleAssignments",
    "role_eligibility_schedules.json": "roleManagement/directory/roleEligibilitySchedules",
    "conditional_access_policies.json": "identity/conditionalAccess/policies",
    "applications.json": "applications?$select=id,appId,displayName,passwordCredentials,requiredResourceAccess&$top=999",
}

ARG_QUERIES = {
    "storage_accounts.json": "microsoft.storage/storageaccounts",
    "network_security_groups.json": "microsoft.network/networksecuritygroups",
    "key_vaults.json": "microsoft.keyvault/vaults",
    "sql_servers.json": "microsoft.sql/servers",
}


def az(*args: str):
    r = subprocess.run(["az", *args, "--output", "json"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"az {' '.join(args[:3])} failed: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def graph_get(path: str):
    return az("rest", "--method", "get", "--url", path if path.startswith("http") else GRAPH + path)


def graph_list(path: str) -> dict:
    """Follow @odata.nextLink so large tenants are collected completely."""
    page = graph_get(path)
    items = list(page.get("value", []))
    while page.get("@odata.nextLink"):
        page = graph_get(page["@odata.nextLink"])
        items += page.get("value", [])
    return {"value": items}


def resource_graph(rtype: str) -> dict:
    query = (f"resources | where type =~ '{rtype}' "
             "| project id, name, type, resourceGroup, location, properties")
    rows, skip = [], None
    while True:
        args = ["graph", "query", "-q", query, "--first", "1000"]
        if skip:
            args += ["--skip-token", skip]
        page = az(*args)
        rows += page.get("data", [])
        skip = page.get("skip_token")
        if not skip:
            return {"data": rows}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    def save(name, obj):
        (out / name).write_text(json.dumps(obj, indent=2) + "\n")
        print(f"  {name}")

    account = az("account", "show")
    errors = []
    for name, path in GRAPH_LISTS.items():
        try:
            save(name, graph_list(path))
        except RuntimeError as e:
            errors.append(f"{name}: {e}")
    try:
        save("authorization_policy.json", graph_get("policies/authorizationPolicy"))
        graph_sp = graph_get(f"servicePrincipals(appId='{GRAPH_APP_ID}')?$select=id,appId,displayName,appRoles")
        save("graph_service_principal.json", graph_sp)
        save("app_role_assignments.json", graph_list(f"servicePrincipals/{graph_sp['id']}/appRoleAssignedTo"))
    except RuntimeError as e:
        errors.append(str(e))
    for name, rtype in ARG_QUERIES.items():
        try:
            save(name, resource_graph(rtype))
        except RuntimeError as e:
            errors.append(f"{name}: {e}")
    try:
        servers = json.loads((out / "sql_servers.json").read_text())["data"]
        save("sql_auditing.json", [{"server": s["name"], "state": (az("sql", "server", "audit-policy", "show",
                                    "--ids", s["id"]) or {}).get("state")} for s in servers])
    except (RuntimeError, FileNotFoundError, KeyError) as e:
        errors.append(f"sql_auditing.json: {e}")
    for name, cmd in {"defender_pricing.json": ["security", "pricing", "list"],
                      "subscription_diagnostic_settings.json": ["monitor", "diagnostic-settings", "subscription", "list"]}.items():
        try:
            save(name, az(*cmd))
        except RuntimeError as e:
            errors.append(f"{name}: {e}")
    save("metadata.json", {"tenant": account.get("tenantDisplayName") or account.get("tenantId"),
                           "subscription": f"/subscriptions/{account['id']}",
                           "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "synthetic": False})
    if errors:
        print("\nSome calls failed; the matching checks will show N/A or incomplete results:")
        print("  " + "\n  ".join(errors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
