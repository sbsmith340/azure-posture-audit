"""Each check must fail on a misconfiguration and pass once it is fixed, not just pass on the sample data."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TENANT = ROOT / "data" / "tenant"
sys.path.insert(0, str(ROOT / "tools"))
import audit  # noqa: E402

EXPECTED_FAIL = {"IAM-02", "IAM-04", "IAM-05", "IAM-06", "IAM-08", "IAM-09", "IAM-10",
                 "APP-02", "APP-03", "NET-01", "STG-01", "DEF-01"}


def results_for(folder):
    _, results = audit.run(folder)
    return {r["id"]: r for r in results}


BASE = results_for(TENANT)


@pytest.fixture
def tenant(tmp_path):
    dst = tmp_path / "tenant"
    shutil.copytree(TENANT, dst)
    return dst


def edit(folder, name, fn):
    p = folder / name
    obj = json.loads(p.read_text())
    fn(obj)
    p.write_text(json.dumps(obj))


def test_reports_are_current():
    snap, results = audit.run(TENANT)
    for path, text in audit.outputs(snap, results).items():
        assert (ROOT / path).read_text() == text, f"{path} is stale"


def test_dataset_is_reproducible():
    before = {p.name: p.read_bytes() for p in TENANT.glob("*.json")}
    subprocess.run([sys.executable, str(ROOT / "data" / "generate.py")], check=True)
    assert {p.name: p.read_bytes() for p in TENANT.glob("*.json")} == before


def test_every_check_is_documented():
    ids = [c.id for c in audit.CHECKS]
    assert len(ids) == len(set(ids))
    for c in audit.CHECKS:
        assert c.severity in audit.SEVERITIES and c.controls and c.why and c.fix, c.id


def test_sample_tenant_results():
    assert {i for i, r in BASE.items() if r["status"] == "FAIL"} == EXPECTED_FAIL


def test_specific_findings():
    def resources(cid):
        return {f["resource"] for f in BASE[cid]["findings"]}
    assert resources("NET-01") == {"nsg-jump", "nsg-build"}          # nsg-web's SSH rule is bastion-only
    assert resources("APP-03") == {"HR Directory Connector", "Legacy Mail Relay"}  # Mail.Read and User.Read.All are not high-risk
    assert "former.contractor@contosofield.example" not in resources("IAM-08")      # disabled accounts are ignored
    assert "svc-scanner@contosofield.example" in resources("IAM-08")                # never signed in
    assert not any("break-glass" in r for r in resources("IAM-06"))                # break-glass may be permanent


# (check, file, mutation) that must turn a passing check into a failing one
BREAK = [
    ("IAM-01", "conditional_access_policies.json", lambda o: o["value"][0].update(state="disabled")),
    ("IAM-03", "conditional_access_policies.json",
     lambda o: o["value"][2]["grantControls"].update(authenticationStrength=None, builtInControls=["mfa"])),
    ("IAM-07", "user_registration_details.json",
     lambda o: [u.update(isMfaRegistered=False) for u in o["value"] if u["userPrincipalName"].startswith("dev.patel")]),
    ("APP-01", "applications.json",
     lambda o: o["value"][0]["passwordCredentials"][0].update(endDateTime="2026-10-15T00:00:00Z")),
    ("STG-02", "storage_accounts.json", lambda o: o["data"][0]["properties"].update(minimumTlsVersion="TLS1_0")),
    ("STG-03", "storage_accounts.json", lambda o: o["data"][0]["properties"].update(supportsHttpsTrafficOnly=False)),
    ("STG-04", "storage_accounts.json", lambda o: o["data"][0]["properties"].pop("allowSharedKeyAccess")),
    ("KV-01", "key_vaults.json", lambda o: o["data"][1]["properties"].update(enablePurgeProtection=None)),
    ("KV-02", "key_vaults.json", lambda o: o["data"][0]["properties"].update(publicNetworkAccess="Enabled")),
    ("SQL-01", "sql_servers.json", lambda o: o["data"][0]["properties"].update(publicNetworkAccess="Enabled")),
    ("SQL-02", "sql_auditing.json", lambda o: o[0].update(state="Disabled")),
    ("LOG-01", "subscription_diagnostic_settings.json", lambda o: o["value"][0].update(workspaceId=None)),
]

# (check, file, mutation) that must turn a failing check into a passing one
FIX = [
    ("IAM-02", "conditional_access_policies.json", lambda o: o["value"][1].update(state="enabled")),
    ("IAM-10", "authorization_policy.json", lambda o: o["defaultUserRolePermissions"].update(
        permissionGrantPoliciesAssigned=["ManagePermissionGrantsForSelf.microsoft-user-default-low"])),
    ("STG-01", "storage_accounts.json", lambda o: o["data"][1]["properties"].update(allowBlobPublicAccess=False)),
    ("DEF-01", "defender_pricing.json",
     lambda o: [p.update(pricingTier="Standard") for p in o["value"] if p["name"] == "StorageAccounts"]),
    ("NET-01", "network_security_groups.json", lambda o: [
        r["properties"].update(sourceAddressPrefix="10.20.0.0/27") for n in o["data"] for r in n["properties"]["securityRules"]]),
    ("APP-02", "applications.json",
     lambda o: o["value"][1]["passwordCredentials"][0].update(startDateTime="2026-06-01T00:00:00Z")),
]


@pytest.mark.parametrize("cid,name,mutate", BREAK, ids=[b[0] for b in BREAK])
def test_passing_check_fails_when_misconfigured(tenant, cid, name, mutate):
    assert BASE[cid]["status"] == "PASS"
    edit(tenant, name, mutate)
    assert results_for(tenant)[cid]["status"] == "FAIL"


@pytest.mark.parametrize("cid,name,mutate", FIX, ids=[f[0] for f in FIX])
def test_failing_check_passes_when_fixed(tenant, cid, name, mutate):
    assert BASE[cid]["status"] == "FAIL"
    edit(tenant, name, mutate)
    assert results_for(tenant)[cid]["status"] == "PASS"


def test_global_admin_count_bounds(tenant):
    def keep(n):
        def fn(o):
            ga = "62e90394-69f5-4237-9190-012177145e10"
            gas = [a for a in o["value"] if a["roleDefinitionId"] == ga]
            o["value"] = [a for a in o["value"] if a["roleDefinitionId"] != ga] + gas[:n]
        return fn
    edit(tenant, "role_assignments.json", keep(1))
    assert results_for(tenant)["IAM-05"]["status"] == "FAIL"        # one is a lockout risk
    shutil.copy(TENANT / "role_assignments.json", tenant / "role_assignments.json")
    edit(tenant, "role_assignments.json", keep(3))
    assert results_for(tenant)["IAM-05"]["status"] == "PASS"


@pytest.mark.parametrize("spec,exposed", [("22", True), ("20-25", True), ("*", True), ("3389", True),
                                          ("443", False), ("8080-8090", False)])
def test_port_range_parsing(spec, exposed):
    rule = {"properties": {"destinationPortRange": spec, "destinationPortRanges": []}}
    hits = any(a <= p <= b for a, b in audit._ports(rule) for p in audit.ADMIN_PORTS)
    assert hits == exposed


def test_missing_files_do_not_crash(tmp_path):
    (tmp_path / "metadata.json").write_text(json.dumps({"collected_at": "2026-10-01T00:00:00Z"}))
    _, results = audit.run(tmp_path)
    assert len(results) == len(audit.CHECKS)
    by_id = {r["id"]: r for r in results}
    assert by_id["SQL-02"]["status"] == "N/A" and by_id["KV-01"]["status"] == "N/A"


def test_collector_is_read_only():
    src = (ROOT / "collect" / "collect.py").read_text()
    compile(src, "collect.py", "exec")
    assert '"--method", "get"' in src
    for verb in ("post", "put", "patch", "delete"):
        assert f'"--method", "{verb}"' not in src.lower()
    assert '"create"' not in src and '"update"' not in src and '"set"' not in src
