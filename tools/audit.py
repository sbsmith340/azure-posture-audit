"""
Audit an Azure / Entra ID tenant snapshot against a set of security checks.

  python tools/audit.py                     # audit data/tenant, write reports/
  python tools/audit.py --tenant DIR        # audit a snapshot saved by collect/collect.sh
  python tools/audit.py --check             # CI: write nothing, fail if reports/ is stale

Each check is a small function registered with @check. It receives the snapshot and
returns (resources evaluated, findings). Checks never call Azure; they read the JSON
files that collect/collect.sh saves, so an audit is repeatable and reviewable.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEVERITIES = ["High", "Moderate", "Low"]
PRIVILEGED_ROLES = {"Global Administrator", "Privileged Role Administrator", "Security Administrator",
                    "Exchange Administrator", "User Administrator", "Application Administrator",
                    "Cloud Application Administrator", "Conditional Access Administrator",
                    "Authentication Administrator", "Privileged Authentication Administrator",
                    "SharePoint Administrator", "Intune Administrator"}
HIGH_RISK_GRAPH_PERMISSIONS = {"Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
                               "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
                               "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.ReadWrite.All"}
INTERNET = {"*", "Internet", "0.0.0.0/0", "Any", "any"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
STALE_DAYS = 90
SECRET_MAX_DAYS = 365
SECRET_WARN_DAYS = 30
DEFENDER_REQUIRED = ["VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults"]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    controls: tuple[str, ...]
    why: str
    fix: str
    fn: object


CHECKS: list[Check] = []


def check(id, title, severity, controls, why, fix):
    def deco(fn):
        CHECKS.append(Check(id, title, severity, tuple(controls), why, fix, fn))
        return fn
    return deco


# --------------------------------------------------------------------------- snapshot
class Snapshot:
    def __init__(self, folder: Path):
        self.folder = folder
        self.meta = self._load("metadata.json", {})
        self.now = parse_time(self.meta.get("collected_at")) if self.meta.get("collected_at") else datetime.utcnow()

    def _load(self, name, default=None):
        p = self.folder / name
        return json.loads(p.read_text()) if p.exists() else default

    def rows(self, name):
        """Graph responses use {"value": [...]}; Resource Graph uses {"data": [...]}; some CLI calls return a list."""
        obj = self._load(name, [])
        if isinstance(obj, dict):
            return obj.get("value", obj.get("data", []))
        return obj

    def raw(self, name):
        return self._load(name, {})

    # helpers shared by several checks
    def users(self):
        return {u["id"]: u for u in self.rows("users.json")}

    def role_names(self):
        return {r["id"]: r["displayName"] for r in self.rows("role_definitions.json")} | \
               {r.get("templateId", r["id"]): r["displayName"] for r in self.rows("role_definitions.json")}

    def assignments(self):
        """(principalId, role name, kind) for permanent ('active') and PIM-eligible assignments."""
        names = self.role_names()
        out = [(a["principalId"], names.get(a["roleDefinitionId"], a["roleDefinitionId"]), "active")
               for a in self.rows("role_assignments.json")]
        out += [(a["principalId"], names.get(a["roleDefinitionId"], a["roleDefinitionId"]), "eligible")
                for a in self.rows("role_eligibility_schedules.json")]
        return out


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)


def upn(snap: Snapshot, pid: str) -> str:
    return snap.users().get(pid, {}).get("userPrincipalName", pid)


# --------------------------------------------------------------------------- identity checks
def _enabled_ca(snap):
    return [p for p in snap.rows("conditional_access_policies.json") if p.get("state") == "enabled"]


def _applies_to_all(p) -> bool:
    u = p["conditions"]["users"]
    return "All" in (u.get("includeUsers") or [])


def _grant(p) -> tuple[set, str]:
    g = p.get("grantControls") or {}
    strength = (g.get("authenticationStrength") or {}).get("displayName", "")
    return set(g.get("builtInControls") or []), strength


@check("IAM-01", "Conditional Access requires MFA for all users", "High", ["IA-2(1)", "IA-2(2)"],
       "Without a tenant-wide MFA policy, one phished password is a full account takeover.",
       "Create an enabled Conditional Access policy for All users and All cloud apps that requires MFA "
       "(or an authentication strength); exclude only break-glass accounts.")
def iam01(snap):
    ok = [p for p in _enabled_ca(snap) if _applies_to_all(p)
          and ("mfa" in _grant(p)[0] or _grant(p)[1])
          and "All" in p["conditions"]["applications"].get("includeApplications", [])]
    return 1, [] if ok else [("tenant", "No enabled policy requires MFA for All users and All cloud apps.")]


@check("IAM-02", "Legacy authentication is blocked", "High", ["IA-2", "AC-17"],
       "Legacy protocols (IMAP, POP, SMTP AUTH, older Office clients) cannot do MFA, so they bypass it.",
       "Enable a Conditional Access policy for All users with client apps 'Exchange ActiveSync' and "
       "'Other clients' and grant control 'Block'.")
def iam02(snap):
    policies = snap.rows("conditional_access_policies.json")
    blocking = [p for p in policies if _applies_to_all(p) and "block" in _grant(p)[0]
                and {"exchangeActiveSync", "other"} <= set(p["conditions"].get("clientAppTypes", []))]
    if any(p["state"] == "enabled" for p in blocking):
        return 1, []
    if blocking:
        names = ", ".join(f"'{p['displayName']}' ({p['state']})" for p in blocking)
        return 1, [("tenant", f"A legacy-auth block policy exists but is not enforced: {names}.")]
    return 1, [("tenant", "No policy blocks legacy authentication clients.")]


@check("IAM-03", "Administrators must use phishing-resistant MFA", "Moderate", ["IA-2(1)", "IA-2(8)"],
       "Push and code-based MFA can be relayed by adversary-in-the-middle phishing kits; FIDO2 and "
       "Windows Hello cannot.",
       "Require the built-in 'Phishing-resistant MFA' authentication strength for privileged directory roles.")
def iam03(snap):
    names = snap.role_names()
    covered = set()
    for p in _enabled_ca(snap):
        if "phishing-resistant" in _grant(p)[1].lower():
            covered |= {names.get(r, r) for r in p["conditions"]["users"].get("includeRoles", [])}
            if _applies_to_all(p):
                covered |= PRIVILEGED_ROLES
    held = sorted({role for _, role, _ in snap.assignments() if role in PRIVILEGED_ROLES})
    missing = [r for r in held if r not in covered]
    return len(held), [(r, "Role is held but not covered by a phishing-resistant MFA policy.") for r in missing]


@check("IAM-04", "No Conditional Access policies left in report-only or disabled", "Low", ["CM-6"],
       "Report-only and disabled policies look like protection on a dashboard but enforce nothing.",
       "Review sign-in impact in report-only mode, then switch the policy to On, or delete it.")
def iam04(snap):
    ps = snap.rows("conditional_access_policies.json")
    return len(ps), [(p["displayName"], f"state is {p['state']}") for p in ps if p["state"] != "enabled"]


@check("IAM-05", "Between two and four Global Administrators", "Moderate", ["AC-6(5)", "AC-2(7)"],
       "Microsoft recommends fewer than five Global Administrators; more widens the blast radius of a "
       "compromise, and fewer than two risks lockout.",
       "Move day-to-day admins to least-privileged roles and keep two break-glass Global Administrators.")
def iam05(snap):
    gas = sorted({upn(snap, p) for p, role, kind in snap.assignments() if role == "Global Administrator" and kind == "active"})
    if 2 <= len(gas) <= 4:
        return 1, []
    return 1, [("tenant", f"{len(gas)} permanent Global Administrators: {', '.join(gas)}.")]


@check("IAM-06", "Privileged roles are PIM-eligible, not permanent", "Moderate", ["AC-2(7)", "AC-6(5)"],
       "Standing admin rights are always available to an attacker; just-in-time activation limits the window.",
       "Convert permanent privileged assignments to eligible assignments in Privileged Identity Management, "
       "keeping only break-glass accounts permanent.")
def iam06(snap):
    rows = [(p, r) for p, r, k in snap.assignments() if r in PRIVILEGED_ROLES and k == "active"]
    findings = [(upn(snap, p), f"permanent {r}") for p, r in rows if "break-glass" not in upn(snap, p)]
    evaluated = len([1 for _, r, _ in snap.assignments() if r in PRIVILEGED_ROLES])
    return evaluated, findings


@check("IAM-07", "Every privileged user has MFA registered", "High", ["IA-2(1)"],
       "A privileged account with no MFA method can be registered by whoever signs in first, including an attacker.",
       "Require MFA registration for the account now, and block sign-in until it is done.")
def iam07(snap):
    reg = {r["id"]: r for r in snap.rows("user_registration_details.json")}
    admins = sorted({p for p, r, _ in snap.assignments() if r in PRIVILEGED_ROLES})
    return len(admins), [(upn(snap, p), "no MFA method registered") for p in admins
                         if not reg.get(p, {}).get("isMfaRegistered")]


@check("IAM-08", f"No enabled accounts inactive for {STALE_DAYS} days", "Moderate", ["AC-2(3)"],
       "Unused accounts are rarely monitored, so they are a common foothold.",
       f"Disable accounts with no sign-in for {STALE_DAYS} days after confirming with the owner; "
       "review service accounts separately.")
def iam08(snap):
    out, enabled = [], [u for u in snap.rows("users.json") if u.get("accountEnabled")]
    for u in enabled:
        last = (u.get("signInActivity") or {}).get("lastSignInDateTime")
        if not last:
            out.append((u["userPrincipalName"], "enabled and has never signed in"))
        elif (snap.now - parse_time(last)).days > STALE_DAYS:
            out.append((u["userPrincipalName"], f"last sign-in {last[:10]} ({(snap.now - parse_time(last)).days} days)"))
    return len(enabled), out


@check("IAM-09", "No guest accounts hold privileged roles", "High", ["AC-6(5)", "AC-2"],
       "Guests are governed by another organization's identity controls and offboarding.",
       "Remove the role, or give the person a member account governed by your own policies.")
def iam09(snap):
    users = snap.users()
    rows = [(p, r) for p, r, _ in snap.assignments() if r in PRIVILEGED_ROLES]
    return len(rows), [(users[p]["userPrincipalName"], f"guest holds {r}") for p, r in rows
                       if users.get(p, {}).get("userType") == "Guest"]


@check("IAM-10", "Users cannot consent to applications on their own", "Moderate", ["CM-11", "AC-6"],
       "Illicit consent grants give an attacker's app persistent mailbox or file access that survives a password reset.",
       "Set user consent to 'Do not allow' (or verified publishers with low-risk permissions only) and turn on "
       "the admin consent workflow.")
def iam10(snap):
    pol = snap.raw("authorization_policy.json").get("defaultUserRolePermissions", {})
    assigned = pol.get("permissionGrantPoliciesAssigned", [])
    # "-legacy" lets users consent to any app for any delegated permission; Microsoft's lower-risk
    # policies limit consent to verified publishers and low-impact permissions.
    legacy = [p for p in assigned if p.startswith("ManagePermissionGrantsForSelf.") and p.endswith("-legacy")]
    return 1, [("tenant", f"user consent policy: {', '.join(legacy)}")] if legacy else []


# --------------------------------------------------------------------------- application checks
@check("APP-01", f"No app secrets expired or expiring within {SECRET_WARN_DAYS} days", "Low", ["IA-5"],
       "Expired secrets break integrations; expiring ones get rotated in a hurry.",
       "Rotate the secret, or better, move the app to a certificate or managed identity.")
def app01(snap):
    out, n = [], 0
    for a in snap.rows("applications.json"):
        for s in a.get("passwordCredentials", []):
            n += 1
            days = (parse_time(s["endDateTime"]) - snap.now).days
            if days < 0:
                out.append((a["displayName"], f"secret expired {s['endDateTime'][:10]}"))
            elif days <= SECRET_WARN_DAYS:
                out.append((a["displayName"], f"secret expires {s['endDateTime'][:10]} ({days} days)"))
    return n, out


@check("APP-02", f"App secrets are valid for no more than {SECRET_MAX_DAYS} days", "Moderate", ["IA-5"],
       "Long-lived secrets are the ones that end up in scripts and repositories.",
       "Issue secrets for 12 months or less, or replace them with certificates or managed identities.")
def app02(snap):
    out, n = [], 0
    for a in snap.rows("applications.json"):
        for s in a.get("passwordCredentials", []):
            n += 1
            life = (parse_time(s["endDateTime"]) - parse_time(s["startDateTime"])).days
            if life > SECRET_MAX_DAYS:
                out.append((a["displayName"], f"secret lifetime {life} days"))
    return n, out


@check("APP-03", "No apps hold high-risk Microsoft Graph application permissions", "High", ["AC-6", "AC-6(5)"],
       "Application permissions act without a signed-in user; Directory.ReadWrite.All or Mail.ReadWrite on a "
       "compromised app is tenant-wide.",
       "Replace with least-privilege or resource-scoped permissions (for mail, an Exchange application access "
       "policy or RBAC for Applications), and review owners and credentials of apps that keep them.")
def app03(snap):
    roles = {r["id"]: r["value"] for r in snap.raw("graph_service_principal.json").get("appRoles", [])}
    grants = snap.rows("app_role_assignments.json")
    apps = {g["principalDisplayName"] for g in grants}
    out = {}
    for g in grants:
        perm = roles.get(g["appRoleId"], g["appRoleId"])
        if perm in HIGH_RISK_GRAPH_PERMISSIONS:
            out.setdefault(g["principalDisplayName"], []).append(perm)
    return len(apps), [(a, "granted " + ", ".join(sorted(p))) for a, p in sorted(out.items())]


# --------------------------------------------------------------------------- resource checks
def _ports(rule) -> list[tuple[int, int]]:
    p = rule["properties"]
    specs = ([p["destinationPortRange"]] if p.get("destinationPortRange") else []) + list(p.get("destinationPortRanges") or [])
    out = []
    for s in specs:
        if s == "*":
            out.append((0, 65535))
        elif "-" in s:
            a, b = s.split("-")
            out.append((int(a), int(b)))
        else:
            out.append((int(s), int(s)))
    return out


@check("NET-01", "No SSH or RDP open to the internet", "High", ["SC-7", "AC-17"],
       "Internet-exposed management ports are brute-forced within minutes of exposure.",
       "Remove the rule and use Azure Bastion or just-in-time VM access; if a rule must stay, restrict the source.")
def net01(snap):
    out, nsgs = [], snap.rows("network_security_groups.json")
    for n in nsgs:
        for r in n["properties"]["securityRules"]:
            p = r["properties"]
            if p["direction"] != "Inbound" or p["access"] != "Allow" or p.get("sourceAddressPrefix") not in INTERNET:
                continue
            exposed = [name for port, name in ADMIN_PORTS.items() if any(a <= port <= b for a, b in _ports(r))]
            if exposed:
                out.append((n["name"], f"rule '{r['name']}' allows {'/'.join(exposed)} from {p['sourceAddressPrefix']}"))
    return len(nsgs), out


def _resource_check(file, predicate, message):
    def fn(snap):
        rows = snap.rows(file)
        return len(rows), [(r["name"], message(r["properties"])) for r in rows if predicate(r["properties"])]
    return fn


check("STG-01", "Storage accounts block anonymous blob access", "High", ["AC-3", "SC-7"],
      "Anonymous access exposes any container someone later marks public.",
      "Set allowBlobPublicAccess to false on the account.")(
    _resource_check("storage_accounts.json", lambda p: p.get("allowBlobPublicAccess") is not False,
                    lambda p: "allowBlobPublicAccess is enabled"))
check("STG-02", "Storage accounts require TLS 1.2 or later", "Moderate", ["SC-8", "SC-13"],
      "TLS 1.0 and 1.1 are deprecated and have known weaknesses.",
      "Set minimumTlsVersion to TLS1_2.")(
    _resource_check("storage_accounts.json", lambda p: p.get("minimumTlsVersion") not in ("TLS1_2", "TLS1_3"),
                    lambda p: f"minimumTlsVersion is {p.get('minimumTlsVersion')}"))
check("STG-03", "Storage accounts accept HTTPS only", "Moderate", ["SC-8"],
      "Plain HTTP exposes data and shared access signatures in transit.",
      "Set supportsHttpsTrafficOnly to true.")(
    _resource_check("storage_accounts.json", lambda p: not p.get("supportsHttpsTrafficOnly"),
                    lambda p: "HTTP traffic allowed"))
check("STG-04", "Storage accounts disable shared key authorization", "Low", ["AC-3", "IA-2"],
      "Account keys grant full access and bypass Entra ID, Conditional Access, and per-user audit.",
      "Move clients to Entra ID authorization, then set allowSharedKeyAccess to false.")(
    _resource_check("storage_accounts.json", lambda p: p.get("allowSharedKeyAccess") is not False,
                    lambda p: "shared key access allowed"))
check("KV-01", "Key vaults have purge protection", "Moderate", ["SC-12", "CP-9"],
      "Without purge protection, a deleted vault or key can be permanently destroyed during the retention window.",
      "Enable purge protection (it cannot be turned off afterwards).")(
    _resource_check("key_vaults.json", lambda p: not p.get("enablePurgeProtection"),
                    lambda p: "purge protection not enabled"))
check("KV-02", "Key vaults are not reachable from public networks", "Moderate", ["SC-7"],
      "Secrets should be reachable only from the networks that use them.",
      "Disable public network access and use a private endpoint, or restrict the firewall to known networks.")(
    _resource_check("key_vaults.json", lambda p: p.get("publicNetworkAccess", "Enabled") != "Disabled",
                    lambda p: "public network access enabled"))
check("SQL-01", "SQL servers are not reachable from public networks", "Moderate", ["SC-7"],
      "Public endpoints expose the database login surface to the internet.",
      "Disable public network access and connect through a private endpoint.")(
    _resource_check("sql_servers.json", lambda p: p.get("publicNetworkAccess", "Enabled") != "Disabled",
                    lambda p: "public network access enabled"))


@check("SQL-02", "SQL server auditing is enabled", "Moderate", ["AU-2", "AU-12"],
       "Without auditing there is no record of who queried or changed data.",
       "Enable server-level auditing to a Log Analytics workspace.")
def sql02(snap):
    rows = snap.rows("sql_auditing.json")
    return len(rows), [(r["server"], "auditing disabled") for r in rows if r.get("state") != "Enabled"]


@check("LOG-01", "Subscription activity log is sent to Log Analytics", "Moderate", ["AU-6", "AU-12", "SI-4"],
       "The activity log is kept for 90 days and can't be queried with other telemetry unless it is exported.",
       "Add a subscription diagnostic setting that sends Administrative, Security and Policy logs to the "
       "Sentinel workspace.")
def log01(snap):
    settings = snap.rows("subscription_diagnostic_settings.json")
    ok = [s for s in settings if s.get("workspaceId")
          and any(l.get("category") == "Administrative" and l.get("enabled") for l in s.get("logs", []))]
    return 1, [] if ok else [("subscription", "no diagnostic setting sends the activity log to a Log Analytics workspace")]


@check("DEF-01", "Defender for Cloud plans are on for core workloads", "Moderate", ["SI-4", "RA-5"],
       "The free tier gives posture recommendations only; threat detection needs the paid plan per resource type.",
       f"Enable the Standard tier for {', '.join(DEFENDER_REQUIRED)}.")
def def01(snap):
    tiers = {p["name"]: p.get("pricingTier") for p in snap.rows("defender_pricing.json")}
    return len(DEFENDER_REQUIRED), [(n, f"plan is {tiers.get(n, 'missing')}") for n in DEFENDER_REQUIRED
                                    if tiers.get(n) != "Standard"]


# --------------------------------------------------------------------------- run + report
def run(folder: Path):
    snap = Snapshot(folder)
    results = []
    for c in CHECKS:
        evaluated, findings = c.fn(snap)
        results.append({"id": c.id, "title": c.title, "severity": c.severity, "controls": list(c.controls),
                        "why": c.why, "fix": c.fix, "evaluated": evaluated,
                        "status": "FAIL" if findings else ("N/A" if evaluated == 0 else "PASS"),
                        "findings": [{"resource": r, "detail": d} for r, d in findings]})
    return snap, results


def summary(results) -> dict:
    s = {"checks": sum(r["status"] != "N/A" for r in results), "passed": sum(r["status"] == "PASS" for r in results),
         "not_evaluated": sum(r["status"] == "N/A" for r in results)}
    for sev in SEVERITIES:
        s[f"failed_{sev.lower()}"] = sum(r["status"] == "FAIL" and r["severity"] == sev for r in results)
    s["findings"] = sum(len(r["findings"]) for r in results)
    s["score_pct"] = round(100 * s["passed"] / s["checks"], 1) if s["checks"] else 0.0
    return s


def report_md(snap, results) -> str:
    s = summary(results)
    L = [f"# Azure and Entra ID Posture Report: {snap.meta.get('tenant', 'tenant')}", "",
         f"Snapshot collected **{snap.meta.get('collected_at', 'unknown')}**"
         + (" (synthetic data)" if snap.meta.get("synthetic") else "") + ". Generated by `tools/audit.py`.", "",
         "## Summary", "", "| | |", "|---|---|",
         f"| Checks passed | {s['passed']} of {s['checks']} ({s['score_pct']}%) |",
         f"| Failed checks | High {s['failed_high']}, Moderate {s['failed_moderate']}, Low {s['failed_low']} |",
         f"| Individual findings | {s['findings']} |",
         f"| Not evaluated (no data for that resource type) | {s['not_evaluated']} |", "",
         "## Fix first", "",
         "| Check | Severity | Finding | Fix |", "|---|---|---|---|"]
    for r in sorted((r for r in results if r["status"] == "FAIL"), key=lambda r: SEVERITIES.index(r["severity"])):
        if r["severity"] != "High":
            continue
        for f in r["findings"]:
            L.append(f"| {r['id']} | {r['severity']} | `{f['resource']}`: {f['detail']} | {r['fix']} |")
    L += ["", "## All checks", "", "| Check | Title | Severity | NIST 800-53 | Result | Evaluated |",
          "|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['id']} | {r['title']} | {r['severity']} | {', '.join(r['controls'])} | "
                 f"{'**FAIL** (' + str(len(r['findings'])) + ')' if r['status'] == 'FAIL' else r['status']} | {r['evaluated']} |")
    L += ["", "## Findings by check", ""]
    for r in results:
        if r["status"] != "FAIL":
            continue
        L += [f"### {r['id']} {r['title']} ({r['severity']})", "", f"**Why it matters:** {r['why']}", "",
              f"**Fix:** {r['fix']}", ""]
        L += [f"- `{f['resource']}`: {f['detail']}" for f in r["findings"]] + [""]
    return "\n".join(L)


def findings_csv(results) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["check_id", "title", "severity", "controls", "resource", "detail", "fix"])
    for r in results:
        for f in r["findings"]:
            w.writerow([r["id"], r["title"], r["severity"], " ".join(r["controls"]), f["resource"], f["detail"], r["fix"]])
    return buf.getvalue()


def outputs(snap, results) -> dict[str, str]:
    return {
        "reports/REPORT.md": report_md(snap, results),
        "reports/findings.json": json.dumps({"tenant": snap.meta, "summary": summary(results), "results": results},
                                            indent=2) + "\n",
        "reports/findings.csv": findings_csv(results),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", type=Path, default=ROOT / "data" / "tenant")
    ap.add_argument("--out", type=Path, default=ROOT)
    ap.add_argument("--check", action="store_true", help="write nothing; fail if reports are stale (CI)")
    args = ap.parse_args()
    ids = [c.id for c in CHECKS]
    if len(ids) != len(set(ids)):
        print("FAILED: duplicate check IDs")
        return 1
    snap, results = run(args.tenant)
    stale = []
    for path, text in outputs(snap, results).items():
        p = args.out / path
        if args.check:
            if not p.exists() or p.read_text() != text:
                stale.append(path)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    if stale:
        print("FAILED: out of date, run python tools/audit.py: " + ", ".join(stale))
        return 1
    s = summary(results)
    print(f"{s['passed']}/{s['checks']} checks passed; {s['findings']} findings "
          f"(High {s['failed_high']}, Moderate {s['failed_moderate']}, Low {s['failed_low']} failed checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
