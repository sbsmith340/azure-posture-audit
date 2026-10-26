# Azure and Entra ID Posture Audit

> 24 security checks across Entra ID, app registrations, and Azure resources, written as small, tested Python functions. A read-only collector saves a tenant snapshot as JSON; the audit turns it into a prioritized report mapped to NIST SP 800-53. Runs here on a synthetic tenant.

![ci](https://github.com/sbsmith340/azure-posture-audit/actions/workflows/ci.yml/badge.svg)
![data](https://img.shields.io/badge/data-synthetic-blue)
![python](https://img.shields.io/badge/python-stdlib%20only-informational)

**[Read the sample report](reports/REPORT.md)** · [findings.csv](reports/findings.csv) · [findings.json](reports/findings.json)

## Problem
Most cloud breaches start with identity and configuration, not exploits: no MFA on an admin, legacy authentication left on, an app with tenant-wide mail access, RDP open to the internet. Defender for Cloud's secure score covers part of this, but Entra ID settings like Conditional Access gaps, standing admin rights, and user consent sit outside it. Checking them by hand in the portal is slow and leaves no record.

## What I built
- **[`tools/audit.py`](tools/audit.py)**: each check is one function with an ID, severity, NIST 800-53 controls, a "why it matters," and a fix. It reads JSON only, so an audit is repeatable and can be reviewed later.
- **[`collect/collect.py`](collect/collect.py)**: a read-only collector (`GET` requests only, enforced by a test) that saves Microsoft Graph and Azure Resource Graph responses in their raw shapes. Not yet run against a live tenant; see Limitations.
- **[`data/generate.py`](data/generate.py)**: builds a synthetic tenant, *Contoso Field Services*, in the same raw shapes, with a realistic mix of good and bad settings.
- **Reports**: Markdown for people, CSV for a tracker or POA&M, JSON for other tools.

## The checks
| Area | Checks |
|---|---|
| Conditional Access | MFA for all users · legacy authentication blocked · phishing-resistant MFA for admins · no report-only or disabled policies |
| Privileged access | 2 to 4 Global Admins · PIM-eligible instead of permanent · admins have MFA registered · no guests in admin roles |
| Accounts and consent | No enabled accounts inactive 90+ days · users can't grant consent to apps on their own |
| App registrations | Secrets not expired or about to expire · secrets valid 12 months or less · no high-risk Graph application permissions (Directory.ReadWrite.All, Mail.ReadWrite, and similar) |
| Network | No SSH or RDP open to the internet (handles `*`, `Internet`, `0.0.0.0/0`, port lists and ranges) |
| Storage, Key Vault, SQL | Anonymous blob access, TLS minimum, HTTPS only, shared key auth · purge protection, public access · SQL public access, auditing |
| Logging and Defender | Activity log sent to Log Analytics · Defender plans on for VMs, SQL, Storage, Key Vault |

## Sample result
On the synthetic tenant: **12 of 24 checks pass, 21 findings.** The five High failures are the ones an attacker would use first: legacy authentication only in report-only mode, a guest with Exchange Administrator, two apps with tenant-wide Graph permissions (one can read and send every mailbox), RDP and SSH open to the internet on two network security groups, and a storage account allowing anonymous blob access.

These line up with the [business email compromise case study](https://github.com/sbsmith340/incident-case-study-bec): user consent to apps (IAM-10) and mail-capable app permissions (APP-03) are the settings that attack abused.

## How it's tested
A check that only ever passes proves nothing, so the tests (32) flip each one:
- every **passing** check is broken on a copy of the tenant (e.g. turn off the MFA policy, open a key vault to the internet) and must fail
- several **failing** checks are fixed on a copy and must pass
- edge cases: port ranges (`20-25` exposes SSH; `8080-8090` doesn't), break-glass accounts allowed to be permanent, disabled accounts ignored, missing data reported as N/A instead of PASS
- the committed reports must match a fresh run, and the generator must reproduce the data byte for byte

## How to run it
```bash
git clone https://github.com/sbsmith340/azure-posture-audit.git
cd azure-posture-audit
python tools/audit.py              # audits data/tenant, writes reports/
pip install pytest && pytest -q tests
```
Against your own tenant (read-only; never commit the snapshot, it's in `.gitignore`):
```bash
az login && az extension add --name resource-graph
python collect/collect.py --out snapshot/
python tools/audit.py --tenant snapshot/ --out snapshot/
```

## Framework mapping
Every check lists its NIST SP 800-53 Rev 5 controls in the report, mainly IA-2 (MFA), AC-2 and AC-6 (accounts, least privilege), IA-5 (authenticators), SC-7 and SC-8 (boundary, transmission), AU-2/6/12 (logging), and SI-4/RA-5 (monitoring).

## Design choices
- **Collect once, audit offline.** Separating collection from evaluation means the evidence can be kept with an assessment, re-audited when a check changes, and tested without a cloud account.
- **Raw API shapes, not a custom schema.** The collector saves responses as Graph and Resource Graph return them, so there's no translation layer to get wrong.
- **Names resolved from the tenant.** Graph permission names come from the Microsoft Graph service principal's `appRoles` and role names from `roleDefinitions`, rather than hard-coded GUIDs.

## Limitations and what's next
- **The collector is lab-test-pending.** It follows the documented API responses but hasn't been run against a live tenant yet; the Azure CLI's Graph token may lack some read permissions in a given tenant.
- Conditional Access logic covers the common patterns (All users, role-targeted policies, exclusions for break-glass), not every combination of conditions, named locations, or device filters.
- Next: a Sentinel/Log Analytics variant of the high-value checks as scheduled KQL, and exporting findings into the [ConMon POA&M pipeline](https://github.com/sbsmith340/conmon-poam-automation).

## Repo layout
```
tools/audit.py            the checks, runner, and report writer
collect/collect.py        read-only snapshot collector (az CLI + Graph + Resource Graph)
data/generate.py          synthetic tenant generator
data/tenant/*.json        the synthetic snapshot
reports/                  REPORT.md, findings.csv, findings.json
tests/                    break/fix tests for every check
```

---
Contoso Field Services, its users, apps, and resources are fictional. Built by [Shawn Smith](https://sbsmith340.github.io).
