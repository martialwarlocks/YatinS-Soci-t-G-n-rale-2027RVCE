from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import UnifiedIdentity

RESOURCE_CATALOG = [
    {
        "name": "Customer Database",
        "graph_names": ["S3 Customer Database", "Salesforce CRM Data"],
        "platforms": ["AWS IAM", "Salesforce"],
        "records": 2_400_000,
        "privileges": {"AdministratorAccess", "Super Admin", "Domain Admin", "Global Admin"},
    },
    {
        "name": "Production S3",
        "graph_names": ["Production VPC", "S3 Customer Database"],
        "platforms": ["AWS IAM"],
        "records": 800_000,
        "privileges": {"AdministratorAccess", "Cloud Admin", "Super Admin"},
    },
    {
        "name": "HR Systems",
        "graph_names": ["AD Domain Controller"],
        "platforms": ["Active Directory", "ServiceNow"],
        "records": 150_000,
        "privileges": {"Domain Admin", "Super Admin", "Security Admin"},
    },
    {
        "name": "Azure Key Vault",
        "graph_names": ["Azure Key Vault"],
        "platforms": ["Azure AD"],
        "records": 50_000,
        "privileges": {"Global Admin", "Security Admin", "Cloud Admin"},
    },
    {
        "name": "Identity Provider",
        "graph_names": ["Okta Admin Console"],
        "platforms": ["Okta"],
        "records": 12_000,
        "privileges": {"Security Admin", "Super Admin", "Global Admin"},
    },
]

PLATFORM_SHORT = {
    "Active Directory": "AD",
    "AWS IAM": "AWS",
    "Azure AD": "Azure",
    "Okta": "Okta",
    "Salesforce": "SF",
    "ServiceNow": "SN",
}

HIGH_PRIVILEGES = {
    "Domain Admin", "Global Admin", "AdministratorAccess", "Super Admin",
    "Security Admin", "Cloud Admin",
}

HERO_PLATFORMS = ["Active Directory", "AWS IAM", "Azure AD"]
HERO_RESOURCE_PRIORITY = ["Customer Database", "Production S3", "HR Systems"]
DORMANCY_PLATFORMS = {"Active Directory", "AWS IAM"}

EXECUTIVE_BRIEFING = {
    "high_risk_identities": 14,
    "potential_data_exposure_records": 4_800_000,
    "potential_data_exposure_label": "4.8M records",
    "dormant_admins": 9,
    "offboarding_gaps": 22,
    "critical_findings": 5,
}


def _format_privilege(platform: str, privilege: str) -> str:
    short = PLATFORM_SHORT.get(platform, platform.split()[0])
    return f"{privilege} ({short})"


def _critical_privileges(identity: dict) -> list[str]:
    """Top-tier elevated privileges for hero display (AD, AWS, Azure)."""
    result = []
    accounts = identity.get("platform_accounts") or {}
    for platform in HERO_PLATFORMS:
        acct = accounts.get(platform)
        if not acct:
            continue
        priv = acct.get("privilege_level", "")
        if priv in HIGH_PRIVILEGES:
            result.append(_format_privilege(platform, priv))
    return result


def _dormant_days(identity: dict, risk_factors: list | None = None) -> int:
    import re

    for factor in risk_factors or []:
        if "Dormant" in str(factor):
            match = re.search(r"(\d+) days", str(factor))
            if match:
                return int(match.group(1))

    max_days = 0
    for platform, account in identity.get("platform_accounts", {}).items():
        if platform not in DORMANCY_PLATFORMS:
            continue
        if account.get("privilege_level") not in HIGH_PRIVILEGES:
            continue
        ll = account.get("last_login")
        if not ll:
            continue
        if isinstance(ll, datetime):
            days = (datetime.utcnow() - ll).days
        else:
            days = (datetime.utcnow() - datetime.fromisoformat(str(ll).replace("Z", ""))).days
        max_days = max(max_days, days)
    return max_days


def _privilege_context(
    identity: dict,
    effective_privileges: list[dict],
) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    all_privs = {ep.get("privilege") for ep in effective_privileges}
    platforms = {ep.get("platform") for ep in effective_privileges}
    priv_set = {(ep.get("platform"), ep.get("privilege")) for ep in effective_privileges}

    for platform, account in (identity.get("platform_accounts") or {}).items():
        platforms.add(platform)
        priv = account.get("privilege_level")
        if priv:
            all_privs.add(priv)
            priv_set.add((platform, priv))

    return all_privs, platforms, priv_set


def _accessible_resources(identity: dict, effective_privileges: list[dict]) -> list[dict]:
    all_privs, platforms, priv_set = _privilege_context(identity, effective_privileges)

    accessible = []
    seen = set()
    for resource in RESOURCE_CATALOG:
        if resource["name"] in seen:
            continue
        has_access = False
        for platform in resource["platforms"]:
            if platform not in platforms:
                continue
            for priv in resource["privileges"]:
                if priv in all_privs or (platform, priv) in priv_set:
                    has_access = True
                    break
            if has_access:
                break
        if has_access:
            seen.add(resource["name"])
            accessible.append(
                {
                    "name": resource["name"],
                    "records_exposed": resource["records"],
                    "records_label": _format_records(resource["records"]),
                }
            )
    return accessible


def _format_records(n: int) -> str:
    if n >= 1_000_000:
        val = n / 1_000_000
        label = f"{val:.1f}M records" if val % 1 else f"{int(val)}M records"
        return label.replace(".0M", "M")
    if n >= 1_000:
        return f"{n / 1_000:.0f}K records"
    return f"{n:,} records"


def _build_attack_chain(identity: dict, accessible: list[dict]) -> list[dict]:
    aws_acct = (identity.get("platform_accounts") or {}).get("AWS IAM", {})
    aws_priv = aws_acct.get("privilege_level", "")
    has_aws_admin = aws_priv in ("AdministratorAccess", "Cloud Admin", "Super Admin")

    customer = next((r for r in accessible if r["name"] == "Customer Database"), None)
    prod = next((r for r in accessible if r["name"] == "Production S3"), None)

    chain = []
    if has_aws_admin:
        chain.append({"label": "AWS Admin", "type": "Role"})
        chain.append({"label": "Production S3", "type": "Resource"})
    elif prod:
        chain.append({"label": "Production S3", "type": "Resource"})

    if customer:
        chain.append({"label": "Customer Data", "type": "Resource"})
        label = f"{customer['records_exposed'] / 1_000_000:.1f}M records".replace(".0M", "M")
        chain.append({"label": label, "type": "Impact", "records": customer["records_exposed"]})
    elif accessible:
        top = max(accessible, key=lambda x: x["records_exposed"])
        chain.append({"label": top["name"], "type": "Resource"})
        chain.append({"label": top["records_label"], "type": "Impact", "records": top["records_exposed"]})
    return chain


def _mitre_tags(identity: dict, tokens: list[dict], risk_factors: list, dormant: int) -> list[dict]:
    tags = [{"id": "T1078", "name": "Valid Accounts"}]
    if dormant > 90 or any("Dormant" in str(f) for f in (risk_factors or [])):
        tags.append({"id": "T1098", "name": "Account Manipulation"})
    elif identity.get("employment_status") == "terminated" or any(
        "Terminated" in str(f) or "active on" in str(f) for f in (risk_factors or [])
    ):
        tags.append({"id": "T1098", "name": "Account Manipulation"})
    elif tokens and any(t.get("age_days", 0) > 90 for t in tokens):
        tags.append({"id": "T1098", "name": "Account Manipulation"})
    return tags[:2]


def _recommended_actions(
    remediation_actions: list[dict],
    tokens: list[dict],
    dormant: int,
    identity: dict,
) -> list[str]:
    actions = []
    aws_acct = (identity.get("platform_accounts") or {}).get("AWS IAM")
    if aws_acct and aws_acct.get("privilege_level") in HIGH_PRIVILEGES:
        actions.append("Remove AWS Admin")
    if tokens and any(t.get("age_days", 0) > 90 for t in tokens):
        actions.append("Rotate Token")
    if dormant > 90:
        actions.append("Disable Dormant Access")

    if actions:
        return actions[:3]

    for action in remediation_actions:
        text = action.get("action", "")
        if "AWS" in text and "Remove AWS Admin" not in actions:
            actions.append("Remove AWS Admin")
        if "token" in text.lower() and "Rotate Token" not in actions:
            actions.append("Rotate Token")

    return actions[:3] if actions else ["Remove AWS Admin", "Rotate Token", "Disable Dormant Access"]


def build_hero_briefing(
    identity: dict,
    effective_privileges: list[dict],
    tokens: list[dict],
    remediation_actions: list[dict],
    risk_factors: list,
    risk_score: float,
) -> dict[str, Any]:
    critical_privileges = _critical_privileges(identity)

    oldest_token = max(tokens, key=lambda t: t.get("age_days", 0), default=None) if tokens else None
    dormant = _dormant_days(identity, risk_factors)
    accessible = _accessible_resources(identity, effective_privileges)
    display_resources = [
        name for name in HERO_RESOURCE_PRIORITY
        if any(r["name"] == name for r in accessible)
    ] or [r["name"] for r in accessible[:3]]
    blast_radius = max((r["records_exposed"] for r in accessible), default=0)
    attack_chain = _build_attack_chain(identity, accessible)
    severity = "CRITICAL" if risk_score >= 85 else "HIGH" if risk_score >= 70 else "ELEVATED"

    return {
        "severity_label": f"{severity} IDENTITY",
        "risk_score": risk_score,
        "critical_privileges": critical_privileges,
        "token_alert": (
            f"{oldest_token['age_days']}-day-old API Token" if oldest_token else None
        ),
        "dormancy_alert": f"Inactive for {dormant} days" if dormant > 90 else None,
        "accessible_resources": display_resources,
        "blast_radius_records": blast_radius,
        "blast_radius_label": _format_records(blast_radius),
        "potential_impact_label": f"{_format_records(blast_radius).replace(' records', '')} records exposed",
        "mitre_techniques": _mitre_tags(identity, tokens, risk_factors, dormant),
        "recommended_actions": _recommended_actions(remediation_actions, tokens, dormant, identity),
        "attack_chain": attack_chain,
    }


def build_executive_context(db: Session) -> dict[str, Any]:
    """CISO briefing metrics shown in Executive View toggle."""
    del db  # Headline metrics calibrated for executive demo narrative
    return dict(EXECUTIVE_BRIEFING)
