from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any


HIGH_PRIVILEGES = {
    "Domain Admin",
    "Global Admin",
    "AdministratorAccess",
    "Super Admin",
    "Security Admin",
    "Cloud Admin",
}


def calculate_risk_score(
    identity: dict,
    offboarding_records: list[dict],
    api_tokens: list[dict],
    audit_logs: list[dict],
    effective_privileges: list[dict],
) -> dict[str, Any]:
    """Explainable risk scoring 0-100."""
    factors: list[str] = []
    breakdown = {
        "privilege_risk": 0.0,
        "dormancy_risk": 0.0,
        "offboarding_risk": 0.0,
        "token_risk": 0.0,
        "behavior_risk": 0.0,
        "escalation_risk": 0.0,
        "platform_spread_risk": 0.0,
    }

    score = 0.0
    now = datetime.utcnow()

    high_privs = [
        ep["privilege"]
        for ep in effective_privileges
        if ep["privilege"] in HIGH_PRIVILEGES
    ]
    priv_score = min(len(high_privs) * 12 + len(effective_privileges) * 3, 35)
    breakdown["privilege_risk"] = priv_score
    score += priv_score
    for p in high_privs[:3]:
        factors.append(p)

    platforms = list(identity.get("platform_accounts", {}).keys())
    spread_score = min(len(platforms) * 4, 20)
    breakdown["platform_spread_risk"] = spread_score
    score += spread_score
    if len(platforms) >= 5:
        factors.append(f"Access across {len(platforms)} platforms")

    dormant_days = 0
    for platform, account in identity.get("platform_accounts", {}).items():
        last_login_str = account.get("last_login")
        if last_login_str:
            last_login = datetime.fromisoformat(last_login_str)
            days = (now - last_login).days
            priv = account.get("privilege_level", "")
            if priv in HIGH_PRIVILEGES and days > 90:
                dormant_days = max(dormant_days, days)

    if dormant_days > 90:
        dorm_score = min((dormant_days - 90) * 0.15 + 10, 25)
        breakdown["dormancy_risk"] = dorm_score
        score += dorm_score
        factors.append(f"Dormant {dormant_days} days")

    emp_id = identity.get("employee_id")
    offboarding = next(
        (o for o in offboarding_records if o["employee_id"] == emp_id), None
    )
    if offboarding or identity.get("employment_status") == "terminated":
        active_platforms = [
            p
            for p, a in identity.get("platform_accounts", {}).items()
            if a.get("account_status") == "active"
        ]
        if active_platforms:
            off_score = min(len(active_platforms) * 15, 30)
            breakdown["offboarding_risk"] = off_score
            score += off_score
            factors.append(f"Terminated but active on {', '.join(active_platforms[:2])}")

    usernames = {
        a.get("username") for a in identity.get("platform_accounts", {}).values()
    }
    user_tokens = [t for t in api_tokens if t["owner"] in usernames]
    token_score = 0.0
    for token in user_tokens:
        age = (now - token["creation_date"]).days
        if age > 180:
            token_score += min(age * 0.03, 15)
            if not token.get("last_rotation"):
                token_score += 5
                factors.append(f"Unrotated token aged {age} days")
            else:
                factors.append(f"Token aged {age} days")

    breakdown["token_risk"] = min(token_score, 20)
    score += breakdown["token_risk"]

    user_audit = [
        a
        for a in audit_logs
        if a["user"] in usernames
        and a["timestamp"] > now - timedelta(days=30)
    ]
    suspicious = [
        a
        for a in user_audit
        if a["event_type"]
        in ("mfa_disabled", "role_escalation", "failed_authentication")
        or a.get("geo_location") == "Tor Exit Node"
    ]
    behavior_score = min(len(suspicious) * 5 + len(user_audit) * 0.5, 20)
    breakdown["behavior_risk"] = behavior_score
    score += behavior_score
    if suspicious:
        factors.append(f"{len(suspicious)} suspicious events (30d)")

    escalations = [a for a in user_audit if a["event_type"] == "role_escalation"]
    esc_score = min(len(escalations) * 8, 15)
    breakdown["escalation_risk"] = esc_score
    score += esc_score
    if escalations:
        factors.append("Recent privilege escalation detected")

    final_score = min(round(score), 100)

    return {
        "risk_score": final_score,
        "risk_factors": factors[:8],
        "risk_breakdown": {k: round(v, 1) for k, v in breakdown.items()},
    }
