from typing import Any

from app.config import settings

PLATFORM_ACTIONS = {
    "AWS IAM": {
        "AdministratorAccess": "Remove AdministratorAccess policy from IAM user/role",
        "Cloud Admin": "Revoke elevated IAM policies and enforce least privilege",
        "default": "Review and reduce IAM permissions to minimum required",
    },
    "Active Directory": {
        "Domain Admin": "Remove user from Domain Admins group",
        "Enterprise Admins": "Remove from Enterprise Admins and audit nested group membership",
        "default": "Disable account and remove from privileged AD groups",
    },
    "Azure AD": {
        "Global Admin": "Remove Global Administrator role assignment",
        "Security Admin": "Review and revoke Security Admin role",
        "default": "Disable Azure AD account and review role assignments",
    },
    "Okta": {
        "default": "Disable inactive Okta account and revoke application assignments",
    },
    "Salesforce": {
        "Super Admin": "Revoke System Administrator profile",
        "default": "Rotate API tokens and reduce Salesforce permission sets",
    },
    "ServiceNow": {
        "default": "Revoke admin roles and disable unused ServiceNow accounts",
    },
}


def generate_remediation(
    identity: dict,
    risk_factors: list[str],
    effective_privileges: list[dict],
    api_tokens: list[dict],
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    usernames = {
        a.get("username") for a in identity.get("platform_accounts", {}).values()
    }

    for ep in effective_privileges:
        platform = ep["platform"]
        priv = ep["privilege"]
        if priv in ("Standard User", "Power User"):
            continue
        platform_actions = PLATFORM_ACTIONS.get(platform, {})
        action_text = platform_actions.get(priv, platform_actions.get("default", f"Review {platform} access"))
        actions.append(
            {
                "platform": platform,
                "priority": "critical" if priv in ("Domain Admin", "Global Admin", "AdministratorAccess") else "high",
                "action": action_text,
                "category": "privilege_reduction",
                "status": "pending",
            }
        )

    for platform, account in identity.get("platform_accounts", {}).items():
        if account.get("account_status") == "active" and identity.get("employment_status") == "terminated":
            actions.append(
                {
                    "platform": platform,
                    "priority": "critical",
                    "action": f"Immediately disable active account on {platform} (terminated employee)",
                    "category": "offboarding",
                    "status": "pending",
                }
            )

        ll = account.get("last_login")
        if ll:
            from datetime import datetime

            days = (datetime.utcnow() - datetime.fromisoformat(ll)).days
            if days > 90 and account.get("privilege_level") in (
                "Domain Admin",
                "Global Admin",
                "AdministratorAccess",
            ):
                actions.append(
                    {
                        "platform": platform,
                        "priority": "high",
                        "action": f"Disable dormant admin account (inactive {days} days) on {platform}",
                        "category": "dormancy",
                        "status": "pending",
                    }
                )

    for token in api_tokens:
        if token["owner"] in usernames:
            from datetime import datetime

            age = (datetime.utcnow() - token["creation_date"]).days
            if age > 90:
                actions.append(
                    {
                        "platform": token["platform"],
                        "priority": "high" if age > 180 else "medium",
                        "action": f"Rotate API token '{token.get('token_name', 'unnamed')}' (age: {age} days)",
                        "category": "token_rotation",
                        "status": "pending",
                    }
                )

    seen = set()
    unique_actions = []
    for a in actions:
        key = (a["platform"], a["action"])
        if key not in seen:
            seen.add(key)
            unique_actions.append(a)

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique_actions.sort(key=lambda x: priority_order.get(x["priority"], 4))

    return unique_actions[:12]


def generate_ai_summary(
    identity: dict,
    risk_score: float,
    risk_factors: list[str],
    effective_privileges: list[dict],
) -> str:
    """Generate human-readable risk summary (template-based, OpenAI optional)."""
    name = identity.get("full_name", "Unknown")
    high_privs = [ep["privilege"] for ep in effective_privileges if ep["privilege"] not in ("Standard User", "Power User")]

    priv_text = ""
    if high_privs:
        priv_text = f"possesses {', '.join(high_privs[:3])} privileges through direct assignment and nested group inheritance"

    dormant_factors = [f for f in risk_factors if "Dormant" in f]
    token_factors = [f for f in risk_factors if "token" in f.lower()]
    offboard_factors = [f for f in risk_factors if "Terminated" in f or "active on" in f]

    parts = [f"{name} {priv_text}." if priv_text else f"{name} has elevated identity risk."]

    if dormant_factors:
        parts.append(f"Account has been {dormant_factors[0].lower()}.")
    if token_factors:
        parts.append(f"Maintains {token_factors[0].lower()}.")
    if offboard_factors:
        parts.append(f"Critical offboarding gap: {offboard_factors[0]}.")
    if risk_score >= 80:
        parts.append("Immediate review and remediation recommended.")
    elif risk_score >= 60:
        parts.append("Priority review recommended within 48 hours.")
    else:
        parts.append("Monitor and schedule routine access review.")

    return " ".join(parts)


def generate_ai_analysis(
    identity: dict,
    risk_score: float,
    risk_factors: list[str],
    effective_privileges: list[dict],
    anomaly_explanation: dict | None = None,
) -> dict[str, Any]:
    """Structured intelligence analysis — root cause, narrative, urgency."""
    name = identity.get("full_name", "Unknown")
    high_privs = [
        ep for ep in effective_privileges
        if ep.get("privilege") not in ("Standard User", "Power User")
    ]
    platforms = list(identity.get("platform_accounts", {}).keys())

    privilege_paths = []
    for ep in high_privs[:3]:
        paths = ep.get("paths") or []
        if paths:
            privilege_paths.append(f"{ep['platform']}: {paths[0]}")
        else:
            privilege_paths.append(f"{ep['platform']}: direct {ep['privilege']}")

    root_causes = []
    if high_privs:
        root_causes.append(f"Accumulated elevated privileges across {len(high_privs)} platform(s)")
    offboard = [f for f in risk_factors if "Terminated" in f or "active on" in f]
    if offboard:
        root_causes.append("Offboarding process failure — HR termination not propagated to all platforms")
    dormant = [f for f in risk_factors if "Dormant" in f]
    if dormant:
        root_causes.append("Privileged account dormancy exceeds 90-day policy threshold")
    if anomaly_explanation and anomaly_explanation.get("is_anomaly"):
        root_causes.append("ML behavioral model flagged deviation from peer baseline")

    urgency = "immediate" if risk_score >= 85 else "high" if risk_score >= 70 else "medium" if risk_score >= 50 else "low"

    summary = generate_ai_summary(identity, risk_score, risk_factors, effective_privileges)

    attack_narrative = ""
    if high_privs and platforms:
        top_priv = high_privs[0]["privilege"]
        attack_narrative = (
            f"An attacker compromising {name}'s credentials on {platforms[0]} could leverage "
            f"{top_priv} privileges"
        )
        if len(platforms) > 1:
            attack_narrative += f" and pivot across {len(platforms)} connected platforms"
        attack_narrative += ", potentially reaching sensitive resources via nested group inheritance."

    return {
        "summary": summary,
        "root_causes": root_causes,
        "privilege_paths": privilege_paths,
        "attack_narrative": attack_narrative,
        "urgency": urgency,
        "risk_score": risk_score,
        "ml_insights": anomaly_explanation.get("reasons", []) if anomaly_explanation else [],
    }


async def generate_openai_summary(
    identity: dict,
    risk_score: float,
    risk_factors: list[str],
) -> str | None:
    if not settings.use_openai or not settings.openai_api_key:
        return None

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=settings.openai_api_key)
        prompt = f"""You are an enterprise identity security analyst. Write a concise 2-3 sentence risk summary for:
Name: {identity.get('full_name')}
Department: {identity.get('department')}
Risk Score: {risk_score}/100
Risk Factors: {', '.join(risk_factors)}
Employment Status: {identity.get('employment_status')}
Include root cause and remediation urgency."""

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
        )
        return response.choices[0].message.content
    except Exception:
        return None
