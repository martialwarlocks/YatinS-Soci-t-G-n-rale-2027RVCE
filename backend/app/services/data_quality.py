from datetime import datetime, timedelta
from typing import Any


def assess_data_quality(
    unified_identities: list[dict],
    identity_snapshots: list[dict],
    offboarding_records: list[dict],
) -> dict[str, Any]:
    """Measure cross-platform identity data completeness and consistency."""
    issues: list[dict] = []
    total = len(unified_identities)

    terminated_ids = {o["employee_id"] for o in offboarding_records}
    snapshot_by_emp: dict[str, list] = {}
    for snap in identity_snapshots:
        snapshot_by_emp.setdefault(snap["employee_id"], []).append(snap)

    orphaned_active = 0
    stale_logins = 0
    privilege_mismatch = 0
    missing_platforms = 0
    email_mismatch = 0

    for identity in unified_identities:
        emp_id = identity["employee_id"]
        accounts = identity.get("platform_accounts", {})
        snaps = snapshot_by_emp.get(emp_id, [])

        if len(accounts) < 2:
            missing_platforms += 1
            issues.append(
                {
                    "type": "low_platform_coverage",
                    "identity": identity["full_name"],
                    "unified_id": identity["unified_id"],
                    "severity": "medium",
                    "detail": f"Only {len(accounts)} platform account(s) correlated",
                }
            )

        if emp_id in terminated_ids or identity.get("employment_status") == "terminated":
            active = [p for p, a in accounts.items() if a.get("account_status") == "active"]
            if active:
                orphaned_active += 1
                issues.append(
                    {
                        "type": "offboarding_gap",
                        "identity": identity["full_name"],
                        "unified_id": identity["unified_id"],
                        "severity": "critical",
                        "detail": f"Terminated but active on: {', '.join(active)}",
                    }
                )

        for snap in snaps:
            if snap["email"] != identity["email"]:
                email_mismatch += 1

        for platform, account in accounts.items():
            ll = account.get("last_login")
            if ll:
                days = (datetime.utcnow() - datetime.fromisoformat(ll)).days
                if days > 180 and account.get("account_status") == "active":
                    stale_logins += 1

            snap = next((s for s in snaps if s["platform"] == platform), None)
            if snap and snap.get("privilege_level") != account.get("privilege_level"):
                privilege_mismatch += 1

    completeness = round(
        max(0, 100 - (missing_platforms / max(total, 1)) * 15 - (email_mismatch / max(total, 1)) * 10),
        1,
    )
    consistency = round(
        max(0, 100 - (orphaned_active / max(total, 1)) * 40 - (privilege_mismatch / max(total, 1)) * 5),
        1,
    )
    freshness = round(
        max(0, 100 - (stale_logins / max(total, 1)) * 20),
        1,
    )
    overall = round((completeness + consistency + freshness) / 3, 1)

    return {
        "overall_score": overall,
        "completeness": completeness,
        "consistency": consistency,
        "freshness": freshness,
        "orphaned_active_accounts": orphaned_active,
        "stale_identities": stale_logins,
        "privilege_mismatches": privilege_mismatch,
        "low_coverage_identities": missing_platforms,
        "issues": sorted(issues, key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x["severity"], 3))[:50],
    }


def assess_identity_quality(identity: dict, offboarding_records: list[dict]) -> list[dict]:
    """Per-identity data quality issues."""
    issues = []
    emp_id = identity.get("employee_id")
    terminated = identity.get("employment_status") == "terminated" or any(
        o["employee_id"] == emp_id for o in offboarding_records
    )

    for platform, account in identity.get("platform_accounts", {}).items():
        if terminated and account.get("account_status") == "active":
            issues.append(
                {
                    "type": "offboarding_gap",
                    "severity": "critical",
                    "platform": platform,
                    "detail": f"HR terminated but {platform} account still active",
                }
            )
        ll = account.get("last_login")
        if ll and account.get("account_status") == "active":
            days = (datetime.utcnow() - datetime.fromisoformat(ll)).days
            if days > 90:
                issues.append(
                    {
                        "type": "stale_account",
                        "severity": "high" if days > 180 else "medium",
                        "platform": platform,
                        "detail": f"No login for {days} days on {platform}",
                    }
                )

    aliases = identity.get("platform_accounts", {})
    if len(aliases) >= 4:
        issues.append(
            {
                "type": "platform_sprawl",
                "severity": "medium",
                "platform": "cross-platform",
                "detail": f"Identity spans {len(aliases)} platforms — review least-privilege",
            }
        )

    return issues
