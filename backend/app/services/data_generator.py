import random
import string
from datetime import datetime, timedelta
from typing import Any

PLATFORMS = [
    "Active Directory",
    "AWS IAM",
    "Azure AD",
    "Okta",
    "Salesforce",
    "ServiceNow",
]

DEPARTMENTS = [
    "Engineering",
    "Finance",
    "HR",
    "Sales",
    "Marketing",
    "IT Security",
    "Operations",
    "Legal",
    "Customer Success",
    "Executive",
]

ROLES = [
    "Software Engineer",
    "Senior Engineer",
    "DevOps Engineer",
    "Security Analyst",
    "Finance Manager",
    "HR Specialist",
    "Sales Director",
    "Marketing Manager",
    "IT Administrator",
    "VP Engineering",
    "CFO",
    "CEO",
    "Contractor",
    "Service Account Owner",
]

PRIVILEGE_LEVELS = [
    "Standard User",
    "Power User",
    "Read Only Admin",
    "Helpdesk Admin",
    "Cloud Admin",
    "Global Admin",
    "Domain Admin",
    "AdministratorAccess",
    "Security Admin",
    "Super Admin",
]

FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph",
    "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Yatin", "Priya", "Raj",
    "Ananya", "Marcus", "Elena", "Carlos", "Sophie", "Ahmed", "Mei", "Olivia",
    "Daniel", "Emma", "Alexander", "Isabella", "Ethan", "Mia", "Noah", "Charlotte",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Sangwan", "Patel", "Sharma", "Chen", "Kim", "Nguyen",
    "Wilson", "Anderson", "Taylor", "Thomas", "Moore", "Jackson", "Martin", "Lee",
    "Thompson", "White", "Harris", "Clark", "Lewis", "Walker", "Hall", "Young",
]

EVENT_TYPES = [
    "login",
    "privilege_change",
    "policy_assignment",
    "token_creation",
    "token_usage",
    "mfa_disabled",
    "failed_authentication",
    "role_escalation",
    "password_reset",
    "account_lockout",
]

GROUPS = {
    "Active Directory": [
        "Domain Users", "Domain Admins", "Enterprise Admins", "IT Admins",
        "Helpdesk", "VPN Users", "Remote Desktop Users", "Security Team",
        "Finance Users", "HR Users", "Contractors", "Service Accounts",
    ],
    "AWS IAM": [
        "Developers", "DevOps", "ReadOnly", "PowerUser", "Administrators",
        "SecurityAudit", "Billing", "DataEngineers", "S3FullAccess",
    ],
    "Azure AD": [
        "Global Readers", "Global Admins", "User Admins", "Security Readers",
        "Application Admins", "Cloud App Admins", "Exchange Admins",
    ],
    "Okta": [
        "Everyone", "Admins", "Developers", "Contractors", "MFA Required",
        "Privileged Access", "App Users",
    ],
    "Salesforce": [
        "Standard Users", "System Administrators", "Marketing Users",
        "Sales Users", "API Integration Users", "View All Data",
    ],
    "ServiceNow": [
        "itil", "admin", "sn_incident_write", "sn_change_write",
        "catalog_admin", "security_admin", "report_user",
    ],
}

NESTED_GROUPS = {
    "Active Directory": {
        "Enterprise Admins": "Domain Admins",
        "IT Admins": "Helpdesk",
        "Security Team": "IT Admins",
    },
    "AWS IAM": {
        "Administrators": "PowerUser",
        "DevOps": "Developers",
        "S3FullAccess": "Developers",
    },
    "Azure AD": {
        "Global Admins": "User Admins",
        "Cloud App Admins": "Application Admins",
    },
}

GROUP_PRIVILEGE_MAP = {
    "Domain Admins": "Domain Admin",
    "Enterprise Admins": "Domain Admin",
    "Global Admins": "Global Admin",
    "Administrators": "AdministratorAccess",
    "S3FullAccess": "AdministratorAccess",
    "System Administrators": "Super Admin",
    "admin": "Super Admin",
    "security_admin": "Security Admin",
}


def _group_privilege(group: str, user_priv: str, is_admin: bool) -> str:
    if group in GROUP_PRIVILEGE_MAP:
        return GROUP_PRIVILEGE_MAP[group]
    if is_admin:
        return user_priv
    return "Standard User"


def _rand_date(days_back: int = 365) -> datetime:
    return datetime.utcnow() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )


def _username(first: str, last: str) -> str:
    patterns = [
        f"{first[0].lower()}{last.lower()}",
        f"{first.lower()}.{last.lower()}",
        f"{first[0].lower()}{last[:4].lower()}",
        f"{last.lower()}{first[0].lower()}",
    ]
    return random.choice(patterns)


def _email(first: str, last: str) -> str:
    return f"{first.lower()}.{last.lower()}@company.com"


def generate_enterprise_data(
    num_people: int = 350,
    num_audit_events: int = 1500,
) -> dict[str, Any]:
    random.seed(42)

    people = []
    # Anchor demo identity — cross-platform resolution showcase
    people.append(
        {
            "employee_id": "EMP10000",
            "first": "Yatin",
            "last": "Sangwan",
            "full_name": "Yatin Sangwan",
            "email": "yatin.sangwan@company.com",
            "username_base": "yatin.s",
            "department": "IT Security",
            "role": "Security Analyst",
            "manager": "N/A",
            "employment_status": "active",
            "is_anchor": True,
        }
    )

    for i in range(1, num_people):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        emp_id = f"EMP{10000 + i:05d}"
        dept = random.choice(DEPARTMENTS)
        role = random.choice(ROLES)
        manager_idx = random.randint(0, max(0, i - 1)) if i > 0 else 0
        manager = (
            f"{people[manager_idx]['first']} {people[manager_idx]['last']}"
            if i > 0
            else "N/A"
        )
        status = random.choices(
            ["active", "active", "active", "terminated", "on_leave"],
            weights=[70, 70, 70, 8, 5],
        )[0]

        people.append(
            {
                "employee_id": emp_id,
                "first": first,
                "last": last,
                "full_name": f"{first} {last}",
                "email": _email(first, last),
                "username_base": _username(first, last),
                "department": dept,
                "role": role,
                "manager": manager,
                "employment_status": status,
                "is_anchor": False,
            }
        )

    identity_snapshots = []
    group_memberships = []
    offboarding_records = []
    api_tokens = []
    username_platform_map: dict[str, list[str]] = {}

    for person in people:
        if person.get("is_anchor"):
            selected_platforms = PLATFORMS
        else:
            num_platforms = random.randint(2, 6)
            selected_platforms = random.sample(PLATFORMS, num_platforms)

        for platform in selected_platforms:
            if person.get("is_anchor"):
                if platform == "Active Directory":
                    username = "yatin.s"
                elif platform == "AWS IAM":
                    username = "ysangwan"
                elif platform == "Okta":
                    username = person["email"]
                else:
                    username = person["username_base"]
            elif platform == "AWS IAM":
                username = person["username_base"][:8]
            elif platform == "Okta":
                username = person["email"]
            else:
                username = person["username_base"]

            username_platform_map.setdefault(username, []).append(platform)

            if person["employment_status"] == "terminated":
                account_status = random.choices(
                    ["disabled", "active", "locked"],
                    weights=[60, 30, 10],
                )[0]
            else:
                account_status = random.choices(
                    ["active", "active", "disabled", "locked"],
                    weights=[85, 85, 10, 5],
                )[0]

            is_admin = person.get("is_anchor") or random.random() < 0.12
            if person.get("is_anchor"):
                priv_map = {
                    "Active Directory": "Domain Admin",
                    "AWS IAM": "AdministratorAccess",
                    "Azure AD": "Global Admin",
                    "Okta": "Security Admin",
                    "Salesforce": "Super Admin",
                    "ServiceNow": "Super Admin",
                }
                priv = priv_map.get(platform, "Cloud Admin")
                days_since_login = 124 if platform in ("AWS IAM", "Active Directory") else random.randint(5, 60)
            elif is_admin:
                priv = random.choice(
                    ["Domain Admin", "Global Admin", "AdministratorAccess", "Super Admin", "Security Admin"]
                )
                days_since_login = random.randint(1, 200) if account_status == "active" else random.randint(30, 400)
                if random.random() < 0.3:
                    days_since_login = random.randint(91, 365)
            elif person["role"] in ("IT Administrator", "DevOps Engineer", "Security Analyst"):
                priv = random.choice(["Cloud Admin", "Helpdesk Admin", "Power User", "Read Only Admin"])
                days_since_login = random.randint(1, 200) if account_status == "active" else random.randint(30, 400)
            else:
                priv = random.choice(["Standard User", "Power User", "Read Only Admin"])
                days_since_login = random.randint(1, 200) if account_status == "active" else random.randint(30, 400)

            identity_snapshots.append(
                {
                    "employee_id": person["employee_id"],
                    "username": username,
                    "email": person["email"],
                    "department": person["department"],
                    "role": person["role"],
                    "manager": person["manager"],
                    "employment_status": person["employment_status"],
                    "platform": platform,
                    "account_status": account_status,
                    "last_login": datetime.utcnow() - timedelta(days=days_since_login),
                    "privilege_level": priv,
                }
            )

            platform_groups = GROUPS.get(platform, ["Default Group"])
            num_groups = random.randint(1, 4)
            for group in random.sample(platform_groups, min(num_groups, len(platform_groups))):
                group_memberships.append(
                    {
                        "user": username,
                        "group": group,
                        "parent_group": NESTED_GROUPS.get(platform, {}).get(group),
                        "privilege_level": _group_privilege(group, priv, is_admin),
                        "platform": platform,
                    }
                )

            if person.get("is_anchor") or (random.random() < 0.25 and account_status == "active"):
                token_age = 421 if person.get("is_anchor") else random.randint(30, 500)
                api_tokens.append(
                    {
                        "owner": username,
                        "platform": platform,
                        "creation_date": datetime.utcnow() - timedelta(days=token_age),
                        "last_rotation": (
                            datetime.utcnow() - timedelta(days=random.randint(0, token_age))
                            if random.random() > 0.4
                            else None
                        ),
                        "permissions": random.sample(
                            ["read", "write", "admin", "delete", "full_access"],
                            random.randint(1, 3),
                        ),
                        "token_name": f"{platform.split()[0]}_token_{random.randint(100, 999)}",
                    }
                )

        if person["employment_status"] == "terminated":
            term_date = _rand_date(180)
            offboarding_records.append(
                {
                    "employee_id": person["employee_id"],
                    "termination_date": term_date,
                    "hr_status": "terminated",
                    "expected_disable_date": term_date + timedelta(days=1),
                }
            )

    audit_logs = []
    snapshot_usernames = list(username_platform_map.keys())
    for _ in range(num_audit_events):
        user = random.choice(snapshot_usernames)
        user_platforms = username_platform_map.get(user, PLATFORMS)
        platform = random.choice(user_platforms)
        event = random.choice(EVENT_TYPES)
        severity = "info"
        if event in ("mfa_disabled", "role_escalation", "failed_authentication"):
            severity = random.choice(["warning", "critical", "high"])
        elif event == "privilege_change":
            severity = random.choice(["warning", "high"])

        geo = random.choice(
            ["US-East", "US-West", "EU-West", "EU-Central", "APAC", "Unknown"]
        )
        if event in ("failed_authentication", "role_escalation") and random.random() < 0.08:
            geo = "Tor Exit Node"
        audit_logs.append(
            {
                "timestamp": _rand_date(90),
                "event_type": event,
                "user": user,
                "platform": platform,
                "details": f"{event.replace('_', ' ').title()} event for {user} on {platform}",
                "severity": severity,
                "ip_address": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "geo_location": geo,
            }
        )

    return {
        "people": people,
        "identity_snapshots": identity_snapshots,
        "group_memberships": group_memberships,
        "audit_logs": audit_logs,
        "offboarding_records": offboarding_records,
        "api_tokens": api_tokens,
    }
