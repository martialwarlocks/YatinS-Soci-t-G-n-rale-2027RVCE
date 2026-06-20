from collections import defaultdict
from typing import Any


def resolve_identities(
    people: list[dict],
    identity_snapshots: list[dict],
) -> list[dict]:
    """Correlate platform accounts to unified identities via employee_id and email."""
    by_employee: dict[str, dict] = {}

    for person in people:
        by_employee[person["employee_id"]] = {
            "unified_id": f"UID-{person['employee_id']}",
            "employee_id": person["employee_id"],
            "full_name": person["full_name"],
            "email": person["email"],
            "department": person["department"],
            "role": person["role"],
            "manager": person["manager"],
            "employment_status": person["employment_status"],
            "platform_accounts": {},
            "snapshots": [],
        }

    email_to_employee: dict[str, str] = {p["email"]: p["employee_id"] for p in people}

    for snap in identity_snapshots:
        emp_id = snap["employee_id"]
        if emp_id not in by_employee:
            if snap["email"] in email_to_employee:
                emp_id = email_to_employee[snap["email"]]
            else:
                continue

        unified = by_employee[emp_id]
        platform = snap["platform"]
        unified["platform_accounts"][platform] = {
            "username": snap["username"],
            "account_status": snap["account_status"],
            "privilege_level": snap["privilege_level"],
            "last_login": snap["last_login"].isoformat() if snap["last_login"] else None,
        }
        unified["snapshots"].append(snap)

    return list(by_employee.values())


def build_username_index(snapshots: list[dict]) -> dict[str, str]:
    """Map platform username -> employee_id."""
    index: dict[str, str] = {}
    for snap in snapshots:
        index[snap["username"]] = snap["employee_id"]
        index[snap["email"]] = snap["employee_id"]
    return index
