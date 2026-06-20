from collections import defaultdict
from typing import Any


PRIVILEGE_HIERARCHY = {
    "Standard User": 1,
    "Power User": 2,
    "Read Only Admin": 3,
    "Helpdesk Admin": 4,
    "Cloud Admin": 5,
    "Security Admin": 6,
    "AdministratorAccess": 7,
    "Global Admin": 8,
    "Domain Admin": 9,
    "Super Admin": 10,
}


def _privilege_rank(level: str) -> int:
    return PRIVILEGE_HIERARCHY.get(level, 1)


def calculate_effective_privileges(
    username: str,
    platform: str,
    group_memberships: list[dict],
    direct_privilege: str,
) -> dict[str, Any]:
    """Traverse nested group memberships to compute effective privileges."""
    platform_groups = [g for g in group_memberships if g["platform"] == platform]

    group_map: dict[str, dict] = {g["group"]: g for g in platform_groups}
    parent_map: dict[str, str | None] = {}
    for g in platform_groups:
        parent_map[g["group"]] = g.get("parent_group")

    user_groups = [g["group"] for g in platform_groups if g["user"] == username]

    visited: set[str] = set()
    inherited_groups: list[str] = []
    privilege_paths: list[list[str]] = []

    def traverse(group: str, path: list[str]) -> None:
        if group in visited:
            return
        visited.add(group)
        current_path = path + [group]
        inherited_groups.append(group)

        parent = parent_map.get(group)
        if parent:
            privilege_paths.append(current_path + [parent])
            traverse(parent, current_path)
        else:
            privilege_paths.append(current_path)

    for group in user_groups:
        traverse(group, [username])

    all_privileges = [direct_privilege]
    for group in inherited_groups:
        if group in group_map:
            all_privileges.append(group_map[group]["privilege_level"])

    effective = max(all_privileges, key=_privilege_rank)

    paths = []
    for path in privilege_paths:
        if len(path) > 1:
            paths.append(" → ".join(path))

    return {
        "direct": direct_privilege,
        "effective": effective,
        "inherited_groups": list(set(inherited_groups)),
        "privilege_paths": paths[:5],
        "all_privileges": list(set(all_privileges)),
    }


def calculate_all_privileges(
    unified_identity: dict,
    group_memberships: list[dict],
) -> dict[str, Any]:
    """Calculate privileges across all platforms for a unified identity."""
    direct: list[dict] = []
    effective: list[dict] = []
    all_paths: list[str] = []

    for platform, account in unified_identity.get("platform_accounts", {}).items():
        priv = account.get("privilege_level", "Standard User")
        username = account.get("username", "")

        direct.append({"platform": platform, "privilege": priv, "type": "direct"})

        result = calculate_effective_privileges(
            username, platform, group_memberships, priv
        )
        effective.append(
            {
                "platform": platform,
                "privilege": result["effective"],
                "inherited_groups": result["inherited_groups"],
                "paths": result["privilege_paths"],
            }
        )
        all_paths.extend(result["privilege_paths"])

    return {
        "direct_privileges": direct,
        "effective_privileges": effective,
        "privilege_paths": all_paths,
    }
