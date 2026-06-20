from collections import defaultdict
from typing import Any

import networkx as nx


class IdentityGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(
        self,
        unified_identities: list[dict],
        group_memberships: list[dict],
        api_tokens: list[dict],
    ) -> nx.DiGraph:
        self.graph = nx.DiGraph()

        for identity in unified_identities:
            uid = identity["unified_id"]
            self.graph.add_node(
                uid,
                node_type="User",
                label=identity["full_name"],
                department=identity.get("department", ""),
                risk_score=identity.get("risk_score", 0),
            )

            for platform, account in identity.get("platform_accounts", {}).items():
                platform_node = f"platform:{platform}:{uid}"
                self.graph.add_node(
                    platform_node,
                    node_type="Platform",
                    label=platform,
                    platform=platform,
                )
                self.graph.add_edge(uid, platform_node, relationship="HasAccount")

                priv = account.get("privilege_level", "Standard User")
                role_node = f"role:{platform}:{priv}:{uid}"
                self.graph.add_node(
                    role_node,
                    node_type="Role",
                    label=priv,
                    platform=platform,
                    privilege=priv,
                )
                self.graph.add_edge(platform_node, role_node, relationship="HasRole")

        for gm in group_memberships:
            group_node = f"group:{gm['platform']}:{gm['group']}"
            user_node_candidates = [
                uid
                for uid in self.graph.nodes
                if self.graph.nodes[uid].get("node_type") == "User"
            ]

            if group_node not in self.graph:
                self.graph.add_node(
                    group_node,
                    node_type="Group",
                    label=gm["group"],
                    platform=gm["platform"],
                    privilege_level=gm["privilege_level"],
                )

            if gm.get("parent_group"):
                parent_node = f"group:{gm['platform']}:{gm['parent_group']}"
                if parent_node not in self.graph:
                    self.graph.add_node(
                        parent_node,
                        node_type="Group",
                        label=gm["parent_group"],
                        platform=gm["platform"],
                    )
                self.graph.add_edge(group_node, parent_node, relationship="Inherits")

            for uid in user_node_candidates:
                identity = next(
                    (i for i in unified_identities if i["unified_id"] == uid), None
                )
                if identity:
                    acct = identity.get("platform_accounts", {}).get(gm["platform"], {})
                    if acct.get("username") == gm["user"]:
                        self.graph.add_edge(uid, group_node, relationship="MemberOf")

        resources = [
            ("S3 Customer Database", "AWS IAM", "full_access"),
            ("Production VPC", "AWS IAM", "admin"),
            ("Azure Key Vault", "Azure AD", "read_write"),
            ("Salesforce CRM Data", "Salesforce", "read_write"),
            ("ServiceNow CMDB", "ServiceNow", "admin"),
            ("AD Domain Controller", "Active Directory", "admin"),
            ("Okta Admin Console", "Okta", "admin"),
        ]

        for res_name, platform, access in resources:
            res_node = f"resource:{platform}:{res_name}"
            self.graph.add_node(
                res_node,
                node_type="Resource",
                label=res_name,
                platform=platform,
                access=access,
            )
            for node, data in self.graph.nodes(data=True):
                if data.get("node_type") == "Role" and platform in node:
                    if data.get("privilege") in (
                        "AdministratorAccess",
                        "Domain Admin",
                        "Global Admin",
                        "Super Admin",
                        "Cloud Admin",
                    ):
                        self.graph.add_edge(node, res_node, relationship="HasAccess")

        username_to_uid = {}
        for identity in unified_identities:
            for platform, account in identity.get("platform_accounts", {}).items():
                username_to_uid[account.get("username", "")] = identity["unified_id"]

        for token in api_tokens:
            owner = token["owner"]
            uid = username_to_uid.get(owner)
            if uid:
                token_node = f"token:{token['platform']}:{token.get('token_name', owner)}"
                self.graph.add_node(
                    token_node,
                    node_type="Token",
                    label=token.get("token_name", "API Token"),
                    platform=token["platform"],
                    permissions=token.get("permissions", []),
                )
                self.graph.add_edge(uid, token_node, relationship="OwnsToken")
                for res_name, plat, _ in resources:
                    if plat == token["platform"] and "admin" in token.get("permissions", []):
                        res_node = f"resource:{plat}:{res_name}"
                        if res_node in self.graph:
                            self.graph.add_edge(token_node, res_node, relationship="HasAccess")

        return self.graph

    def get_attack_paths(self, unified_id: str, max_paths: int = 5) -> list[dict]:
        paths = []
        if unified_id not in self.graph:
            return paths

        resource_nodes = [
            n
            for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "Resource"
        ]

        for resource in resource_nodes[:10]:
            try:
                for path in nx.all_simple_paths(
                    self.graph, unified_id, resource, cutoff=6
                ):
                    path_data = []
                    for node in path:
                        data = self.graph.nodes[node]
                        path_data.append(
                            {
                                "id": node,
                                "label": data.get("label", node),
                                "type": data.get("node_type", "Unknown"),
                            }
                        )
                    paths.append({"target": self.graph.nodes[resource]["label"], "path": path_data})
                    if len(paths) >= max_paths:
                        return paths
            except nx.NetworkXNoPath:
                continue

        return paths

    def to_react_flow(
        self,
        unified_id: str | None = None,
        depth: int = 2,
        max_nodes: int = 60,
    ) -> dict:
        nodes = []
        edges = []
        included = set()

        if unified_id and unified_id in self.graph:
            included.add(unified_id)
            frontier = {unified_id}
            for _ in range(depth):
                if len(included) >= max_nodes:
                    break
                next_frontier: set[str] = set()
                for node in frontier:
                    neighbors = list(self.graph.predecessors(node)) + list(
                        self.graph.successors(node)
                    )
                    for neighbor in neighbors:
                        if neighbor in included:
                            continue
                        next_frontier.add(neighbor)
                        included.add(neighbor)
                        if len(included) >= max_nodes:
                            break
                    if len(included) >= max_nodes:
                        break
                frontier = next_frontier
        else:
            included = set(list(self.graph.nodes)[:max_nodes])

        type_colors = {
            "User": "#3b82f6",
            "Group": "#8b5cf6",
            "Role": "#f59e0b",
            "Resource": "#ef4444",
            "Platform": "#06b6d4",
            "Token": "#ec4899",
        }

        for i, node in enumerate(included):
            if node not in self.graph:
                continue
            data = self.graph.nodes[node]
            nodes.append(
                {
                    "id": node,
                    "type": "default",
                    "position": {"x": (i % 8) * 180, "y": (i // 8) * 120},
                    "data": {
                        "label": data.get("label", node),
                        "nodeType": data.get("node_type", "Unknown"),
                    },
                    "style": {
                        "background": type_colors.get(data.get("node_type"), "#64748b"),
                        "color": "#fff",
                        "border": "1px solid #334155",
                        "borderRadius": "8px",
                        "padding": "8px 12px",
                        "fontSize": "12px",
                    },
                }
            )

        for u, v, edge_data in self.graph.edges(data=True):
            if u in included and v in included:
                edges.append(
                    {
                        "id": f"{u}-{v}",
                        "source": u,
                        "target": v,
                        "label": edge_data.get("relationship", ""),
                        "animated": edge_data.get("relationship") == "HasAccess",
                        "style": {"stroke": "#64748b"},
                    }
                )

        return {"nodes": nodes, "edges": edges}

    def get_stats(self) -> dict:
        type_counts = defaultdict(int)
        for _, data in self.graph.nodes(data=True):
            type_counts[data.get("node_type", "Unknown")] += 1
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": dict(type_counts),
        }
