from typing import Any


COMPLIANCE_MAP = {
    "privilege_risk": [
        {"framework": "NIST", "control": "AC-6", "title": "Least Privilege", "description": "Excessive privileges detected beyond job requirements"},
        {"framework": "CIS", "control": "CIS-5", "title": "Account Management", "description": "Privileged account requires access review"},
        {"framework": "MITRE ATT&CK", "control": "T1078", "title": "Valid Accounts", "description": "Abuse of valid privileged accounts for lateral movement"},
    ],
    "dormancy_risk": [
        {"framework": "NIST", "control": "AC-2", "title": "Account Management", "description": "Dormant privileged accounts must be disabled"},
        {"framework": "CIS", "control": "CIS-5", "title": "Account Management", "description": "Inactive accounts exceed policy threshold"},
        {"framework": "GDPR", "control": "Article 32", "title": "Security of Processing", "description": "Inactive access increases data breach risk"},
    ],
    "offboarding_risk": [
        {"framework": "NIST", "control": "AC-2", "title": "Account Management", "description": "Terminated user retains active platform access"},
        {"framework": "CIS", "control": "CIS-6", "title": "Access Control Management", "description": "Offboarding process failure detected"},
        {"framework": "GDPR", "control": "Article 5", "title": "Principles of Processing", "description": "Unauthorized access to personal data post-termination"},
        {"framework": "MITRE ATT&CK", "control": "T1098", "title": "Account Manipulation", "description": "Orphaned account available for account takeover"},
    ],
    "token_risk": [
        {"framework": "NIST", "control": "AC-2", "title": "Account Management", "description": "API credentials exceed rotation policy"},
        {"framework": "CIS", "control": "CIS-6", "title": "Access Control Management", "description": "Unrotated credentials increase compromise risk"},
        {"framework": "MITRE ATT&CK", "control": "T1552", "title": "Unsecured Credentials", "description": "Stale API tokens may be exploited"},
    ],
    "behavior_risk": [
        {"framework": "NIST", "control": "AC-2", "title": "Account Management", "description": "Anomalous authentication behavior detected"},
        {"framework": "MITRE ATT&CK", "control": "T1078", "title": "Valid Accounts", "description": "Suspicious use of valid credentials"},
        {"framework": "GDPR", "control": "Article 32", "title": "Security of Processing", "description": "Behavioral anomalies indicate potential breach"},
    ],
    "escalation_risk": [
        {"framework": "NIST", "control": "AC-6", "title": "Least Privilege", "description": "Unauthorized privilege escalation detected"},
        {"framework": "MITRE ATT&CK", "control": "T1078.003", "title": "Local Accounts", "description": "Privilege escalation via account manipulation"},
        {"framework": "CIS", "control": "CIS-6", "title": "Access Control Management", "description": "Unexpected role assignment requires investigation"},
    ],
}


def map_compliance(risk_breakdown: dict[str, float], threshold: float = 5.0) -> list[dict]:
    mappings = []
    seen = set()

    for category, score in risk_breakdown.items():
        if score >= threshold and category in COMPLIANCE_MAP:
            for control in COMPLIANCE_MAP[category]:
                key = (control["framework"], control["control"])
                if key not in seen:
                    seen.add(key)
                    mappings.append({**control, "risk_category": category, "risk_score_component": score})

    return mappings


def generate_compliance_report(unified_identities: list[dict]) -> dict[str, Any]:
    framework_counts: dict[str, int] = {}
    control_findings: list[dict] = []
    affected_identities = 0

    for identity in unified_identities:
        mappings = identity.get("compliance_mappings", [])
        if mappings:
            affected_identities += 1
        for m in mappings:
            fw = m["framework"]
            framework_counts[fw] = framework_counts.get(fw, 0) + 1
            control_findings.append(
                {
                    "identity": identity.get("full_name"),
                    "unified_id": identity.get("unified_id"),
                    "framework": fw,
                    "control": m["control"],
                    "title": m["title"],
                    "risk_score": identity.get("risk_score", 0),
                }
            )

    return {
        "total_identities_assessed": len(unified_identities),
        "identities_with_findings": affected_identities,
        "framework_summary": framework_counts,
        "findings": sorted(control_findings, key=lambda x: x["risk_score"], reverse=True)[:100],
        "compliance_score": round(
            max(0, 100 - (affected_identities / max(len(unified_identities), 1)) * 100),
            1,
        ),
    }
