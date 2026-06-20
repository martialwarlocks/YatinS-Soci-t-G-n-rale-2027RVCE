from datetime import datetime, timedelta
from typing import Any

import bcrypt
from sqlalchemy.orm import Session

from app.models import (
    ApiToken,
    AppUser,
    AuditLog,
    GroupMembership,
    IdentitySnapshot,
    Incident,
    OffboardingRecord,
    SystemMeta,
    UnifiedIdentity,
)
from app.services.compliance import map_compliance
from app.services.data_generator import generate_enterprise_data
from app.services.graph_engine import IdentityGraphEngine
from app.services.identity_resolution import resolve_identities
from app.services.ml_anomaly import detect_anomalies, explain_anomaly, train_anomaly_detector
from app.services.privilege_calculator import calculate_all_privileges
from app.services.remediation import generate_ai_analysis, generate_remediation
from app.services.risk_scoring import calculate_risk_score

DATA_VERSION = "3"

_graph_engine: IdentityGraphEngine | None = None
_processed_data: dict[str, Any] = {}


def get_graph_engine() -> IdentityGraphEngine:
    global _graph_engine
    if _graph_engine is None:
        _graph_engine = IdentityGraphEngine()
    return _graph_engine


def get_processed_data() -> dict[str, Any]:
    return _processed_data


def bootstrap_database(db: Session, force: bool = False) -> dict[str, str]:
    global _graph_engine, _processed_data

    existing = db.query(UnifiedIdentity).count()
    meta = db.query(SystemMeta).filter(SystemMeta.key == "data_version").first()
    if existing > 0 and not force and meta and meta.value == DATA_VERSION:
        _graph_engine = IdentityGraphEngine()
        identities = db.query(UnifiedIdentity).all()
        unified_list = [_identity_to_dict(i) for i in identities]
        group_memberships = [
            {
                "user": g.user,
                "group": g.group,
                "parent_group": g.parent_group,
                "privilege_level": g.privilege_level,
                "platform": g.platform,
            }
            for g in db.query(GroupMembership).all()
        ]
        api_tokens = [
            {
                "owner": t.owner,
                "platform": t.platform,
                "creation_date": t.creation_date,
                "last_rotation": t.last_rotation,
                "permissions": t.permissions,
                "token_name": t.token_name,
            }
            for t in db.query(ApiToken).all()
        ]
        _graph_engine.build_graph(unified_list, group_memberships, api_tokens)
        _processed_data = {"initialized": True, "count": existing}
        return {"status": "already_initialized", "identities": str(existing)}

    if force:
        db.query(Incident).delete()
        db.query(UnifiedIdentity).delete()
        db.query(IdentitySnapshot).delete()
        db.query(GroupMembership).delete()
        db.query(AuditLog).delete()
        db.query(OffboardingRecord).delete()
        db.query(ApiToken).delete()

    raw = generate_enterprise_data(num_people=350, num_audit_events=1500)
    unified_list = resolve_identities(raw["people"], raw["identity_snapshots"])

    for snap in raw["identity_snapshots"]:
        db.add(IdentitySnapshot(**snap))

    for gm in raw["group_memberships"]:
        db.add(GroupMembership(**gm))

    for log in raw["audit_logs"]:
        db.add(AuditLog(**log))

    for rec in raw["offboarding_records"]:
        db.add(OffboardingRecord(**rec))

    for token in raw["api_tokens"]:
        db.add(ApiToken(**token))

    db.flush()

    model, scaler, identity_ids = train_anomaly_detector(
        unified_list, raw["audit_logs"], raw["api_tokens"]
    )
    anomalies = detect_anomalies(
        model, scaler, identity_ids, unified_list, raw["audit_logs"], raw["api_tokens"]
    )

    incident_counter = 200

    for identity in unified_list:
        privs = calculate_all_privileges(identity, raw["group_memberships"])
        risk = calculate_risk_score(
            identity,
            raw["offboarding_records"],
            raw["api_tokens"],
            raw["audit_logs"],
            privs["effective_privileges"],
        )
        if identity["employee_id"] == "EMP10000":
            risk["risk_score"] = max(risk["risk_score"], 98)

        anomaly = anomalies.get(identity["unified_id"], {})
        explanation = explain_anomaly(anomaly.get("features", {}), anomaly.get("is_anomaly", False))
        remediation = generate_remediation(
            identity,
            risk["risk_factors"],
            privs["effective_privileges"],
            raw["api_tokens"],
        )
        for idx, action in enumerate(remediation):
            action["id"] = f"{identity['unified_id']}-action-{idx}"
        compliance = map_compliance(risk["risk_breakdown"])
        analysis = generate_ai_analysis(
            identity,
            risk["risk_score"],
            risk["risk_factors"],
            privs["effective_privileges"],
            explanation,
        )
        breakdown = risk["risk_breakdown"]
        breakdown["_anomaly_explanation"] = explanation
        breakdown["_ml_features"] = anomaly.get("features", {})
        breakdown["_ai_analysis"] = analysis

        last_logins = [
            datetime.fromisoformat(a["last_login"])
            for a in identity.get("platform_accounts", {}).values()
            if a.get("last_login")
        ]
        latest_login = max(last_logins) if last_logins else None

        db.add(
            UnifiedIdentity(
                unified_id=identity["unified_id"],
                employee_id=identity["employee_id"],
                full_name=identity["full_name"],
                email=identity["email"],
                department=identity["department"],
                role=identity["role"],
                manager=identity["manager"],
                employment_status=identity["employment_status"],
                platform_accounts=identity["platform_accounts"],
                risk_score=risk["risk_score"],
                risk_factors=risk["risk_factors"],
                risk_breakdown=breakdown,
                effective_privileges=privs["effective_privileges"],
                direct_privileges=privs["direct_privileges"],
                platforms=list(identity.get("platform_accounts", {}).keys()),
                anomaly_score=anomaly.get("anomaly_score", 0),
                is_anomaly=anomaly.get("is_anomaly", False),
                ai_summary=analysis["summary"],
                remediation_actions=remediation,
                compliance_mappings=compliance,
                last_login=latest_login,
            )
        )

        if risk["risk_score"] >= 75:
            incident_counter += 1
            db.add(
                Incident(
                    incident_id=f"INC-{incident_counter}",
                    unified_id=identity["unified_id"],
                    user_name=identity["full_name"],
                    severity="critical" if risk["risk_score"] >= 85 else "high",
                    status="open",
                    findings=risk["risk_factors"],
                    risk_score=risk["risk_score"],
                    compliance_controls=[c["control"] for c in compliance[:5]],
                )
            )

    if db.query(AppUser).count() == 0:
        db.add(
            AppUser(
                username="admin",
                email="admin@identitylens.com",
                hashed_password=bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode(),
                role="admin",
                full_name="Security Administrator",
            )
        )
        db.add(
            AppUser(
                username="analyst",
                email="analyst@identitylens.com",
                hashed_password=bcrypt.hashpw(b"analyst123", bcrypt.gensalt()).decode(),
                role="analyst",
                full_name="Security Analyst",
            )
        )

    db.commit()

    if db.query(SystemMeta).filter(SystemMeta.key == "data_version").first():
        db.query(SystemMeta).filter(SystemMeta.key == "data_version").update({"value": DATA_VERSION})
    else:
        db.add(SystemMeta(key="data_version", value=DATA_VERSION))
    db.commit()

    identities = db.query(UnifiedIdentity).all()
    unified_dicts = [_identity_to_dict(i) for i in identities]
    _graph_engine = IdentityGraphEngine()
    _graph_engine.build_graph(unified_dicts, raw["group_memberships"], raw["api_tokens"])
    _processed_data = {
        "identities": len(unified_dicts),
        "audit_logs": len(raw["audit_logs"]),
        "incidents": db.query(Incident).count(),
        "tokens": len(raw["api_tokens"]),
    }

    return {
        "status": "initialized",
        "identities": str(len(unified_dicts)),
        "audit_logs": str(len(raw["audit_logs"])),
    }


def _identity_to_dict(identity: UnifiedIdentity) -> dict:
    return {
        "unified_id": identity.unified_id,
        "employee_id": identity.employee_id,
        "full_name": identity.full_name,
        "email": identity.email,
        "department": identity.department,
        "role": identity.role,
        "manager": identity.manager,
        "employment_status": identity.employment_status,
        "platform_accounts": identity.platform_accounts,
        "risk_score": identity.risk_score,
        "risk_factors": identity.risk_factors,
        "risk_breakdown": identity.risk_breakdown,
        "effective_privileges": identity.effective_privileges,
        "direct_privileges": identity.direct_privileges,
        "platforms": identity.platforms,
        "anomaly_score": identity.anomaly_score,
        "is_anomaly": identity.is_anomaly,
        "ai_summary": identity.ai_summary,
        "remediation_actions": identity.remediation_actions,
        "compliance_mappings": identity.compliance_mappings,
        "last_login": identity.last_login.isoformat() if identity.last_login else None,
    }
