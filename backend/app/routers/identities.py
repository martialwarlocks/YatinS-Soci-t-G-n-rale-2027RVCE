from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import ApiToken, AuditLog, Incident, UnifiedIdentity
from app.services.bootstrap import get_graph_engine
from app.services.impact_analysis import build_executive_context, build_hero_briefing
from app.services.remediation import generate_ai_analysis, generate_ai_summary, generate_openai_summary

router = APIRouter(prefix="/identities", tags=["Identities"])


@router.get("")
def list_identities(
    skip: int = 0,
    limit: int = 50,
    search: str = Query("", alias="q"),
    min_risk: float = Query(0, ge=0, le=100),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(UnifiedIdentity).filter(UnifiedIdentity.risk_score >= min_risk)
    if search:
        query = query.filter(
            UnifiedIdentity.full_name.ilike(f"%{search}%")
            | UnifiedIdentity.email.ilike(f"%{search}%")
        )
    total = query.count()
    identities = query.order_by(UnifiedIdentity.risk_score.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "items": [_summary(i) for i in identities],
    }


@router.get("/{unified_id}")
def get_identity(unified_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    identity = db.query(UnifiedIdentity).filter(UnifiedIdentity.unified_id == unified_id).first()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")

    usernames = {a.get("username") for a in (identity.platform_accounts or {}).values()}
    audit_timeline = (
        db.query(AuditLog)
        .filter(AuditLog.user.in_(usernames))
        .filter(AuditLog.timestamp >= datetime.utcnow() - timedelta(days=90))
        .order_by(AuditLog.timestamp.desc())
        .limit(50)
        .all()
    )

    tokens = db.query(ApiToken).filter(ApiToken.owner.in_(usernames)).all()
    graph = get_graph_engine()
    attack_paths = graph.get_attack_paths(unified_id)
    graph_data = graph.to_react_flow(unified_id, depth=2, max_nodes=60)

    token_payload = [
        {
            "token_name": t.token_name,
            "platform": t.platform,
            "creation_date": t.creation_date.isoformat(),
            "last_rotation": t.last_rotation.isoformat() if t.last_rotation else None,
            "permissions": t.permissions,
            "age_days": (datetime.utcnow() - t.creation_date).days,
            "rotation_status": "overdue" if (datetime.utcnow() - t.creation_date).days > 90 else "ok",
        }
        for t in tokens
    ]

    identity_dict = {
        "unified_id": identity.unified_id,
        "employee_id": identity.employee_id,
        "full_name": identity.full_name,
        "employment_status": identity.employment_status,
        "platform_accounts": identity.platform_accounts or {},
    }

    hero_briefing = build_hero_briefing(
        identity_dict,
        identity.effective_privileges or [],
        token_payload,
        identity.remediation_actions or [],
        identity.risk_factors or [],
        identity.risk_score,
    )
    executive_context = build_executive_context(db)

    breakdown = identity.risk_breakdown or {}
    ai_analysis = breakdown.get("_ai_analysis", {})
    anomaly_explanation = breakdown.get("_anomaly_explanation", {})
    data_quality_issues = breakdown.get("_data_quality_issues", [])
    resolution_map = [
        {"platform": platform, "username": acct.get("username"), "email": identity.email}
        for platform, acct in (identity.platform_accounts or {}).items()
    ]

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
        "direct_privileges": identity.direct_privileges,
        "effective_privileges": identity.effective_privileges,
        "risk_score": identity.risk_score,
        "risk_factors": identity.risk_factors,
        "risk_breakdown": {k: v for k, v in breakdown.items() if not k.startswith("_")},
        "anomaly_score": identity.anomaly_score,
        "is_anomaly": identity.is_anomaly,
        "ai_summary": identity.ai_summary,
        "ai_analysis": ai_analysis,
        "anomaly_explanation": anomaly_explanation,
        "data_quality_issues": data_quality_issues,
        "resolution_map": resolution_map,
        "remediation_actions": identity.remediation_actions,
        "compliance_mappings": identity.compliance_mappings,
        "access_timeline": [
            {
                "timestamp": a.timestamp.isoformat(),
                "event_type": a.event_type,
                "platform": a.platform,
                "details": a.details,
                "severity": a.severity,
                "geo_location": a.geo_location,
            }
            for a in audit_timeline
        ],
        "tokens": token_payload,
        "attack_paths": attack_paths,
        "graph": graph_data,
        "hero_briefing": hero_briefing,
        "executive_context": executive_context,
    }


@router.patch("/{unified_id}/remediation/{action_id}")
def update_remediation_status(
    unified_id: str,
    action_id: str,
    body: dict,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    identity = db.query(UnifiedIdentity).filter(UnifiedIdentity.unified_id == unified_id).first()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")

    status = body.get("status", "approved")
    actions = identity.remediation_actions or []
    updated = False
    for action in actions:
        if action.get("id") == action_id:
            action["status"] = status
            action["updated_at"] = datetime.utcnow().isoformat()
            updated = True
            break

    if not updated:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    identity.remediation_actions = actions
    db.commit()
    return {"status": "updated", "action_id": action_id, "new_status": status}


@router.post("/{unified_id}/ai-analysis")
async def regenerate_ai_analysis(
    unified_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    identity = db.query(UnifiedIdentity).filter(UnifiedIdentity.unified_id == unified_id).first()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")

    identity_dict = {
        "full_name": identity.full_name,
        "department": identity.department,
        "employment_status": identity.employment_status,
        "platform_accounts": identity.platform_accounts or {},
    }

    breakdown = identity.risk_breakdown or {}
    explanation = breakdown.get("_anomaly_explanation", {})

    openai_summary = await generate_openai_summary(
        identity_dict, identity.risk_score, identity.risk_factors or []
    )
    if openai_summary:
        identity.ai_summary = openai_summary
        db.commit()
        return {"ai_summary": openai_summary, "source": "openai"}

    analysis = generate_ai_analysis(
        identity_dict,
        identity.risk_score,
        identity.risk_factors or [],
        identity.effective_privileges or [],
        explanation,
    )
    identity.ai_summary = analysis["summary"]
    breakdown["_ai_analysis"] = analysis
    identity.risk_breakdown = breakdown
    db.commit()

    return {"ai_summary": analysis["summary"], "ai_analysis": analysis, "source": "intelligence_engine"}


def _summary(identity: UnifiedIdentity) -> dict:
    return {
        "unified_id": identity.unified_id,
        "full_name": identity.full_name,
        "email": identity.email,
        "department": identity.department,
        "risk_score": identity.risk_score,
        "platforms": identity.platforms,
        "employment_status": identity.employment_status,
        "is_anomaly": identity.is_anomaly,
    }
