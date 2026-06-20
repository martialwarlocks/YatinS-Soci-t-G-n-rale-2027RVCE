from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Incident, UnifiedIdentity
from app.services.bootstrap import get_graph_engine
from app.services.compliance import generate_compliance_report

router = APIRouter(tags=["Incidents & Compliance"])


class IncidentUpdate(BaseModel):
    status: str | None = None


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.status:
        incident.status = body.status
    db.commit()
    return {"incident_id": incident_id, "status": incident.status}


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db), _=Depends(get_current_user)):
    incidents = db.query(Incident).order_by(Incident.risk_score.desc()).all()
    return [
        {
            "incident_id": i.incident_id,
            "unified_id": i.unified_id,
            "user_name": i.user_name,
            "severity": i.severity,
            "status": i.status,
            "findings": i.findings,
            "risk_score": i.risk_score,
            "created_at": i.created_at.isoformat(),
            "compliance_controls": i.compliance_controls,
        }
        for i in incidents
    ]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    identity = (
        db.query(UnifiedIdentity)
        .filter(UnifiedIdentity.unified_id == incident.unified_id)
        .first()
    )

    graph = get_graph_engine()
    attack_paths = graph.get_attack_paths(incident.unified_id) if identity else []
    graph_data = graph.to_react_flow(incident.unified_id, depth=3) if identity else {"nodes": [], "edges": []}

    return {
        "incident_id": incident.incident_id,
        "unified_id": incident.unified_id,
        "user_name": incident.user_name,
        "severity": incident.severity,
        "status": incident.status,
        "findings": incident.findings,
        "risk_score": incident.risk_score,
        "created_at": incident.created_at.isoformat(),
        "compliance_controls": incident.compliance_controls,
        "identity": {
            "full_name": identity.full_name if identity else incident.user_name,
            "department": identity.department if identity else "",
            "platform_accounts": identity.platform_accounts if identity else {},
            "ai_summary": identity.ai_summary if identity else "",
            "remediation_actions": identity.remediation_actions if identity else [],
        },
        "attack_paths": attack_paths,
        "graph": graph_data,
    }


@router.get("/compliance/report")
def compliance_report(db: Session = Depends(get_db), _=Depends(get_current_user)):
    identities = db.query(UnifiedIdentity).all()
    identity_dicts = [
        {
            "full_name": i.full_name,
            "unified_id": i.unified_id,
            "risk_score": i.risk_score,
            "compliance_mappings": i.compliance_mappings,
        }
        for i in identities
    ]
    return generate_compliance_report(identity_dicts)


@router.get("/graph/global")
def global_graph(_=Depends(get_current_user)):
    graph = get_graph_engine()
    return {
        "graph": graph.to_react_flow(None, depth=1),
        "stats": graph.get_stats(),
    }
