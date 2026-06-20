from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import ApiToken, AuditLog, Incident, UnifiedIdentity
from app.services.bootstrap import get_graph_engine, get_processed_data
from app.services.compliance import generate_compliance_report

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/kpis")
def get_kpis(db: Session = Depends(get_db), _=Depends(get_current_user)):
    total = db.query(UnifiedIdentity).count()
    high_risk = db.query(UnifiedIdentity).filter(UnifiedIdentity.risk_score >= 70).count()
    all_identities = db.query(UnifiedIdentity).all()
    orphaned = sum(
        1
        for i in all_identities
        if i.employment_status == "terminated"
        and (i.risk_breakdown or {}).get("offboarding_risk", 0) > 10
    )
    dormant_admins = sum(
        1 for i in all_identities if (i.risk_breakdown or {}).get("dormancy_risk", 0) > 10
    )
    active_tokens = db.query(ApiToken).count()
    critical_incidents = (
        db.query(Incident).filter(Incident.severity == "critical", Incident.status == "open").count()
    )
    anomalies = db.query(UnifiedIdentity).filter(UnifiedIdentity.is_anomaly == True).count()

    return {
        "total_identities": total,
        "high_risk_users": high_risk,
        "orphaned_accounts": orphaned,
        "dormant_admins": dormant_admins,
        "active_tokens": active_tokens,
        "critical_incidents": critical_incidents,
        "ml_anomalies": anomalies,
    }


@router.get("/leaderboard")
def get_leaderboard(
    limit: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="q"),
    sort_by: str = Query("risk_score"),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(UnifiedIdentity)
    if search:
        query = query.filter(
            UnifiedIdentity.full_name.ilike(f"%{search}%")
            | UnifiedIdentity.email.ilike(f"%{search}%")
            | UnifiedIdentity.department.ilike(f"%{search}%")
        )

    sort_map = {
        "risk_score": desc(UnifiedIdentity.risk_score),
        "name": UnifiedIdentity.full_name,
        "department": UnifiedIdentity.department,
    }
    query = query.order_by(sort_map.get(sort_by, desc(UnifiedIdentity.risk_score)))

    identities = query.limit(limit).all()
    return [
        {
            "unified_id": i.unified_id,
            "name": i.full_name,
            "risk_score": i.risk_score,
            "department": i.department,
            "platforms": i.platforms,
            "privileges": [
                ep["privilege"]
                for ep in (i.effective_privileges or [])
                if ep.get("privilege") not in ("Standard User", "Power User")
            ][:3],
            "status": i.employment_status,
            "is_anomaly": i.is_anomaly,
        }
        for i in identities
    ]


@router.get("/risk-trend")
def get_risk_trend(db: Session = Depends(get_db), _=Depends(get_current_user)):
    buckets = {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0}
    for identity in db.query(UnifiedIdentity.risk_score).all():
        score = identity.risk_score
        if score <= 25:
            buckets["0-25"] += 1
        elif score <= 50:
            buckets["26-50"] += 1
        elif score <= 75:
            buckets["51-75"] += 1
        else:
            buckets["76-100"] += 1
    return [{"range": k, "count": v} for k, v in buckets.items()]


@router.get("/risk-timeline")
def get_risk_timeline(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Security event volume over last 30 days from audit logs."""
    from app.models import AuditLog

    now = datetime.utcnow()
    days = [(now - timedelta(days=i)).date() for i in range(29, -1, -1)]
    day_counts = {d.isoformat(): 0 for d in days}

    logs = (
        db.query(AuditLog)
        .filter(AuditLog.timestamp >= now - timedelta(days=30))
        .filter(AuditLog.severity.in_(["warning", "critical", "high"]))
        .all()
    )
    for log in logs:
        key = log.timestamp.date().isoformat()
        if key in day_counts:
            day_counts[key] += 1

    return [{"date": d, "events": day_counts[d]} for d in day_counts]


@router.get("/department-risk")
def get_department_risk(db: Session = Depends(get_db), _=Depends(get_current_user)):
    results = (
        db.query(
            UnifiedIdentity.department,
            func.avg(UnifiedIdentity.risk_score).label("avg_risk"),
            func.count(UnifiedIdentity.id).label("count"),
        )
        .group_by(UnifiedIdentity.department)
        .order_by(desc("avg_risk"))
        .all()
    )
    return [
        {"department": r.department, "avg_risk": round(float(r.avg_risk), 1), "count": r.count}
        for r in results
    ]


@router.get("/platform-distribution")
def get_platform_distribution(db: Session = Depends(get_db), _=Depends(get_current_user)):
    platform_counts: dict[str, int] = {}
    for identity in db.query(UnifiedIdentity.platforms).all():
        for p in identity.platforms or []:
            platform_counts[p] = platform_counts.get(p, 0) + 1
    return [{"platform": k, "count": v} for k, v in sorted(platform_counts.items(), key=lambda x: -x[1])]


@router.get("/dormancy-distribution")
def get_dormancy_distribution(db: Session = Depends(get_db), _=Depends(get_current_user)):
    buckets = {"0-30 days": 0, "31-90 days": 0, "91-180 days": 0, "180+ days": 0}
    now = datetime.utcnow()
    for identity in db.query(UnifiedIdentity).all():
        if not identity.last_login:
            buckets["180+ days"] += 1
            continue
        days = (now - identity.last_login).days
        if days <= 30:
            buckets["0-30 days"] += 1
        elif days <= 90:
            buckets["31-90 days"] += 1
        elif days <= 180:
            buckets["91-180 days"] += 1
        else:
            buckets["180+ days"] += 1
    return [{"range": k, "count": v} for k, v in buckets.items()]


@router.get("/access-matrix")
def get_access_matrix(db: Session = Depends(get_db), _=Depends(get_current_user)):
    matrix: dict[str, dict[str, int]] = {}
    for identity in db.query(UnifiedIdentity).all():
        dept = identity.department
        if dept not in matrix:
            matrix[dept] = {}
        for platform in identity.platforms or []:
            matrix[dept][platform] = matrix[dept].get(platform, 0) + 1

    departments = list(matrix.keys())
    platforms = sorted({p for d in matrix.values() for p in d})
    rows = []
    for dept in departments:
        row = {"department": dept}
        for p in platforms:
            row[p] = matrix[dept].get(p, 0)
        rows.append(row)
    return {"departments": departments, "platforms": platforms, "data": rows}


@router.get("/privilege-heatmap")
def get_privilege_heatmap(db: Session = Depends(get_db), _=Depends(get_current_user)):
    heatmap: dict[str, dict[str, int]] = {}
    for identity in db.query(UnifiedIdentity).all():
        for ep in identity.effective_privileges or []:
            platform = ep.get("platform", "Unknown")
            priv = ep.get("privilege", "Unknown")
            if platform not in heatmap:
                heatmap[platform] = {}
            heatmap[platform][priv] = heatmap[platform].get(priv, 0) + 1

    data = []
    for platform, privs in heatmap.items():
        for priv, count in privs.items():
            data.append({"platform": platform, "privilege": priv, "count": count})
    return data
