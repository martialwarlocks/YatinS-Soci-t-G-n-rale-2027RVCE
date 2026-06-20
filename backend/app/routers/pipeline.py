from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import IdentitySnapshot, OffboardingRecord, UnifiedIdentity
from app.services.data_quality import assess_data_quality
from app.services.pipeline import get_pipeline_status, run_intelligence_pipeline

router = APIRouter(prefix="/pipeline", tags=["Intelligence Pipeline"])


@router.get("/status")
def pipeline_status(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return get_pipeline_status(db)


@router.post("/run")
def run_pipeline(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return run_intelligence_pipeline(db)


@router.get("/data-quality")
def data_quality_report(db: Session = Depends(get_db), _=Depends(get_current_user)):
    identities = [
        {
            "unified_id": i.unified_id,
            "full_name": i.full_name,
            "employee_id": i.employee_id,
            "email": i.email,
            "employment_status": i.employment_status,
            "platform_accounts": i.platform_accounts,
        }
        for i in db.query(UnifiedIdentity).all()
    ]
    snapshots = [
        {
            "employee_id": s.employee_id,
            "email": s.email,
            "platform": s.platform,
            "privilege_level": s.privilege_level,
            "account_status": s.account_status,
        }
        for s in db.query(IdentitySnapshot).all()
    ]
    offboarding = [
        {
            "employee_id": o.employee_id,
            "termination_date": o.termination_date,
            "hr_status": o.hr_status,
            "expected_disable_date": o.expected_disable_date,
        }
        for o in db.query(OffboardingRecord).all()
    ]
    return assess_data_quality(identities, snapshots, offboarding)
