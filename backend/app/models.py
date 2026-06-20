from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UnifiedIdentity(Base):
    __tablename__ = "unified_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    unified_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    employee_id: Mapped[str] = mapped_column(String(32), index=True)
    full_name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(256), index=True)
    department: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(128))
    manager: Mapped[str] = mapped_column(String(128))
    employment_status: Mapped[str] = mapped_column(String(32))
    platform_accounts: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    effective_privileges: Mapped[list] = mapped_column(JSON, default=list)
    direct_privileges: Mapped[list] = mapped_column(JSON, default=list)
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(default=False)
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    remediation_actions: Mapped[list] = mapped_column(JSON, default=list)
    compliance_mappings: Mapped[list] = mapped_column(JSON, default=list)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IdentitySnapshot(Base):
    __tablename__ = "identity_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    employee_id: Mapped[str] = mapped_column(String(32), index=True)
    username: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(256))
    department: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(128))
    manager: Mapped[str] = mapped_column(String(128))
    employment_status: Mapped[str] = mapped_column(String(32))
    platform: Mapped[str] = mapped_column(String(64), index=True)
    account_status: Mapped[str] = mapped_column(String(32))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    privilege_level: Mapped[str] = mapped_column(String(64))


class GroupMembership(Base):
    __tablename__ = "group_memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user: Mapped[str] = mapped_column(String(128), index=True)
    group: Mapped[str] = mapped_column(String(128), index=True)
    parent_group: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    privilege_level: Mapped[str] = mapped_column(String(64))
    platform: Mapped[str] = mapped_column(String(64))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    user: Mapped[str] = mapped_column(String(128), index=True)
    platform: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="info")
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    geo_location: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


class OffboardingRecord(Base):
    __tablename__ = "offboarding_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    employee_id: Mapped[str] = mapped_column(String(32), index=True)
    termination_date: Mapped[datetime] = mapped_column(DateTime)
    hr_status: Mapped[str] = mapped_column(String(32))
    expected_disable_date: Mapped[datetime] = mapped_column(DateTime)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[str] = mapped_column(String(128), index=True)
    platform: Mapped[str] = mapped_column(String(64))
    creation_date: Mapped[datetime] = mapped_column(DateTime)
    last_rotation: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    token_name: Mapped[str] = mapped_column(String(128), default="")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(32), unique=True)
    unified_id: Mapped[str] = mapped_column(String(64), index=True)
    user_name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="open")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    compliance_controls: Mapped[list] = mapped_column(JSON, default=list)


class AppUser(Base):
    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(256))
    hashed_password: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    full_name: Mapped[str] = mapped_column(String(128))


class SystemMeta(Base):
    __tablename__ = "system_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))
