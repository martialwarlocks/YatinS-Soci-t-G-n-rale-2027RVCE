from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AppUser

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    full_name: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def authenticate_user(db: Session, username: str, password: str) -> Optional[AppUser]:
    user = db.query(AppUser).filter(AppUser.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> AppUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(AppUser).filter(AppUser.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def require_role(*roles: str):
    async def role_checker(user: AppUser = Depends(get_current_user)) -> AppUser:
        if user.role not in roles and "admin" not in (user.role,):
            if user.role not in roles:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_checker
