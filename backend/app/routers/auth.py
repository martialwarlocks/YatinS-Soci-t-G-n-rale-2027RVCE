from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import Token, UserLogin, authenticate_user, create_access_token, get_current_user
from app.database import get_db
from app.models import AppUser

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.username, "role": user.role})
    return Token(
        access_token=token,
        token_type="bearer",
        role=user.role,
        full_name=user.full_name,
    )


@router.get("/me")
def get_me(user: AppUser = Depends(get_current_user)):
    return {
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name,
    }
