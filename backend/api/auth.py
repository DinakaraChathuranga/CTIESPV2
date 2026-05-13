# api/auth.py
"""
JWT authentication and role-based access control.

Two roles:
  security_reader — can view all data, approve/reject/restore alerts
  security_admin  — all reader permissions + edit asset registry, manage clients,
                    upload/delete sample reports, manage users
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from core.config import settings
from core.database import get_db
from models import db_models as M
from models import schemas as S

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ALGORITHM = "HS256"


# ─── Password helpers ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─── Token helpers ────────────────────────────────────────────────────────────

def create_access_token(username: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── FastAPI dependencies ─────────────────────────────────────────────────────

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> M.User:
    payload = decode_token(token)
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token payload")

    result = await db.execute(select(M.User).where(M.User.username == username))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    return user


async def require_reader(user: M.User = Depends(get_current_user)) -> M.User:
    """Any authenticated user (reader or admin)."""
    return user


async def require_admin(user: M.User = Depends(get_current_user)) -> M.User:
    """Only security_admin role."""
    if user.role != "security_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for this action",
        )
    return user


# ─── Auth router ──────────────────────────────────────────────────────────────

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.get("/setup-status")
async def setup_status(db: AsyncSession = Depends(get_db)):
    """Check if the platform has been set up (any admin user exists)."""
    count = await db.scalar(
        select(func.count(M.User.id)).where(M.User.role == "security_admin")
    )
    return {"needs_setup": count == 0}


@auth_router.post("/setup", response_model=S.TokenOut, status_code=201)
async def setup_first_admin(body: S.SetupRequest, db: AsyncSession = Depends(get_db)):
    """
    Create the first admin account. Only works when NO admin users exist yet.
    After setup this endpoint returns 403.
    """
    admin_count = await db.scalar(
        select(func.count(M.User.id)).where(M.User.role == "security_admin")
    )
    if admin_count > 0:
        raise HTTPException(403, "Platform already set up. Use /login.")

    existing = await db.execute(select(M.User).where(M.User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Username already taken")

    user = M.User(
        username=body.username,
        hashed_password=hash_password(body.password),
        role="security_admin",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(user.username, user.role)
    logger.info(f"[Auth] First admin created: {user.username}")
    return S.TokenOut(access_token=token, user=S.UserOut.model_validate(user))


@auth_router.post("/login", response_model=S.TokenOut)
async def login(body: S.LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(M.User).where(M.User.username == body.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is disabled")

    token = create_access_token(user.username, user.role)
    logger.info(f"[Auth] Login: {user.username} ({user.role})")
    return S.TokenOut(access_token=token, user=S.UserOut.model_validate(user))


@auth_router.get("/me", response_model=S.UserOut)
async def me(current_user: M.User = Depends(require_reader)):
    return current_user
@auth_router.post("/change-password")
async def change_password(
    body: S.PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(M.User).where(M.User.username == body.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid username or current password",
        )

    if not user.is_active:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Account is disabled. Contact an administrator.",
        )

    if verify_password(body.new_password, user.hashed_password):
        raise HTTPException(400, "New password cannot be the same as the current password")

    user.hashed_password = hash_password(body.new_password)
    await db.commit()

    logger.info("[Auth] Password changed for user: %s", user.username)
    return {
        "ok": True,
        "message": "Password updated successfully. Please log in with your new password.",
    }

@auth_router.get("/users", response_model=list[S.UserOut])
async def list_users(
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(M.User).order_by(M.User.created_at))
    return result.scalars().all()


@auth_router.post("/users", response_model=S.UserOut, status_code=201)
async def create_user(
    body: S.UserCreate,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(M.User).where(M.User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Username already taken")

    user = M.User(
        username=body.username,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info(f"[Auth] User created: {user.username} ({user.role})")
    return user

@auth_router.post("/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    body: S.AdminPasswordResetRequest,
    current_user: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(M.User, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    user.hashed_password = hash_password(body.new_password)
    await db.commit()

    logger.info(
        "[Auth] Admin %s reset password for %s",
        current_user.username,
        user.username,
    )

    return {
        "ok": True,
        "message": f"Password reset for {user.username}",
    }

@auth_router.patch("/users/{user_id}/role", response_model=S.UserOut)
async def change_user_role(
    user_id: str,
    role: str,
    current_user: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if role not in ("security_reader", "security_admin"):
        raise HTTPException(400, "Role must be security_reader or security_admin")

    user = await db.get(M.User, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    if user.id == current_user.id:
        raise HTTPException(400, "Cannot change your own role")

    user.role = role
    await db.commit()
    await db.refresh(user)
    return user


@auth_router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    current_user: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(M.User, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    if user.id == current_user.id:
        raise HTTPException(400, "Cannot delete your own account")

    await db.delete(user)
    await db.commit()
