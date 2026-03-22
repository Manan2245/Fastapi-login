import hashlib
import os
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import DateTime, Integer, String, create_engine, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "app.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
ENV_PATH = BASE_DIR / ".env"
OTP_EXPIRE_MINUTES = 5
OTP_MAX_ATTEMPTS = 5
ACCESS_TOKEN_EXPIRE_SECONDS = 30
DEVICE_COOKIE_NAME = "trusted_device_id"

app = FastAPI(title="Email OTP Auth App")
security = HTTPBearer()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OTPCode(Base):
    __tablename__ = "otp_codes"

    email: Mapped[str] = mapped_column(String(255), primary_key=True)
    otp: Mapped[str] = mapped_column(String(6), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    token_jti: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_revoked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int = ACCESS_TOKEN_EXPIRE_SECONDS
    otp_required: bool


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_env_file() -> None:
    if not ENV_PATH.exists():
        return

    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return f"{salt}${hashed.hex()}"


def generate_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def get_jwt_secret() -> str:
    jwt_secret = os.getenv("JWT_SECRET")
    if not jwt_secret:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET is missing. Add JWT_SECRET in .env.",
        )
    return jwt_secret


def create_access_token(user: User, device_id: str) -> tuple[str, str, datetime]:
    expires_at = utc_now() + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    token_jti = str(uuid.uuid4())
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "device_id": device_id,
        "jti": token_jti,
        "exp": expires_at,
    }
    token = jwt.encode(payload, get_jwt_secret(), algorithm="HS256")
    return token, token_jti, expires_at


def get_or_create_device_id(request: Request) -> tuple[str, bool]:
    device_id = request.cookies.get(DEVICE_COOKIE_NAME)
    if device_id:
        return device_id, False
    return str(uuid.uuid4()), True


def set_device_cookie(response: Response, device_id: str) -> None:
    response.set_cookie(
        key=DEVICE_COOKIE_NAME,
        value=device_id,
        httponly=True,
        samesite="lax",
        max_age=30,
    )


def persist_user_session(
    db: Session, user: User, device_id: str, token_jti: str, expires_at: datetime
) -> None:
    existing_session = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.device_id == device_id,
        )
        .first()
    )
    if existing_session:
        existing_session.token_jti = token_jti
        existing_session.email = user.email
        existing_session.expires_at = expires_at
        existing_session.is_revoked = 0
        return

    db.add(
        UserSession(
            user_id=user.id,
            email=user.email,
            device_id=device_id,
            token_jti=token_jti,
            expires_at=expires_at,
            is_revoked=0,
            created_at=utc_now(),
        )
    )


def get_active_trusted_session(db: Session, email: str, device_id: str) -> UserSession | None:
    session = (
        db.query(UserSession)
        .filter(
            UserSession.email == email,
            UserSession.device_id == device_id,
            UserSession.is_revoked == 0,
        )
        .first()
    )
    if not session:
        return None
    if utc_now() > ensure_utc(session.expires_at):
        session.is_revoked = 1
        db.commit()
        return None
    return session


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(
            credentials.credentials,
            get_jwt_secret(),
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    token_jti = payload.get("jti")
    user_id = payload.get("sub")
    device_id = payload.get("device_id")

    if not token_jti or not user_id or not device_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    session = (
        db.query(UserSession)
        .filter(
            UserSession.token_jti == token_jti,
            UserSession.user_id == int(user_id),
            UserSession.device_id == device_id,
            UserSession.is_revoked == 0,
        )
        .first()
    )
    if not session or utc_now() > ensure_utc(session.expires_at):
        raise HTTPException(status_code=401, detail="Session is no longer valid")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found for token")

    return user


def send_otp_email(receiver_email: str, otp: str) -> None:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER", smtp_user or "")

    if not all([smtp_host, smtp_user, smtp_password, smtp_sender]):
        raise HTTPException(
            status_code=500,
            detail=(
                "SMTP settings are missing. Add SMTP_HOST, SMTP_PORT, "
                "SMTP_USER, SMTP_PASSWORD and optionally SMTP_SENDER in .env."
            ),
        )

    message = EmailMessage()
    message["Subject"] = "Your login OTP"
    message["From"] = smtp_sender
    message["To"] = receiver_email
    message.set_content(
        f"Your OTP is {otp}. It will expire in {OTP_EXPIRE_MINUTES} minutes."
    )

    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_password)
            server.send_message(message)
        return

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(message)


@app.on_event("startup")
def startup() -> None:
    load_env_file()
    init_db()


@app.get("/")
async def welcome():
    return {
        "message": "Registration and email OTP login API is running",
        "docs": "/docs",
    }


@app.post("/register")
async def register_user(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = (
        db.query(User)
        .filter(or_(User.email == payload.email, User.username == payload.username))
        .first()
    )
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User with this email or username already exists",
        )

    user = User(
        name=payload.name,
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        created_at=utc_now(),
    )
    db.add(user)
    db.commit()

    return {
        "message": "User registered successfully",
        "email": payload.email,
        "username": payload.username,
    }


@app.post("/login")
async def login_with_email(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    device_id, cookie_created = get_or_create_device_id(request)
    trusted_session = get_active_trusted_session(db, payload.email, device_id)
    if trusted_session:
        token, token_jti, expires_at = create_access_token(user, device_id)
        persist_user_session(db, user, device_id, token_jti, expires_at)
        db.commit()
        if cookie_created:
            set_device_cookie(response, device_id)
        return TokenResponse(
            access_token=token,
            otp_required=False,
        )

    otp = generate_otp()
    expires_at = utc_now() + timedelta(minutes=OTP_EXPIRE_MINUTES)

    otp_row = db.query(OTPCode).filter(OTPCode.email == payload.email).first()
    if otp_row:
        otp_row.otp = otp
        otp_row.expires_at = expires_at
        otp_row.attempts = 0
    else:
        otp_row = OTPCode(
            email=payload.email,
            otp=otp,
            expires_at=expires_at,
            attempts=0,
        )
        db.add(otp_row)

    db.commit()
    send_otp_email(payload.email, otp)
    if cookie_created:
        set_device_cookie(response, device_id)

    return {
        "message": "OTP sent successfully",
        "email": payload.email,
        "expires_in_minutes": OTP_EXPIRE_MINUTES,
        "otp_required": True,
    }


@app.post("/verify-otp")
async def verify_otp(
    payload: OTPVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    otp_row = db.query(OTPCode).filter(OTPCode.email == payload.email).first()
    if not otp_row:
        raise HTTPException(status_code=404, detail="OTP not found for this email")

    if utc_now() > ensure_utc(otp_row.expires_at):
        db.delete(otp_row)
        db.commit()
        raise HTTPException(status_code=400, detail="OTP has expired")

    otp_row.attempts += 1
    if otp_row.attempts > OTP_MAX_ATTEMPTS:
        db.delete(otp_row)
        db.commit()
        raise HTTPException(status_code=400, detail="Too many invalid attempts")

    if payload.otp != otp_row.otp:
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user = db.query(User).filter(User.email == payload.email).first()
    device_id, _ = get_or_create_device_id(request)
    token, token_jti, expires_at = create_access_token(user, device_id)
    persist_user_session(db, user, device_id, token_jti, expires_at)
    db.delete(otp_row)
    db.commit()
    set_device_cookie(response, device_id)

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "expires_in_seconds": ACCESS_TOKEN_EXPIRE_SECONDS,
        "otp_required": False,
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
        },
    }


@app.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "username": current_user.username,
        "email": current_user.email,
    }
