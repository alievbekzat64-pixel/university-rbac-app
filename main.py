# -*- coding: utf-8 -*-
"""
University RBAC Web Application
Практическая реализация темы:
"Использование технологии разделения прав доступа для обеспечения безопасности веб-приложений"

Запуск:
python -m uvicorn main:app --reload
"""

import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable

from fastapi import Depends, FastAPI, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from jose import JWTError, jwt
from passlib.context import CryptContext

from pydantic import BaseModel, Field, validator

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker


# ==============================================================================
# 1. ОСНОВНЫЕ НАСТРОЙКИ ПРИЛОЖЕНИЯ
# ==============================================================================

APP_NAME = "University Secure RBAC"
APP_VERSION = "4.0"

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_SECRET_KEY_FOR_PRODUCTION_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./university_rbac.db")
# Render/PostgreSQL sometimes gives an URL that starts with postgres://.
# SQLAlchemy expects postgresql://, so we normalize it here.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

STATIC_DIR = os.getenv("STATIC_DIR", "./static")
EXPORT_DIR = os.getenv("EXPORT_DIR", "./app_data/university_exports")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)

allowed_origins_raw = os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000")
ALLOWED_ORIGINS = [origin.strip() for origin in allowed_origins_raw.split(",") if origin.strip()]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


# ==============================================================================
# 2. БАЗА ДАННЫХ И ORM-МОДЕЛИ
# ==============================================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False, default="Пользователь")
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    is_active = Column(Integer, default=1, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    role = relationship("Role")


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(Text, unique=True, nullable=False)
    username = Column(String, nullable=False)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class StudentRecord(Base):
    __tablename__ = "student_records"

    id = Column(Integer, primary_key=True, index=True)
    student_code = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    group_name = Column(String, nullable=False)
    faculty = Column(String, nullable=False)
    status = Column(String, default="Активен", nullable=False)


class GradeRecord(Base):
    __tablename__ = "grade_records"

    id = Column(Integer, primary_key=True, index=True)
    student_name = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    grade = Column(String, nullable=False)
    teacher = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AcademicRequest(Base):
    __tablename__ = "academic_requests"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    sender = Column(String, nullable=False)
    status = Column(String, default="Принято", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class PaymentRecord(Base):
    __tablename__ = "payment_records"

    id = Column(Integer, primary_key=True, index=True)
    student_name = Column(String, nullable=False)
    purpose = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String, default="Оплачено", nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)


class SiemLog(Base):
    __tablename__ = "siem_logs"

    id = Column(Integer, primary_key=True, index=True)
    event = Column(String, nullable=False)
    username = Column(String, nullable=False)
    role = Column(String, nullable=False, default="-")
    details = Column(Text, nullable=False)
    ip_address = Column(String, nullable=False, default="-")
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)


Base.metadata.create_all(bind=engine)


# ==============================================================================
# 3. МАТРИЦА ДОСТУПА RBAC
# ==============================================================================

ACCESS_MATRIX: Dict[str, Dict[str, object]] = {
    "profile": {
        "title": "Профиль текущего пользователя",
        "roles": ["Admin", "IB", "DeanOffice", "Teacher", "Student", "Accountant"],
        "actions": ["read"],
    },
    "user_management": {
        "title": "Управление учетными записями",
        "roles": ["Admin"],
        "actions": ["create", "read", "block", "activate"],
    },
    "student_records_read": {
        "title": "Просмотр карточек студентов",
        "roles": ["Admin", "DeanOffice", "Teacher", "Student", "Accountant"],
        "actions": ["read"],
    },
    "student_records_write": {
        "title": "Создание и обновление карточек студентов",
        "roles": ["Admin", "DeanOffice"],
        "actions": ["create", "update"],
    },
    "grade_records_read": {
        "title": "Просмотр оценок и ведомостей",
        "roles": ["Admin", "DeanOffice", "Teacher", "Student"],
        "actions": ["read"],
    },
    "grade_records_write": {
        "title": "Выставление оценок",
        "roles": ["Admin", "Teacher"],
        "actions": ["create"],
    },
    "academic_requests_read": {
        "title": "Просмотр академических заявок",
        "roles": ["Admin", "DeanOffice", "Teacher", "Student"],
        "actions": ["read"],
    },
    "academic_requests_write": {
        "title": "Создание академической заявки",
        "roles": ["Admin", "DeanOffice", "Student"],
        "actions": ["create"],
    },
    "finance_report": {
        "title": "Финансовые сведения по оплатам",
        "roles": ["Admin", "Accountant"],
        "actions": ["read", "download"],
    },
    "security_logs": {
        "title": "Журнал событий безопасности",
        "roles": ["Admin", "IB"],
        "actions": ["read", "download"],
    },
    "security_report": {
        "title": "Отчет по безопасности",
        "roles": ["Admin", "IB"],
        "actions": ["read", "download"],
    },
    "rbac_matrix": {
        "title": "Матрица доступа RBAC",
        "roles": ["Admin", "IB"],
        "actions": ["read"],
    },
    "access_testing": {
        "title": "Проверка доступа",
        "roles": ["Admin", "IB", "DeanOffice", "Teacher", "Student", "Accountant"],
        "actions": ["read"],
    },
}


# ==============================================================================
# 4. PYDANTIC-СХЕМЫ
# ==============================================================================

class UserCreate(BaseModel):
    full_name: str = Field(..., min_length=2)
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)
    role_id: int

    @validator("password")
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Пароль должен быть не короче 8 символов")
        if value.lower() in {"password", "password123", "admin123"}:
            raise ValueError("Пароль слишком простой")
        return value


class UserStatusUpdate(BaseModel):
    is_active: int = Field(..., ge=0, le=1)


class StudentRecordCreate(BaseModel):
    student_code: str = Field(..., min_length=2)
    full_name: str = Field(..., min_length=2)
    group_name: str = Field(..., min_length=2)
    faculty: str = Field(..., min_length=2)
    status: str = "Активен"


class GradeCreate(BaseModel):
    student_name: str = Field(..., min_length=2)
    subject: str = Field(..., min_length=2)
    grade: str = Field(..., min_length=1)


class AcademicRequestCreate(BaseModel):
    title: str = Field(..., min_length=2)
    content: str = Field(..., min_length=3)


# ==============================================================================
# 5. FASTAPI И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def now_local_text(dt: Optional[datetime] = None) -> str:
    source = dt or datetime.utcnow()
    return source.strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def log_to_siem(
    db: Session,
    event: str,
    username: str,
    role: str,
    details: str,
    ip_address: str = "-",
) -> None:
    db.add(
        SiemLog(
            event=event,
            username=username,
            role=role,
            details=details,
            ip_address=ip_address,
        )
    )
    db.commit()


def create_access_token(username: str, expires_delta: timedelta) -> str:
    expire = datetime.utcnow() + expires_delta
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def is_token_revoked(db: Session, token: str) -> bool:
    return db.query(RevokedToken).filter(RevokedToken.token == token).first() is not None


def get_client_ip(request_ip: str = "-") -> str:
    return request_ip or "-"


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Отсутствует токен авторизации")

    token = credentials.credentials

    if is_token_revoked(db, token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен отозван после выхода из системы")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Некорректная структура токена")
    except JWTError:
        log_to_siem(db, "JWT_TAMPERING_ALERT", "UNKNOWN", "-", "Некорректная JWT-подпись или поврежденный токен")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверная криптографическая подпись JWT")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Пользователь не найден")

    if user.is_active == 0:
        log_to_siem(db, "BLOCKED_ACCOUNT_ACCESS", user.username, user.role.name, "Попытка доступа с заблокированной учетной записи")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Учетная запись заблокирована")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Учетная запись временно заблокирована до {now_local_text(user.locked_until)}",
        )

    return user


def require_roles(*allowed_roles: str) -> Callable:
    def dependency(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        role_name = user.role.name

        if role_name not in allowed_roles:
            log_to_siem(
                db,
                "FORBIDDEN_ACCESS",
                user.username,
                role_name,
                f"Попытка доступа к защищенному ресурсу. Разрешенные роли: {', '.join(allowed_roles)}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Доступ запрещен: роль пользователя не входит в разрешенную матрицу RBAC",
            )

        return user

    return dependency


def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "full_name": user.full_name,
        "username": user.username,
        "role": user.role.name,
        "is_active": user.is_active,
        "failed_login_attempts": user.failed_login_attempts,
        "locked_until": now_local_text(user.locked_until) if user.locked_until else None,
    }


def student_to_dict(s: StudentRecord) -> dict:
    return {
        "id": s.id,
        "student_code": s.student_code,
        "full_name": s.full_name,
        "group_name": s.group_name,
        "faculty": s.faculty,
        "status": s.status,
    }


def grade_to_dict(g: GradeRecord) -> dict:
    return {
        "id": g.id,
        "student_name": g.student_name,
        "subject": g.subject,
        "grade": g.grade,
        "teacher": g.teacher,
        "created_at": now_local_text(g.created_at),
    }


def request_to_dict(r: AcademicRequest) -> dict:
    return {
        "id": r.id,
        "title": r.title,
        "content": r.content,
        "sender": r.sender,
        "status": r.status,
        "created_at": now_local_text(r.created_at),
    }


def payment_to_dict(p: PaymentRecord) -> dict:
    return {
        "id": p.id,
        "student_name": p.student_name,
        "purpose": p.purpose,
        "amount": p.amount,
        "status": p.status,
        "timestamp": now_local_text(p.timestamp),
    }


def log_to_dict(l: SiemLog) -> dict:
    return {
        "id": l.id,
        "event": l.event,
        "username": l.username,
        "role": l.role,
        "details": l.details,
        "ip_address": l.ip_address,
        "timestamp": now_local_text(l.timestamp),
    }


# ==============================================================================
# 6. СТАРТОВАЯ ИНИЦИАЛИЗАЦИЯ
# ==============================================================================

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        roles = ["Admin", "IB", "DeanOffice", "Teacher", "Student", "Accountant"]
        for idx, role_name in enumerate(roles, start=1):
            if not db.query(Role).filter(Role.id == idx).first():
                db.add(Role(id=idx, name=role_name))
        db.commit()

        # Системный администратор нужен только для первого входа и создания пользователей.
        # Дополнительные готовые тестовые пользователи НЕ создаются.
        if not db.query(User).filter(User.username == "admin").first():
            admin_role = db.query(Role).filter(Role.name == "Admin").first()
            db.add(
                User(
                    full_name="Системный администратор",
                    username="admin",
                    hashed_password=hash_password("admin12345"),
                    role_id=admin_role.id,
                    is_active=1,
                )
            )
            db.commit()

        # Демо-данные университета не являются учетными записями.
        # Они нужны только для заполнения таблиц на защите.
        if not db.query(StudentRecord).first():
            students = [
                StudentRecord(student_code="KSTU-2026-001", full_name="Субанов Батырбек", group_name="БИС-1-22", faculty="Информационная безопасность"),
                StudentRecord(student_code="KSTU-2026-002", full_name="Асанова Айдана", group_name="ПИ-2-22", faculty="Программная инженерия"),
                StudentRecord(student_code="KSTU-2026-003", full_name="Маматов Нурбек", group_name="ИС-3-22", faculty="Информационные системы"),
            ]
            db.add_all(students)

        if not db.query(GradeRecord).first():
            db.add_all(
                [
                    GradeRecord(student_name="Субанов Батырбек", subject="Безопасность веб-приложений", grade="отлично", teacher="teacher_demo"),
                    GradeRecord(student_name="Асанова Айдана", subject="Базы данных", grade="хорошо", teacher="teacher_demo"),
                ]
            )

        if not db.query(AcademicRequest).first():
            db.add(
                AcademicRequest(
                    title="Справка с места учебы",
                    content="Запрос на получение справки для предоставления по месту требования.",
                    sender="student_demo",
                    status="Принято",
                )
            )

        if not db.query(PaymentRecord).first():
            db.add_all(
                [
                    PaymentRecord(student_name="Субанов Батырбек", purpose="Оплата контракта за семестр", amount=35000.0),
                    PaymentRecord(student_name="Асанова Айдана", purpose="Оплата общежития", amount=8000.0),
                ]
            )

        db.commit()
    finally:
        db.close()


# ==============================================================================
# 7. АУТЕНТИФИКАЦИЯ И ПРОФИЛЬ
# ==============================================================================

@app.get("/health")
def health():
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()

    if not user:
        log_to_siem(db, "LOGIN_FAILED", username, "-", "Попытка входа под несуществующим логином")
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=403,
            detail=f"Учетная запись временно заблокирована до {now_local_text(user.locked_until)}",
        )

    if user.is_active == 0:
        log_to_siem(db, "BLOCKED_ACCOUNT_LOGIN", user.username, user.role.name, "Попытка входа в заблокированную учетную запись")
        raise HTTPException(status_code=403, detail="Учетная запись заблокирована")

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=10)
            log_to_siem(
                db,
                "ACCOUNT_TEMP_LOCKED",
                user.username,
                user.role.name,
                "Учетная запись временно заблокирована после 5 неудачных попыток входа",
            )
        else:
            log_to_siem(
                db,
                "LOGIN_FAILED",
                user.username,
                user.role.name,
                f"Неудачная попытка входа. Количество ошибок: {user.failed_login_attempts}",
            )

        db.commit()
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")

    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    token = create_access_token(user.username, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    log_to_siem(db, "USER_LOGIN", user.username, user.role.name, "Успешный вход в систему")

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role.name,
    }


@app.post("/logout")
def logout(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    if credentials and credentials.credentials:
        token = credentials.credentials
        username = "unknown"

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub") or "unknown"
        except JWTError:
            pass

        if not is_token_revoked(db, token):
            db.add(RevokedToken(token=token, username=username))
            db.commit()

        log_to_siem(db, "USER_LOGOUT", username, "-", "Пользователь завершил сессию")

    return {"detail": "Сессия завершена"}


@app.get("/me")
def get_me(user: User = Depends(require_roles(*ACCESS_MATRIX["profile"]["roles"]))):
    role_name = user.role.name
    available_modules = []
    unavailable_modules = []

    for key, value in ACCESS_MATRIX.items():
        item = {
            "key": key,
            "title": value["title"],
            "actions": value["actions"],
        }
        if role_name in value["roles"]:
            available_modules.append(item)
        else:
            unavailable_modules.append(item)

    return {
        "user": user_to_dict(user),
        "available_modules": available_modules,
        "unavailable_modules": unavailable_modules,
    }


# ==============================================================================
# 8. УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ==============================================================================

@app.post("/register")
def register_user(
    user_data: UserCreate,
    auth: User = Depends(require_roles(*ACCESS_MATRIX["user_management"]["roles"])),
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")

    role = db.query(Role).filter(Role.id == user_data.role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Указанная роль не найдена")

    new_user = User(
        full_name=user_data.full_name,
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        role_id=role.id,
        is_active=1,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_to_siem(
        db,
        "IAM_USER_CREATED",
        auth.username,
        auth.role.name,
        f"Создан пользователь {new_user.username} с ролью {role.name}",
    )

    return {"detail": "Пользователь создан", "user": user_to_dict(new_user)}


@app.get("/users")
def list_users(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["user_management"]["roles"])),
    db: Session = Depends(get_db),
):
    return [user_to_dict(user) for user in db.query(User).order_by(User.id.asc()).all()]


@app.post("/users/{username}/status")
def change_user_status(
    username: str,
    status_data: UserStatusUpdate,
    auth: User = Depends(require_roles(*ACCESS_MATRIX["user_management"]["roles"])),
    db: Session = Depends(get_db),
):
    if username == "admin":
        raise HTTPException(status_code=400, detail="Запрещено блокировать системную учетную запись admin")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    user.is_active = status_data.is_active
    if status_data.is_active == 1:
        user.failed_login_attempts = 0
        user.locked_until = None

    db.commit()

    status_text = "активирован" if status_data.is_active == 1 else "заблокирован"
    log_to_siem(
        db,
        "IAM_USER_STATUS_CHANGED",
        auth.username,
        auth.role.name,
        f"Пользователь {username} {status_text}",
    )

    return {"detail": f"Пользователь {username} {status_text}"}


# ==============================================================================
# 9. УНИВЕРСИТЕТСКИЕ МОДУЛИ
# ==============================================================================

@app.get("/students")
def list_students(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["student_records_read"]["roles"])),
    db: Session = Depends(get_db),
):
    return [student_to_dict(s) for s in db.query(StudentRecord).order_by(StudentRecord.id.desc()).all()]


@app.post("/students")
def create_student(
    data: StudentRecordCreate,
    auth: User = Depends(require_roles(*ACCESS_MATRIX["student_records_write"]["roles"])),
    db: Session = Depends(get_db),
):
    existing = db.query(StudentRecord).filter(StudentRecord.student_code == data.student_code).first()
    if existing:
        raise HTTPException(status_code=400, detail="Студент с таким кодом уже существует")

    student = StudentRecord(
        student_code=data.student_code,
        full_name=data.full_name,
        group_name=data.group_name,
        faculty=data.faculty,
        status=data.status,
    )
    db.add(student)
    db.commit()
    db.refresh(student)

    log_to_siem(db, "STUDENT_RECORD_CREATED", auth.username, auth.role.name, f"Создана карточка студента {student.full_name}")
    return {"detail": "Карточка студента создана", "student": student_to_dict(student)}


@app.get("/grades")
def list_grades(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["grade_records_read"]["roles"])),
    db: Session = Depends(get_db),
):
    return [grade_to_dict(g) for g in db.query(GradeRecord).order_by(GradeRecord.id.desc()).all()]


@app.post("/grades")
def create_grade(
    data: GradeCreate,
    auth: User = Depends(require_roles(*ACCESS_MATRIX["grade_records_write"]["roles"])),
    db: Session = Depends(get_db),
):
    grade = GradeRecord(
        student_name=data.student_name,
        subject=data.subject,
        grade=data.grade,
        teacher=auth.username,
    )
    db.add(grade)
    db.commit()
    db.refresh(grade)

    log_to_siem(db, "GRADE_CREATED", auth.username, auth.role.name, f"Выставлена оценка студенту {grade.student_name}")
    return {"detail": "Оценка сохранена", "grade": grade_to_dict(grade)}


@app.get("/academic-requests")
def list_academic_requests(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["academic_requests_read"]["roles"])),
    db: Session = Depends(get_db),
):
    return [request_to_dict(r) for r in db.query(AcademicRequest).order_by(AcademicRequest.id.desc()).all()]


@app.post("/academic-requests")
def create_academic_request(
    data: AcademicRequestCreate,
    auth: User = Depends(require_roles(*ACCESS_MATRIX["academic_requests_write"]["roles"])),
    db: Session = Depends(get_db),
):
    request_item = AcademicRequest(
        title=data.title,
        content=data.content,
        sender=auth.username,
        status="Принято",
    )
    db.add(request_item)
    db.commit()
    db.refresh(request_item)

    log_to_siem(db, "ACADEMIC_REQUEST_CREATED", auth.username, auth.role.name, f"Создана заявка: {request_item.title}")
    return {"detail": "Заявка создана", "request": request_to_dict(request_item)}


@app.get("/finance-report")
def finance_report(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["finance_report"]["roles"])),
    db: Session = Depends(get_db),
):
    payments = db.query(PaymentRecord).order_by(PaymentRecord.id.desc()).all()
    total = sum(p.amount for p in payments)
    return {
        "total_amount": total,
        "payments_count": len(payments),
        "generated_by": auth.username,
        "payments": [payment_to_dict(p) for p in payments],
    }


# ==============================================================================
# 10. МАТРИЦА, ТЕСТИРОВАНИЕ И ОТЧЕТЫ БЕЗОПАСНОСТИ
# ==============================================================================

@app.get("/access-matrix")
def get_access_matrix(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["rbac_matrix"]["roles"])),
):
    return {"access_matrix": ACCESS_MATRIX}


@app.get("/security-logs")
def get_security_logs(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["security_logs"]["roles"])),
    db: Session = Depends(get_db),
):
    logs = db.query(SiemLog).order_by(SiemLog.id.desc()).limit(200).all()
    return [log_to_dict(log) for log in logs]


@app.get("/security-report")
def get_security_report(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["security_report"]["roles"])),
    db: Session = Depends(get_db),
):
    users = db.query(User).all()
    logs = db.query(SiemLog).all()

    forbidden_count = sum(1 for log in logs if log.event == "FORBIDDEN_ACCESS")
    failed_login_count = sum(1 for log in logs if log.event in {"LOGIN_FAILED", "ACCOUNT_TEMP_LOCKED"})
    login_count = sum(1 for log in logs if log.event == "USER_LOGIN")
    blocked_users = sum(1 for user in users if user.is_active == 0)
    temp_locked_users = sum(1 for user in users if user.locked_until and user.locked_until > datetime.utcnow())

    last_login = (
        db.query(SiemLog)
        .filter(SiemLog.event == "USER_LOGIN")
        .order_by(SiemLog.id.desc())
        .first()
    )

    return {
        "generated_at": now_local_text(),
        "generated_by": auth.username,
        "users_total": len(users),
        "active_users": sum(1 for user in users if user.is_active == 1),
        "blocked_users": blocked_users,
        "temporary_locked_users": temp_locked_users,
        "events_total": len(logs),
        "successful_logins": login_count,
        "failed_login_events": failed_login_count,
        "forbidden_access_events": forbidden_count,
        "last_login": log_to_dict(last_login) if last_login else None,
    }


@app.get("/security-report/download")
def download_security_report(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["security_report"]["roles"])),
    db: Session = Depends(get_db),
):
    report = get_security_report(auth=auth, db=db)

    content = []
    content.append("ОТЧЕТ ПО БЕЗОПАСНОСТИ УНИВЕРСИТЕТСКОЙ RBAC-СИСТЕМЫ")
    content.append("=" * 70)
    content.append(f"Дата формирования: {report['generated_at']}")
    content.append(f"Сформировал: {report['generated_by']}")
    content.append("-" * 70)
    content.append(f"Всего пользователей: {report['users_total']}")
    content.append(f"Активных пользователей: {report['active_users']}")
    content.append(f"Заблокированных пользователей: {report['blocked_users']}")
    content.append(f"Временно заблокированных после ошибок входа: {report['temporary_locked_users']}")
    content.append(f"Всего событий безопасности: {report['events_total']}")
    content.append(f"Успешных входов: {report['successful_logins']}")
    content.append(f"Событий неудачного входа: {report['failed_login_events']}")
    content.append(f"Запрещенных попыток доступа: {report['forbidden_access_events']}")
    content.append("-" * 70)
    content.append("Вывод: система фиксирует действия пользователей и блокирует доступ, если роль не входит в матрицу RBAC.")

    def iterator():
        yield ("\n".join(content)).encode("utf-8")

    return StreamingResponse(
        iterator(),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=UNIVERSITY_SECURITY_REPORT.txt"},
    )


@app.get("/rbac-report/download")
def download_rbac_report(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["rbac_matrix"]["roles"])),
):
    lines = []
    lines.append("ОТЧЕТ ПО МАТРИЦЕ РАЗДЕЛЕНИЯ ПРАВ ДОСТУПА RBAC")
    lines.append("=" * 70)
    lines.append(f"Дата формирования: {now_local_text()}")
    lines.append(f"Сформировал: {auth.username} ({auth.role.name})")
    lines.append("-" * 70)

    for key, item in ACCESS_MATRIX.items():
        lines.append(f"Модуль: {item['title']}")
        lines.append(f"Ключ: {key}")
        lines.append(f"Разрешенные роли: {', '.join(item['roles'])}")
        lines.append(f"Операции: {', '.join(item['actions'])}")
        lines.append("-" * 70)

    lines.append("Вывод: доступ к функциям системы ограничивается на уровне серверных endpoint-ов.")

    def iterator():
        yield ("\n".join(lines)).encode("utf-8")

    return StreamingResponse(
        iterator(),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=RBAC_ACCESS_MATRIX_REPORT.txt"},
    )


@app.get("/security-logs/download")
def download_security_logs(
    auth: User = Depends(require_roles(*ACCESS_MATRIX["security_logs"]["roles"])),
    db: Session = Depends(get_db),
):
    logs = db.query(SiemLog).order_by(SiemLog.id.asc()).all()

    lines = []
    lines.append("ЖУРНАЛ СОБЫТИЙ БЕЗОПАСНОСТИ")
    lines.append("=" * 70)
    lines.append(f"Дата выгрузки: {now_local_text()}")
    lines.append(f"Выгрузил: {auth.username} ({auth.role.name})")
    lines.append("-" * 70)

    for log in logs:
        lines.append(
            f"[{now_local_text(log.timestamp)}] {log.event} | user={log.username} | role={log.role} | {log.details}"
        )

    def iterator():
        yield ("\n".join(lines)).encode("utf-8")

    return StreamingResponse(
        iterator(),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=SIEM_SECURITY_LOGS.txt"},
    )
