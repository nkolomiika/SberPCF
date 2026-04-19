from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import models  # noqa: F401
from app.audit_store import audit_store
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.exceptions import ConflictError, ForbiddenError, NotFoundError, PCFError, UnauthorizedError, ValidationError
from app.routers import (
    assets,
    audit_logs,
    auth,
    comments,
    files,
    import_,
    notifications,
    projects,
    reports,
    users,
    vulnerabilities,
    websocket,
)
from app.services import UserService
from app.storage.minio_client import MinioStorage

settings = get_settings()

app = FastAPI(title="PCF API", version="1.0.0", openapi_url="/api/v1/openapi.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _register_routes() -> None:
    prefix = "/api/v1"
    app.include_router(auth.router, prefix=prefix)
    app.include_router(users.router, prefix=prefix)
    app.include_router(projects.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(vulnerabilities.router, prefix=prefix)
    app.include_router(files.router, prefix=prefix)
    app.include_router(comments.router, prefix=prefix)
    app.include_router(notifications.router, prefix=prefix)
    app.include_router(import_.router, prefix=prefix)
    app.include_router(reports.router, prefix=prefix)
    app.include_router(audit_logs.router, prefix=prefix)
    app.include_router(websocket.router)


def _register_error_handlers() -> None:
    def _format_request_validation(exc: RequestValidationError) -> str:
        messages: list[str] = []
        for item in exc.errors():
            raw_loc = [str(part) for part in item.get("loc", [])]
            loc = ".".join(part for part in raw_loc if part not in {"body", "query", "path"})
            error_type = item.get("type", "")
            if error_type == "missing":
                message = "Поле обязательно"
            elif error_type == "string_too_short":
                min_length = item.get("ctx", {}).get("min_length")
                message = "Поле не может быть пустым" if min_length == 1 else f"Минимальная длина: {min_length}"
            elif error_type == "string_too_long":
                max_length = item.get("ctx", {}).get("max_length")
                message = f"Максимальная длина: {max_length}"
            elif error_type == "greater_than_equal":
                value = item.get("ctx", {}).get("ge")
                message = f"Значение должно быть не меньше {value}"
            elif error_type == "less_than_equal":
                value = item.get("ctx", {}).get("le")
                message = f"Значение должно быть не больше {value}"
            else:
                message = item.get("msg", "Некорректные входные данные")
            messages.append(f"{loc}: {message}" if loc else message)
        return "; ".join(messages) or "Некорректные входные данные"

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": _format_request_validation(exc)})

    @app.exception_handler(NotFoundError)
    async def not_found_handler(_: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(UnauthorizedError)
    async def unauthorized_handler(_: Request, exc: UnauthorizedError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(ForbiddenError)
    async def forbidden_handler(_: Request, exc: ForbiddenError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ConflictError)
    async def conflict_handler(_: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ValidationError)
    async def validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(PCFError)
    async def app_error_handler(_: Request, exc: PCFError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.on_event("startup")
async def startup() -> None:
    """Инициализирует БД, MinIO и стартового администратора."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if conn.dialect.name == "postgresql":
            await conn.execute(text("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'developer'"))
            await conn.execute(text("ALTER TYPE project_status ADD VALUE IF NOT EXISTS 'handover_to_development'"))
            await conn.execute(text("ALTER TYPE project_status ADD VALUE IF NOT EXISTS 'vulnerability_recheck'"))
            await conn.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS folder VARCHAR(255) NOT NULL DEFAULT ''"))
            await conn.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS timeline_frozen_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE projects ALTER COLUMN folder SET DEFAULT ''"))
            await conn.execute(text("UPDATE projects SET folder = '' WHERE folder = 'Без папки'"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS tags JSON"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_minio_bucket VARCHAR(63)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_minio_key TEXT"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_content_type VARCHAR(127)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_uploaded_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS workflow_steps JSON"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS query_params JSON"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS request_body TEXT"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS request_content_type VARCHAR(127)"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS request_headers JSON"))
            await conn.execute(text("UPDATE users SET tags = '[]'::json WHERE tags IS NULL"))
            await conn.execute(text("UPDATE endpoints SET query_params = '[]'::json WHERE query_params IS NULL"))
            await conn.execute(text("UPDATE endpoints SET request_headers = '[]'::json WHERE request_headers IS NULL"))
        elif conn.dialect.name == "sqlite":
            columns = (await conn.execute(text("PRAGMA table_info(projects)"))).fetchall()
            has_folder = any(row[1] == "folder" for row in columns)
            has_timeline_frozen_at = any(row[1] == "timeline_frozen_at" for row in columns)
            if not has_folder:
                await conn.execute(text("ALTER TABLE projects ADD COLUMN folder VARCHAR(255) NOT NULL DEFAULT ''"))
            if not has_timeline_frozen_at:
                await conn.execute(text("ALTER TABLE projects ADD COLUMN timeline_frozen_at TIMESTAMP"))
    await audit_store.ensure_table()
    MinioStorage().ensure_bucket()
    async with SessionLocal() as db:
        service = UserService(db)
        await service.bootstrap_admin()


@app.get("/health")
async def health() -> dict:
    """Healthcheck эндпоинт для проверки доступности сервиса."""
    return {"status": "ok"}


_register_routes()
_register_error_handlers()
