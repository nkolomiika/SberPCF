from uuid import UUID

from fastapi import APIRouter, Depends, File as UploadApiFile, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.schemas import ImportResult, OpenApiImportResult
from app.services import ImportService

router = APIRouter(tags=["import"])


@router.post("/projects/{project_id}/import", response_model=ImportResult)
async def import_project_data(
    project_id: UUID,
    file: UploadFile = UploadApiFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ImportResult:
    """Импортирует JSON-структуру активов в проект."""
    payload = await file.read()
    return await ImportService(db).import_json(project_id, payload, current_user.id)


@router.post("/projects/{project_id}/hosts/{host_id}/import-openapi", response_model=OpenApiImportResult)
async def import_openapi_file(
    project_id: UUID,
    host_id: UUID,
    file: UploadFile = UploadApiFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> OpenApiImportResult:
    """Импортирует OpenAPI/Swagger JSON/YAML в endpoint-структуру конкретного хоста."""
    payload = await file.read()
    return await ImportService(db).import_openapi(project_id, host_id, payload, current_user.id)
