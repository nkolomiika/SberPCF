from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.services import ReportService

router = APIRouter(tags=["reports"])

MEDIA_TYPE_BY_FORMAT = {
    "md": "text/markdown; charset=utf-8",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@router.post("/projects/{project_id}/reports/generate")
async def generate_report(
    project_id: UUID,
    output_format: str = Query(..., alias="format"),
    _: None = Depends(enforce_csrf),
    _user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Генерирует и возвращает отчёт по проекту."""
    content = await ReportService(db).generate(project_id, output_format)
    media_type = MEDIA_TYPE_BY_FORMAT.get(output_format, "application/octet-stream")
    headers = {"Content-Disposition": f'attachment; filename="report-{project_id}.{output_format}"'}
    return StreamingResponse(iter([content]), media_type=media_type, headers=headers)
