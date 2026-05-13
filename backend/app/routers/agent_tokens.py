from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, require_admin
from app.models import User
from app.schemas import AgentTokenCreate, AgentTokenCreateResponse, AgentTokenOut
from app.services import AgentTokenService

router = APIRouter(prefix="/agent-tokens", tags=["agent-tokens"])


@router.get("", response_model=list[AgentTokenOut])
async def list_agent_tokens(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Возвращает agent API tokens без секретных значений."""
    return await AgentTokenService(db).list_tokens()


@router.post("", response_model=AgentTokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_agent_token(
    payload: AgentTokenCreate,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Создаёт agent API token; значение token возвращается только один раз."""
    data, raw_token = await AgentTokenService(db).create_token(payload.model_dump(), admin.id)
    return {**data, "token": raw_token}


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent_token(
    token_id: UUID,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Отзывает agent API token."""
    await AgentTokenService(db).revoke_token(token_id, admin.id)
