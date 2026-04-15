from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import (
    EndpointCreate,
    EndpointOut,
    EndpointUpdate,
    HostCreate,
    HostOut,
    HostUpdate,
    PortCreate,
    PortOut,
    PortUpdate,
    ServiceCreate,
    ServiceOut,
    ServiceUpdate,
)
from app.services import AssetService

router = APIRouter(tags=["assets"])


@router.get("/projects/{project_id}/hosts", response_model=dict)
async def list_hosts(
    project_id: UUID,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает список хостов проекта."""
    items, total = await AssetService(db).list_hosts(project_id, page, size, status_filter)
    return to_paginated_response([HostOut.model_validate(it) for it in items], total, PageParams(page=page, size=size)).model_dump()


@router.post("/projects/{project_id}/hosts", response_model=HostOut, status_code=status.HTTP_201_CREATED)
async def create_host(
    project_id: UUID,
    payload: HostCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> HostOut:
    """Создаёт хост в проекте."""
    host = await AssetService(db).create_host(project_id, payload.model_dump(), current_user.id)
    return HostOut.model_validate(host)


@router.get("/projects/{project_id}/hosts/{host_id}")
async def get_host(
    project_id: UUID,
    host_id: UUID,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает хост с вложенными сущностями."""
    return await AssetService(db).get_host(project_id, host_id)


@router.put("/projects/{project_id}/hosts/{host_id}", response_model=HostOut)
async def update_host(
    project_id: UUID,
    host_id: UUID,
    payload: HostUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> HostOut:
    """Обновляет хост."""
    host = await AssetService(db).update_host(project_id, host_id, payload.model_dump(exclude_unset=True), current_user.id)
    return HostOut.model_validate(host)


@router.delete("/projects/{project_id}/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(
    project_id: UUID,
    host_id: UUID,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет хост."""
    await AssetService(db).delete_host(project_id, host_id, current_user.id)


@router.get("/projects/{project_id}/hosts/{host_id}/ports", response_model=list[PortOut])
async def list_ports(
    project_id: UUID,
    host_id: UUID,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[PortOut]:
    """Возвращает список портов хоста."""
    ports = await AssetService(db).list_ports(host_id)
    return [PortOut.model_validate(port) for port in ports]


@router.post("/projects/{project_id}/hosts/{host_id}/ports", response_model=PortOut, status_code=status.HTTP_201_CREATED)
async def create_port(
    project_id: UUID,
    host_id: UUID,
    payload: PortCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> PortOut:
    """Создаёт порт хоста."""
    port = await AssetService(db).create_port(project_id, host_id, payload.model_dump(), current_user.id)
    return PortOut.model_validate(port)


@router.get("/projects/{project_id}/hosts/{host_id}/ports/{port_id}", response_model=PortOut)
async def get_port(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> PortOut:
    """Возвращает порт."""
    port = await AssetService(db).get_port(host_id, port_id)
    return PortOut.model_validate(port)


@router.put("/projects/{project_id}/hosts/{host_id}/ports/{port_id}", response_model=PortOut)
async def update_port(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    payload: PortUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> PortOut:
    """Обновляет порт."""
    port = await AssetService(db).update_port(project_id, host_id, port_id, payload.model_dump(exclude_unset=True), current_user.id)
    return PortOut.model_validate(port)


@router.delete("/projects/{project_id}/hosts/{host_id}/ports/{port_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_port(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет порт."""
    await AssetService(db).delete_port(project_id, host_id, port_id, current_user.id)


@router.get("/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services", response_model=list[ServiceOut])
async def list_services(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ServiceOut]:
    """Возвращает список сервисов порта."""
    services = await AssetService(db).list_services(port_id)
    return [ServiceOut.model_validate(service) for service in services]


@router.post(
    "/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services",
    response_model=ServiceOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_service(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    payload: ServiceCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ServiceOut:
    """Создаёт сервис."""
    service = await AssetService(db).create_service(project_id, host_id, port_id, payload.model_dump(), current_user.id)
    return ServiceOut.model_validate(service)


@router.put("/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services/{service_id}", response_model=ServiceOut)
async def update_service(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    service_id: UUID,
    payload: ServiceUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ServiceOut:
    """Обновляет сервис."""
    service = await AssetService(db).update_service(
        project_id,
        host_id,
        port_id,
        service_id,
        payload.model_dump(exclude_unset=True),
        current_user.id,
    )
    return ServiceOut.model_validate(service)


@router.delete("/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service(
    project_id: UUID,
    host_id: UUID,
    port_id: UUID,
    service_id: UUID,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет сервис."""
    await AssetService(db).delete_service(project_id, port_id, service_id, current_user.id)


@router.get("/projects/{project_id}/hosts/{host_id}/endpoints", response_model=list[EndpointOut])
async def list_endpoints(
    project_id: UUID,
    host_id: UUID,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[EndpointOut]:
    """Возвращает endpoints хоста."""
    endpoints = await AssetService(db).list_endpoints(host_id)
    return [EndpointOut.model_validate(endpoint) for endpoint in endpoints]


@router.post("/projects/{project_id}/hosts/{host_id}/endpoints", response_model=EndpointOut, status_code=status.HTTP_201_CREATED)
async def create_endpoint(
    project_id: UUID,
    host_id: UUID,
    payload: EndpointCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> EndpointOut:
    """Создаёт endpoint."""
    endpoint = await AssetService(db).create_endpoint(project_id, host_id, payload.model_dump(), current_user.id)
    return EndpointOut.model_validate(endpoint)


@router.put("/projects/{project_id}/hosts/{host_id}/endpoints/{endpoint_id}", response_model=EndpointOut)
async def update_endpoint(
    project_id: UUID,
    host_id: UUID,
    endpoint_id: UUID,
    payload: EndpointUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> EndpointOut:
    """Обновляет endpoint."""
    endpoint = await AssetService(db).update_endpoint(project_id, host_id, endpoint_id, payload.model_dump(exclude_unset=True), current_user.id)
    return EndpointOut.model_validate(endpoint)


@router.delete("/projects/{project_id}/hosts/{host_id}/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_endpoint(
    project_id: UUID,
    host_id: UUID,
    endpoint_id: UUID,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет endpoint."""
    await AssetService(db).delete_endpoint(project_id, host_id, endpoint_id, current_user.id)
