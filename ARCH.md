# Архитектура и спецификация API
## PCF — Pentest Collaboration Framework

---

# 1. Архитектура системы

## 1.1 Общая схема

```
┌──────────────────────────────────────────────────────────────────────┐
│                           Docker Compose                             │
│                                                                      │
│  ┌──────────────┐    HTTP/WS    ┌──────────────────────────────┐    │
│  │   frontend   │◄────────────►│           backend             │    │
│  │ React + TS   │              │   Python REST API + WS        │    │
│  └──────────────┘              └────────────┬──────────────────┘    │
│                                             │                        │
│                         ┌───────────────────┼──────────────┐        │
│                         │                   │              │        │
│                ┌────────▼──┐  ┌─────────────▼──┐  ┌───────▼─────┐  │
│                │    db     │  │    clickhouse  │  │    minio    │  │
│                │PostgreSQL │  │   Audit Logs   │  │ File Store  │  │
│                └───────────┘  └────────────────┘  └─────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

## 1.2 Архитектура бэкенда (Layered Architecture)

```
┌─────────────────────────────────────────────┐
│              HTTP / WebSocket               │  ← Транспортный уровень
├─────────────────────────────────────────────┤
│              Routers (Controllers)          │  ← Маршрутизация, валидация входных данных
├─────────────────────────────────────────────┤
│              Services (Business Logic)      │  ← Бизнес-логика, оркестрация
├─────────────────────────────────────────────┤
│              Repositories                   │  ← Работа с БД, SQL-запросы
├─────────────────────────────────────────────┤
│              Models (ORM)                   │  ← SQLAlchemy-модели
├─────────────────────────────────────────────┤
│    PostgreSQL    MinIO    ClickHouse        │  ← Хранилища данных
└─────────────────────────────────────────────┘
```

## 1.3 Структура директорий бэкенда

```
backend/
├── app/
│   ├── main.py                  # Точка входа, инициализация FastAPI/Flask
│   ├── config.py                # Настройки из env-переменных
│   ├── database.py              # Подключение к PostgreSQL (SQLAlchemy)
│   ├── dependencies.py          # DI: get_db, get_current_user, require_admin
│   │
│   ├── models/                  # SQLAlchemy ORM-модели
│   │   ├── user.py
│   │   ├── project.py
│   │   ├── host.py
│   │   ├── port.py
│   │   ├── service.py
│   │   ├── endpoint.py
│   │   ├── vulnerability.py
│   │   ├── vulnerability_asset.py
│   │   ├── file.py
│   │   ├── comment.py
│   │   ├── notification.py
│   │   └── refresh_token.py
│   │
│   ├── schemas/                 # Pydantic-схемы (request/response)
│   │   ├── auth.py
│   │   ├── user.py
│   │   ├── project.py
│   │   ├── host.py
│   │   ├── port.py
│   │   ├── service.py
│   │   ├── endpoint.py
│   │   ├── vulnerability.py
│   │   ├── file.py
│   │   ├── comment.py
│   │   ├── notification.py
│   │   └── pagination.py
│   │
│   ├── repositories/            # Repository Pattern — работа с БД
│   │   ├── base.py
│   │   ├── user_repo.py
│   │   ├── project_repo.py
│   │   ├── host_repo.py
│   │   ├── port_repo.py
│   │   ├── service_repo.py
│   │   ├── endpoint_repo.py
│   │   ├── vulnerability_repo.py
│   │   ├── file_repo.py
│   │   ├── comment_repo.py
│   │   ├── notification_repo.py
│   │   └── audit_repo.py
│   │
│   ├── services/                # Service Layer — бизнес-логика
│   │   ├── auth_service.py
│   │   ├── user_service.py
│   │   ├── project_service.py
│   │   ├── asset_service.py
│   │   ├── vulnerability_service.py
│   │   ├── file_service.py
│   │   ├── comment_service.py
│   │   ├── notification_service.py
│   │   ├── import_service.py
│   │   ├── report_service.py
│   │   └── audit_service.py
│   │
│   ├── routers/                 # FastAPI Routers
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── projects.py
│   │   ├── hosts.py
│   │   ├── ports.py
│   │   ├── services.py
│   │   ├── endpoints.py
│   │   ├── vulnerabilities.py
│   │   ├── files.py
│   │   ├── comments.py
│   │   ├── notifications.py
│   │   ├── reports.py
│   │   ├── import_.py
│   │   └── audit.py
│   │
│   ├── websocket/
│   │   ├── manager.py           # ConnectionManager: регистрация/рассылка
│   │   └── events.py            # Типы и форматы WS-событий
│   │
│   ├── storage/
│   │   └── minio_client.py      # Клиент MinIO: upload/download/delete
│   │
│   ├── infrastructure/
│   │   └── clickhouse_client.py # Клиент ClickHouse: запись и чтение audit_logs
│   │
│   └── utils/
│       ├── jwt.py               # Генерация и валидация JWT
│       ├── security.py          # bcrypt, SHA-256
│       ├── pagination.py        # Хелпер для offset-пагинации
│       └── audit.py             # Декоратор для автоматической записи аудита
│
├── migrations/                  # Alembic-миграции
├── tests/
├── Dockerfile
└── requirements.txt
```

## 1.4 Структура директорий фронтенда

```
frontend/
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   │
│   ├── api/                     # HTTP-клиент (axios instances)
│   │   ├── client.ts            # Базовый клиент с interceptors (JWT refresh)
│   │   ├── auth.ts
│   │   ├── projects.ts
│   │   ├── vulnerabilities.ts
│   │   └── ...
│   │
│   ├── store/                   # Глобальное состояние (Context API / Zustand)
│   │   ├── AuthContext.tsx
│   │   ├── NotificationContext.tsx
│   │   └── WebSocketContext.tsx
│   │
│   ├── hooks/                   # Custom React hooks
│   │   ├── useAuth.ts
│   │   ├── useWebSocket.ts
│   │   ├── usePagination.ts
│   │   └── useNotifications.ts
│   │
│   ├── pages/                   # Страницы (роуты)
│   │   ├── LoginPage.tsx
│   │   ├── ProjectsPage.tsx
│   │   ├── ProjectDetailPage.tsx
│   │   ├── VulnerabilityDetailPage.tsx
│   │   └── ...
│   │
│   ├── components/              # Переиспользуемые компоненты
│   │   ├── common/
│   │   ├── layout/
│   │   └── features/
│   │
│   └── types/                   # TypeScript-типы (совпадают со схемами API)
│       ├── auth.ts
│       ├── project.ts
│       ├── vulnerability.ts
│       └── ...
│
├── Dockerfile
└── package.json
```

---

# 2. Паттерны проектирования

## 2.1 Backend

### Repository Pattern
Весь доступ к БД инкапсулируется в классах-репозиториях. Router и Service никогда не пишут SQL напрямую.

```python
# repositories/base.py
class BaseRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

# repositories/vulnerability_repo.py
class VulnerabilityRepository(BaseRepository):
    async def get_by_project(self, project_id: UUID, page: int, size: int) -> tuple[list, int]:
        ...
    async def create(self, data: VulnerabilityCreate) -> Vulnerability:
        ...
    async def update(self, vuln_id: UUID, data: VulnerabilityUpdate) -> Vulnerability:
        ...
    async def delete(self, vuln_id: UUID) -> None:
        ...
```

### Service Layer
Сервисы содержат бизнес-логику и оркестрируют репозитории. Один сервис может использовать несколько репозиториев.

```python
# services/vulnerability_service.py
class VulnerabilityService:
    def __init__(self, vuln_repo, audit_repo, ws_manager, notification_service):
        ...

    async def create_vulnerability(self, project_id, data, current_user):
        # 1. Проверить доступ пользователя к проекту
        # 2. Создать запись в БД через vuln_repo
        # 3. Записать в audit_log
        # 4. Отправить WS-событие всем участникам проекта
        ...
```

### Dependency Injection
Все зависимости (БД-сессия, текущий пользователь, проверка прав) передаются через FastAPI Depends.

```python
# dependencies.py
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    # Читаем access-токен из httpOnly cookie, не из заголовка Authorization
    token = request.cookies.get("access_token")
    if not token:
        raise ForbiddenError("Требуется аутентификация")
    ...

async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(403)
    return current_user

async def require_project_access(project_id: UUID, current_user: User = Depends(get_current_user), db = Depends(get_db)) -> Project:
    # Проверяет: admin видит всё, pentester — только назначенные проекты
    ...
```

### Factory Pattern — генерация отчётов
Фабрика создаёт нужный генератор отчёта в зависимости от формата.

```python
# services/report_service.py
class ReportGenerator(ABC):
    @abstractmethod
    async def generate(self, project_id: UUID) -> bytes: ...

class MarkdownReportGenerator(ReportGenerator): ...
class PdfReportGenerator(ReportGenerator): ...
class DocxReportGenerator(ReportGenerator): ...

class ReportFactory:
    _generators = {
        "md":   MarkdownReportGenerator,
        "pdf":  PdfReportGenerator,
        "docx": DocxReportGenerator,
    }

    @classmethod
    def create(cls, format: str) -> ReportGenerator:
        generator = cls._generators.get(format)
        if not generator:
            raise ValueError(f"Unsupported format: {format}")
        return generator()
```

### Decorator Pattern — аудит
Декоратор автоматически записывает действие в `audit_logs` (ClickHouse) после выполнения сервисного метода. Запись производится асинхронно (fire-and-forget): ошибка записи в ClickHouse логируется, но не прерывает основную операцию.

```python
# utils/audit.py
def audit_action(action: str, entity_type: str):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            # Пишем в ClickHouse асинхронно, не блокируя ответ
            try:
                await audit_repo.create(action=action, entity_type=entity_type, ...)
            except Exception:
                logger.exception("Ошибка записи аудита в ClickHouse")
            return result
        return wrapper
    return decorator

# Использование:
@audit_action("CREATE", "vulnerability")
async def create_vulnerability(self, ...): ...
```

### WebSocket Connection Manager
Singleton-менеджер хранит активные соединения и рассылает события по комнатам (project_id).

```python
# websocket/manager.py
class ConnectionManager:
    def __init__(self):
        # project_id -> list of WebSocket connections
        self._rooms: dict[UUID, list[WebSocket]] = {}

    async def connect(self, project_id: UUID, ws: WebSocket): ...
    async def disconnect(self, project_id: UUID, ws: WebSocket): ...
    async def broadcast(self, project_id: UUID, event: dict): ...

ws_manager = ConnectionManager()  # глобальный singleton
```

## 2.2 Frontend

### Zustand + React Hooks (State Management)
Глобальное состояние авторизации и части UI хранится в `Zustand`; локальное состояние страниц и обработчики UI реализуются через React hooks.
Актуальный runtime/frontend toolchain работает только через `main.tsx` и `TS/TSX`-слой; legacy `*.js` файлы остаются в репозитории как неактивный слой и исключаются из type-check/lint.

```typescript
// store.ts
export const useAuthStore = create((set) => ({
  user: null,
  initialize: async () => { /* загрузка /users/me */ },
  signIn: async () => { /* login + getMe */ }
}));
```

### Axios — Cookie-based аутентификация
Токены хранятся в httpOnly cookie и отправляются браузером автоматически.
Никакой ручной работы с заголовком `Authorization` не требуется.

```typescript
// api/client.ts
const axiosInstance = axios.create({
  baseURL: "/api/v1",
  // Обязательно: отправлять cookie при каждом запросе (в т.ч. cross-origin)
  withCredentials: true,
});

// При получении 401 — cookie истекла, вызываем /auth/refresh
// Бэкенд сам обновит cookie через Set-Cookie в ответе
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401 && !error.config._retry) {
      error.config._retry = true;
      try {
        // POST /auth/refresh — бэкенд читает refresh cookie и выставляет новую access cookie
        await axiosInstance.post("/auth/refresh");
        // Повторяем оригинальный запрос — браузер уже отправит обновлённую cookie
        return axiosInstance(error.config);
      } catch {
        // refresh тоже истёк — редиректим на логин
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);
```

### Feature-based Structure
Компоненты сгруппированы по фичам, а не по типу (не все кнопки в одной папке).

```
components/features/
├── vulnerabilities/
│   ├── VulnerabilityList.tsx
│   ├── VulnerabilityCard.tsx
│   ├── VulnerabilityForm.tsx
│   └── VulnerabilityAssets.tsx
├── assets/
│   ├── HostTree.tsx
│   └── PortList.tsx
└── comments/
    ├── CommentList.tsx
    └── CommentForm.tsx  # с поддержкой @mention
```

---

# 3. Спецификация API (Swagger)

## Общие соглашения

- Базовый URL: `/api/v1`
- Аутентификация: **httpOnly cookie** — токены выставляются сервером через `Set-Cookie` при логине и автоматически отправляются браузером при каждом запросе. Заголовок `Authorization` **не используется**.
- Фронтенд обязан выполнять все запросы с флагом `withCredentials: true` (axios) или `credentials: "include"` (fetch).
- Пагинация: `?page=1&size=20`
- Формат ответа пагинированных списков:

```json
{
  "items": [...],
  "total": 100,
  "page": 1,
  "size": 20,
  "pages": 5
}
```

- Формат ошибки:

```json
{
  "detail": "Описание ошибки"
}
```

- Коды ошибок:
  - `400` — ошибка валидации входных данных
  - `401` — не авторизован
  - `403` — недостаточно прав
  - `404` — ресурс не найден
  - `409` — конфликт (дубликат)
  - `422` — ошибка бизнес-валидации

---

## 3.1 Auth — Аутентификация

### POST /api/v1/auth/login
Вход в систему. Токены **не возвращаются в теле ответа** — сервер выставляет два httpOnly cookie.

**Auth:** не требуется

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response 200:**

Заголовки ответа:
```
Set-Cookie: access_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1800
Set-Cookie: refresh_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh; Max-Age=2592000
```

Тело ответа (только публичные данные пользователя):
```json
{
  "id": "uuid",
  "username": "nikita",
  "role": "admin",
  "must_change_password": false
}
```

**Errors:** `401` — неверные учётные данные

---

### POST /api/v1/auth/refresh
Обновление access-токена. Бэкенд читает `refresh_token` из cookie и выставляет новую `access_token` cookie.

**Auth:** не требуется (refresh_token cookie отправляется браузером автоматически)

**Request Body:** отсутствует

**Response 200:**

Заголовки ответа:
```
Set-Cookie: access_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1800
```

Тело ответа:
```json
{
  "ok": true,
  "must_change_password": false
}
```

**Errors:** `401` — refresh cookie отсутствует, истекла или отозвана

---

### POST /api/v1/auth/logout
Отзыв токенов. Сервер инвалидирует refresh-токен в БД и удаляет обе cookie через `Max-Age=0`.

**Auth:** требуется (access_token cookie)

**Request Body:** отсутствует

**Response 204:** No Content

Заголовки ответа:
```
Set-Cookie: access_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0
Set-Cookie: refresh_token=; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh; Max-Age=0
```

---

### POST /api/v1/auth/force-change-password
Обязательная смена временного пароля после invite/reset flow.

**Auth:** требуется (access_token cookie)

**Request Body:**
```json
{
  "new_password": "StrongPassword123!"
}
```

**Response 200:** `User`

**Поведение:**
- доступен только пользователю с `must_change_password = true`
- при успешной смене пароля флаг `must_change_password` снимается
- все активные refresh-токены пользователя отзываются

---

## 3.2 Users — Пользователи

> Административные операции над пользователями доступны только роли `admin`. Сам пользователь может читать и редактировать собственный профиль, менять свой пароль и загружать свой аватар.

### GET /api/v1/users/me
Получить информацию о текущем пользователе.

**Auth:** требуется (любая роль)

**Response 200:**
```json
{
  "id": "uuid",
  "username": "nikita",
  "email": "nikita@example.com",
  "full_name": "Nikita Ivanov",
  "tags": ["team-a", "web"],
  "avatar_url": "/api/v1/users/{id}/avatar",
  "role": "admin",
  "is_active": true,
  "must_change_password": false,
  "password_changed_at": "2024-01-01T00:00:00Z",
  "created_at": "2024-01-01T00:00:00Z"
}
```

---

### GET /api/v1/users
Список всех пользователей системы.

**Auth:** `admin`

**Query params:** `?page=1&size=20`

**Response 200:** `PaginatedResponse<User>`

---

### POST /api/v1/users
Создание нового пользователя (только администратор).

**Auth:** `admin`

**Request Body:**
```json
{
  "username": "string",      // required, уникальный
  "email": "string",         // required, уникальный
  "full_name": "string",     // optional
  "tags": ["web", "ext"],    // optional
  "password": "string",      // optional, min 8 символов
  "send_invite_email": true,  // optional, если true — пароль генерируется сервером и отправляется по email
  "role": "pentester"        // "admin" | "pentester", default "pentester"
}
```

**Response 201:**
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "role": "pentester",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

**Errors:** `409` — username или email уже занят

---

### PATCH /api/v1/users/me
Обновить собственный профиль (`username`, `email`, `full_name`, `tags`).

**Auth:** требуется

**Response 200:** `User`

---

### PATCH /api/v1/users/me/password
Сменить собственный пароль с проверкой текущего пароля.

**Auth:** требуется

**Response 200:** `User`

---

### POST /api/v1/users/me/avatar
Загрузить/заменить собственный аватар.

**Auth:** требуется

**Request:** `multipart/form-data`, поле `avatar`

**Response 200:** `User`

---

### GET /api/v1/users/{user_id}/avatar
Скачать аватар пользователя. Доступно самому пользователю или администратору.

**Auth:** требуется

**Response 200:** бинарные данные изображения

---

### GET /api/v1/users/{user_id}
Получить пользователя по ID.

**Auth:** `admin`

**Response 200:** `User`

**Errors:** `404`

---

### PUT /api/v1/users/{user_id}
Обновить данные пользователя.

**Auth:** `admin`

**Request Body:**
```json
{
  "username": "string",      // optional
  "email": "string",         // optional
  "role": "admin",           // optional
  "is_active": true          // optional
}
```

**Response 200:** `User`

---

### DELETE /api/v1/users/{user_id}
Удалить пользователя.

**Auth:** `admin`

**Response 204:** No Content

**Errors:** `400` — нельзя удалить самого себя

---

### PATCH /api/v1/users/{user_id}/password
Сбросить пароль пользователя. Временный пароль генерируется сервером, отправляется на email и требует обязательной смены при следующем входе.

**Auth:** `admin`

**Request Body:** отсутствует

**Response 200:**
```json
{
  "ok": true,
  "email_sent_to": "user@example.com",
  "must_change_password": true
}
```

---

## 3.3 Projects — Проекты

### GET /api/v1/projects
Список проектов.
- `admin` видит все проекты
- `pentester` видит только проекты, в которых является участником

**Auth:** требуется

**Query params:** `?page=1&size=20&status=active`

**Response 200:** `PaginatedResponse<Project>`
```json
{
  "items": [{
    "id": "uuid",
    "name": "Pentest Corp 2024",
    "description": "...",
    "start_date": "2024-01-01",
    "end_date": "2024-03-01",
    "status": "active",
    "created_by": "uuid",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }],
  "total": 1, "page": 1, "size": 20, "pages": 1
}
```

---

### POST /api/v1/projects
Создать проект.

**Auth:** `admin`

**Request Body:**
```json
{
  "name": "string",          // required
  "description": "string",   // optional
  "start_date": "2024-01-01",// optional
  "end_date": "2024-03-01"   // optional
}
```

**Response 201:** `Project`

---

### GET /api/v1/projects/{project_id}
Получить проект по ID.

**Auth:** требуется (участник или admin)

**Response 200:** `Project`

**Errors:** `403`, `404`

---

### PUT /api/v1/projects/{project_id}
Обновить проект.

**Auth:** `admin`

**Request Body:**
```json
{
  "name": "string",
  "description": "string",
  "start_date": "2024-01-01",
  "end_date": "2024-03-01",
  "status": "completed"
}
```

**Response 200:** `Project`

---

### DELETE /api/v1/projects/{project_id}
Удалить проект (каскадно: хосты, уязвимости, файлы в MinIO).

**Auth:** `admin`

**Response 204:** No Content

---

### GET /api/v1/projects/{project_id}/members
Список участников проекта.

**Auth:** требуется (участник или admin)

**Response 200:**
```json
[{
  "user_id": "uuid",
  "username": "string",
  "email": "string",
  "role": "pentester",
  "added_at": "2024-01-01T00:00:00Z"
}]
```

---

### POST /api/v1/projects/{project_id}/members
Добавить участника в проект.

**Auth:** `admin`

**Request Body:**
```json
{
  "user_id": "uuid"
}
```

**Response 201:**
```json
{
  "user_id": "uuid",
  "username": "string",
  "added_at": "2024-01-01T00:00:00Z"
}
```

**Errors:** `409` — пользователь уже участник

---

### DELETE /api/v1/projects/{project_id}/members/{user_id}
Удалить участника из проекта.

**Auth:** `admin`

**Response 204:** No Content

---

## 3.4 Hosts — Хосты

### GET /api/v1/projects/{project_id}/hosts
Список хостов проекта.

**Auth:** требуется (участник или admin)

**Query params:** `?page=1&size=20&status=up`

**Response 200:** `PaginatedResponse<Host>`
```json
{
  "items": [{
    "id": "uuid",
    "project_id": "uuid",
    "ip_address": "192.168.1.1",
    "hostname": "target.example.com",
    "os": "Ubuntu 22.04",
    "status": "up",
    "notes": "...",
    "created_at": "...",
    "updated_at": "..."
  }],
  "total": 1, "page": 1, "size": 20, "pages": 1
}
```

---

### POST /api/v1/projects/{project_id}/hosts
Добавить хост.

**Auth:** требуется (участник или admin)

**Request Body:**
```json
{
  "ip_address": "192.168.1.1",  // optional, но хотя бы одно из ip/hostname required
  "hostname": "string",          // optional
  "os": "string",                // optional
  "status": "unknown",           // "up"|"down"|"unknown", default "unknown"
  "notes": "string"              // optional
}
```

**Response 201:** `Host`

---

### GET /api/v1/projects/{project_id}/hosts/{host_id}
Получить хост с вложенными портами и endpoints.

**Auth:** требуется

**Response 200:**
```json
{
  "id": "uuid",
  "ip_address": "192.168.1.1",
  "hostname": "target.example.com",
  "os": "Ubuntu 22.04",
  "status": "up",
  "notes": "...",
  "ports": [...],
  "endpoints": [...]
}
```

---

### PUT /api/v1/projects/{project_id}/hosts/{host_id}
Обновить хост.

**Auth:** требуется

**Request Body:** аналогично POST (все поля optional)

**Response 200:** `Host`

---

### DELETE /api/v1/projects/{project_id}/hosts/{host_id}
Удалить хост (каскадно: порты, сервисы, endpoints).

**Auth:** требуется

**Response 204:** No Content

---

## 3.5 Ports — Порты

### GET /api/v1/projects/{project_id}/hosts/{host_id}/ports
Список портов хоста.

**Auth:** требуется

**Response 200:**
```json
[{
  "id": "uuid",
  "host_id": "uuid",
  "port_number": 80,
  "protocol": "tcp",
  "state": "open",
  "services": [...],
  "created_at": "...",
  "updated_at": "..."
}]
```

---

### POST /api/v1/projects/{project_id}/hosts/{host_id}/ports
Добавить порт.

**Auth:** требуется

**Request Body:**
```json
{
  "port_number": 80,            // required, 1-65535
  "protocol": "tcp",            // "tcp"|"udp", default "tcp"
  "state": "open"               // "open"|"closed"|"filtered", default "open"
}
```

**Response 201:** `Port`

**Errors:** `409` — порт с таким номером и протоколом уже существует

---

### GET /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}
Получить порт.

**Auth:** требуется

**Response 200:** `Port`

---

### PUT /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}
Обновить порт.

**Auth:** требуется

**Request Body:**
```json
{
  "state": "closed"
}
```

**Response 200:** `Port`

---

### DELETE /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}
Удалить порт (каскадно: сервисы).

**Auth:** требуется

**Response 204:** No Content

---

## 3.6 Services — Сервисы

### GET /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services
Список сервисов на порту.

**Auth:** требуется

**Response 200:**
```json
[{
  "id": "uuid",
  "port_id": "uuid",
  "name": "http",
  "version": "Apache/2.4.51",
  "banner": "...",
  "created_at": "...",
  "updated_at": "..."
}]
```

---

### POST /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services
Добавить сервис.

**Auth:** требуется

**Request Body:**
```json
{
  "name": "http",               // required
  "version": "Apache/2.4.51",  // optional
  "banner": "string"            // optional
}
```

**Response 201:** `Service`

---

### PUT /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services/{service_id}
Обновить сервис.

**Auth:** требуется

**Response 200:** `Service`

---

### DELETE /api/v1/projects/{project_id}/hosts/{host_id}/ports/{port_id}/services/{service_id}
Удалить сервис.

**Auth:** требуется

**Response 204:** No Content

---

## 3.7 Endpoints — HTTP-ручки

### GET /api/v1/projects/{project_id}/hosts/{host_id}/endpoints
Список endpoints хоста.

**Auth:** требуется

**Response 200:**
```json
[{
  "id": "uuid",
  "host_id": "uuid",
  "path": "/api/v1/login",
  "method": "POST",
  "description": "Авторизация пользователя",
  "created_at": "...",
  "updated_at": "..."
}]
```

---

### POST /api/v1/projects/{project_id}/hosts/{host_id}/endpoints
Добавить endpoint.

**Auth:** требуется

**Request Body:**
```json
{
  "path": "/api/v1/login",                                         // required
  "method": "POST",          // "GET"|"POST"|"PUT"|"PATCH"|"DELETE"|"HEAD"|"OPTIONS", optional
  "description": "string"                                          // optional
}
```

**Response 201:** `Endpoint`

---

### PUT /api/v1/projects/{project_id}/hosts/{host_id}/endpoints/{endpoint_id}
Обновить endpoint.

**Auth:** требуется

**Response 200:** `Endpoint`

---

### DELETE /api/v1/projects/{project_id}/hosts/{host_id}/endpoints/{endpoint_id}
Удалить endpoint.

**Auth:** требуется

**Response 204:** No Content

---

## 3.8 Vulnerabilities — Уязвимости

### GET /api/v1/projects/{project_id}/vulnerabilities
Список уязвимостей проекта.

**Auth:** требуется

**Query params:** `?page=1&size=20&severity=critical&status=open`

**Response 200:** `PaginatedResponse<Vulnerability>`
```json
{
  "items": [{
    "id": "uuid",
    "project_id": "uuid",
    "title": "SQL Injection в форме входа",
    "description": "...",
    "severity": "critical",
    "cvss_version": "3.1",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe_id": "CWE-89",
    "status": "open",
    "steps_to_reproduce": "...",
    "impact": "...",
    "recommendations": "...",
    "created_by": "uuid",
    "created_at": "...",
    "updated_at": "..."
  }],
  "total": 1, "page": 1, "size": 20, "pages": 1
}
```

---

### POST /api/v1/projects/{project_id}/vulnerabilities
Создать уязвимость.

**Auth:** требуется

**Request Body:**
```json
{
  "title": "string",            // required
  "description": "string",      // optional
  "severity": "critical",       // required: "critical"|"high"|"medium"|"low"|"info"
  "cvss_version": "3.1",        // optional: "3.1"|"4.0"
  "cvss_score": 9.8,            // optional: 0.0-10.0
  "cvss_vector": "string",      // optional
  "cwe_id": "CWE-89",           // optional, свободный текст
  "status": "open",             // optional, default "open"
  "steps_to_reproduce": "string",// optional
  "impact": "string",           // optional
  "recommendations": "string"   // optional
}
```

**Response 201:** `Vulnerability`

---

### GET /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}
Получить уязвимость с активами, файлами и комментариями.

**Auth:** требуется

**Response 200:**
```json
{
  "id": "uuid",
  "title": "...",
  "...": "...",
  "assets": [
    {"asset_type": "host", "asset_id": "uuid", "asset_detail": {...}},
    {"asset_type": "endpoint", "asset_id": "uuid", "asset_detail": {...}}
  ],
  "files": [...],
  "comments_count": 3
}
```

---

### PUT /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}
Обновить уязвимость (все поля optional).

**Auth:** требуется

**Response 200:** `Vulnerability`

---

### PATCH /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/status
Изменить статус уязвимости (отдельный эндпоинт, фиксируется в audit как `STATUS_CHANGE`).

**Auth:** требуется

**Request Body:**
```json
{
  "status": "fixed"  // "open"|"in_progress"|"fixed"|"wont_fix"|"accepted_risk"
}
```

**Response 200:** `Vulnerability`

---

### DELETE /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}
Удалить уязвимость (каскадно: файлы в MinIO, комментарии).

**Auth:** требуется

**Response 204:** No Content

---

## 3.9 Vulnerability Assets — Связи уязвимости с активами

### GET /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/assets
Список активов, связанных с уязвимостью.

**Auth:** требуется

**Response 200:**
```json
[{
  "id": "uuid",
  "vulnerability_id": "uuid",
  "asset_type": "endpoint",
  "asset_id": "uuid",
  "asset_detail": {
    "path": "/api/v1/login",
    "method": "POST"
  }
}]
```

---

### POST /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/assets
Привязать актив к уязвимости.

**Auth:** требуется

**Request Body:**
```json
{
  "asset_type": "endpoint",    // "host"|"port"|"service"|"endpoint"
  "asset_id": "uuid"
}
```

**Response 201:** `VulnerabilityAsset`

**Errors:** `404` — актив не найден; `409` — связь уже существует; `422` — актив принадлежит другому проекту

---

### DELETE /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/assets/{asset_link_id}
Удалить связь уязвимости с активом.

**Auth:** требуется

**Response 204:** No Content

---

## 3.10 Files — Файлы

### GET /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/files
Список файлов уязвимости.

**Auth:** требуется

**Response 200:**
```json
[{
  "id": "uuid",
  "original_name": "screenshot.png",
  "content_type": "image/png",
  "size_bytes": 204800,
  "uploaded_by": "uuid",
  "uploaded_at": "2024-01-01T00:00:00Z"
}]
```

---

### POST /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/files
Загрузить файл. Формат: `multipart/form-data`.

**Auth:** требуется

**Request:** `Content-Type: multipart/form-data`
- Поле `file`: бинарные данные файла (макс. 50 МБ)

**Response 201:**
```json
{
  "id": "uuid",
  "original_name": "screenshot.png",
  "content_type": "image/png",
  "size_bytes": 204800,
  "uploaded_by": "uuid",
  "uploaded_at": "2024-01-01T00:00:00Z"
}
```

**Errors:**
- `400` — неподдерживаемый тип файла
- `413` — файл превышает 50 МБ

---

### GET /api/v1/files/{file_id}/download
Получить файл для скачивания/отображения.

**Auth:** требуется

**Response 200:** бинарные данные файла с заголовками:
- `Content-Type: image/png`
- `Content-Disposition: inline; filename="screenshot.png"` (для изображений)
- `Content-Disposition: attachment; filename="report.pdf"` (для документов)

---

### DELETE /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/files/{file_id}
Удалить файл (из БД и MinIO).

**Auth:** требуется

**Response 204:** No Content

---

## 3.11 Comments — Комментарии

### GET /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/comments
Список комментариев к уязвимости.

**Auth:** требуется

**Query params:** `?page=1&size=50`

**Response 200:** `PaginatedResponse<Comment>`
```json
{
  "items": [{
    "id": "uuid",
    "vulnerability_id": "uuid",
    "user_id": "uuid",
    "username": "nikita",
    "content": "Подтверждаю @ivan, уязвимость воспроизводится",
    "mentions": [{"user_id": "uuid", "username": "ivan"}],
    "created_at": "...",
    "updated_at": "..."
  }],
  "total": 3, "page": 1, "size": 50, "pages": 1
}
```

---

### POST /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/comments
Добавить комментарий. Бэкенд парсит @username в тексте и создаёт уведомления.

**Auth:** требуется

**Request Body:**
```json
{
  "content": "string"           // required, текст с опциональными @username
}
```

**Response 201:** `Comment`

---

### PUT /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/comments/{comment_id}
Редактировать комментарий (только автор).

**Auth:** требуется (только автор комментария)

**Request Body:**
```json
{
  "content": "string"
}
```

**Response 200:** `Comment`

**Errors:** `403` — не автор

---

### DELETE /api/v1/projects/{project_id}/vulnerabilities/{vuln_id}/comments/{comment_id}
Удалить комментарий (только автор или admin).

**Auth:** требуется (автор или admin)

**Response 204:** No Content

---

## 3.12 Notifications — Уведомления

### GET /api/v1/notifications
Список in-app уведомлений текущего пользователя.

**Auth:** требуется

**Query params:** `?page=1&size=20&is_read=false`

**Response 200:** `PaginatedResponse<Notification>`
```json
{
  "items": [{
    "id": "uuid",
    "type": "mention",
    "comment_id": "uuid",
    "is_read": false,
    "created_at": "...",
    "context": {
      "vulnerability_id": "uuid",
      "vulnerability_title": "SQL Injection",
      "project_id": "uuid",
      "commenter_username": "ivan"
    }
  }],
  "total": 5, "page": 1, "size": 20, "pages": 1
}
```

---

### GET /api/v1/notifications/unread-count
Количество непрочитанных уведомлений (для бейджа).

**Auth:** требуется

**Response 200:**
```json
{
  "count": 5
}
```

---

### PATCH /api/v1/notifications/{notification_id}/read
Отметить уведомление как прочитанное.

**Auth:** требуется (только получатель)

**Response 200:**
```json
{
  "id": "uuid",
  "is_read": true
}
```

---

### PATCH /api/v1/notifications/read-all
Отметить все уведомления как прочитанные.

**Auth:** требуется

**Response 204:** No Content

---

## 3.13 Import — Импорт данных

### POST /api/v1/projects/{project_id}/import
Импортировать данные об инфраструктуре из JSON-файла формата PCF.

**Auth:** требуется

**Request:** `Content-Type: multipart/form-data`
- Поле `file`: JSON-файл

**Схема PCF JSON:**
```json
{
  "hosts": [
    {
      "ip_address": "192.168.1.1",
      "hostname": "target.local",
      "status": "up",
      "notes": "string",
      "ports": [
        {
          "port_number": 80,
          "protocol": "tcp",
          "state": "open",
          "services": [
            {
              "name": "http",
              "version": "Apache/2.4.51",
              "banner": "string"
            }
          ]
        }
      ],
      "endpoints": [
        {
          "path": "/api/login",
          "method": "POST",
          "description": "string",
          "query_params": [],
          "request_headers": [],
          "request_body": null,
          "request_content_type": null,
          "request_raw": null
        }
      ]
    }
  ]
}
```

**Валидация:**
- у каждого host должен быть `ip_address` или `hostname`
- `protocol`: `tcp | udp`
- `state`: `open | closed | filtered`
- `method`: `GET | POST | PUT | PATCH | DELETE | HEAD | OPTIONS`
- endpoint обязан содержать `path` или `request_raw`
- повторный импорт использует merge-стратегию без дублей: существующие `host/port/service/endpoint` переиспользуются по идентичности, а недостающие поля мягко дополняются

**Дополнение по UI:** на карточке хоста доступен отдельный frontend-only импорт Swagger/OpenAPI (`JSON`/`YAML`), который разворачивает `paths` в набор обычных вызовов создания endpoint.

**Response 200:**
```json
{
  "hosts_created": 5,
  "ports_created": 23,
  "services_created": 12,
  "endpoints_created": 8,
  "errors": []
}
```

**Errors:**
- `400` — невалидная JSON-схема
- `422` — ошибка бизнес-валидации (например, дубликат порта)

---

## 3.14 Reports — Отчёты

### POST /api/v1/projects/{project_id}/reports/generate
Сформировать и скачать отчёт по проекту.

**Auth:** требуется

**Query params:** `?format=pdf` (`md` | `pdf` | `docx`)

**Response 200:** бинарные данные файла с заголовками:
- `Content-Type: text/markdown` / `application/pdf` / `application/vnd.openxmlformats-officedocument.wordprocessingml.document`
- `Content-Disposition: attachment; filename="report-{project_name}.{format}"`

**Содержимое отчёта:**
- общая информация о проекте и участниках
- статистика по severity/status
- сводка по хостам и портам
- список уязвимостей с `CVSS`, `CWE`, активами, вложениями
- шаги воспроизведения, включая структурированные `workflow_steps`, если они заданы
- список скриншотов/вложений, привязанных к уязвимостям
- для `PDF` и `DOCX` изображения из MinIO встраиваются прямо в документ в секциях этапов воспроизведения и дополнительных скриншотов

**Errors:** `400` — неподдерживаемый формат

---

## 3.15 Audit Logs — Журнал действий

> Приложение пишет аудит в PostgreSQL и дополнительно доставляет записи в ClickHouse. Чтение журнала может использовать ClickHouse как основной backend, но API-интерфейс для клиента остаётся единым.

### GET /api/v1/audit-logs
Список записей журнала действий.

**Auth:** `admin`

**Query params:** `?page=1&size=50&user_id=uuid&username=alice&action=LOGIN&entity_type=vulnerability&query=password&created_from=2024-01-01&created_to=2024-12-31`

**Response 200:** `PaginatedResponse<AuditLog>`
```json
{
  "items": [{
    "id": "uuid",
    "user_id": "uuid",
    "username": "nikita",
    "action": "STATUS_CHANGE",
    "entity_type": "vulnerability",
    "entity_id": "uuid",
    "details": {
      "old_status": "open",
      "new_status": "fixed"
    },
    "ip_address": "127.0.0.1",
    "created_at": "2024-01-01T00:00:00Z"
  }],
  "total": 100, "page": 1, "size": 50, "pages": 2
}
```

---

## 3.16 WebSocket

### WS /ws/projects/{project_id}
Real-time канал проекта. Браузер автоматически передаёт cookie при WebSocket-рукопожатии (handshake).

**Auth:** httpOnly cookie `access_token` — передаётся браузером автоматически при установке соединения. Никакой query-параметр `?token=` не используется. Бэкенд читает cookie из заголовка `Cookie` входящего HTTP Upgrade-запроса.

**Формат входящего события от сервера:**
```json
{
  "event": "created",
  "entity": "vulnerability",
  "project_id": "uuid",
  "data": {
    "id": "uuid",
    "title": "SQL Injection",
    "severity": "critical",
    "status": "open",
    "..."
  }
}
```

**Формат уведомления об упоминании:**
```json
{
  "event": "notification",
  "data": {
    "id": "uuid",
    "type": "mention",
    "comment_id": "uuid",
    "is_read": false,
    "context": {
      "vulnerability_id": "uuid",
      "vulnerability_title": "SQL Injection",
      "commenter_username": "ivan"
    }
  }
}
```

**Возможные значения `event`:** `created`, `updated`, `deleted`, `notification`

**Возможные значения `entity`:** `host`, `port`, `service`, `endpoint`, `vulnerability`, `comment`, `file`

---

# 4. Матрица доступа к эндпоинтам

| Эндпоинт | admin | pentester (участник) | pentester (не участник) |
|---|:---:|:---:|:---:|
| POST /auth/login | ✓ | ✓ | ✓ |
| POST /auth/refresh | ✓ | ✓ | ✓ |
| POST /auth/force-change-password | ✓ | ✓ | ✓ |
| GET /users/me | ✓ | ✓ | ✓ |
| PATCH /users/me | ✓ | ✓ | ✓ |
| PATCH /users/me/password | ✓ | ✓ | ✓ |
| POST /users/me/avatar | ✓ | ✓ | ✓ |
| GET /users/{id}/avatar | ✓ | ✓ (только свой) | ✓ (только свой) |
| GET /users | ✓ | ✗ | ✗ |
| POST /users | ✓ | ✗ | ✗ |
| PATCH /users/{id}/password | ✓ | ✗ | ✗ |
| PUT/DELETE /users/{id} | ✓ | ✗ | ✗ |
| GET /projects | ✓ (все) | ✓ (свои) | ✓ (свои) |
| POST /projects | ✓ | ✗ | ✗ |
| PUT/DELETE /projects/{id} | ✓ | ✗ | ✗ |
| GET/POST/DELETE /projects/{id}/members | ✓ | ✗ | ✗ |
| GET /projects/{id}/hosts | ✓ | ✓ | ✗ |
| POST/PUT/DELETE hosts, ports, services, endpoints | ✓ | ✓ | ✗ |
| GET/POST/PUT/DELETE /vulnerabilities | ✓ | ✓ | ✗ |
| PATCH /vulnerabilities/{id}/status | ✓ | ✓ | ✗ |
| POST/DELETE /files | ✓ | ✓ | ✗ |
| GET /files/{id}/download | ✓ | ✓ | ✗ |
| POST/PUT/DELETE /comments | ✓ | ✓ (свои) | ✗ |
| DELETE /comments/{id} (чужой) | ✓ | ✗ | ✗ |
| GET/PATCH /notifications | ✓ | ✓ | ✓ |
| POST /import | ✓ | ✓ | ✗ |
| POST /reports/generate | ✓ | ✓ | ✗ |
| GET /audit-logs | ✓ | ✗ | ✗ |
| WS /ws/projects/{id} | ✓ | ✓ | ✗ |

---

# 5. Переменные окружения

## Backend (.env)

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:password@db:5432/pcf

# JWT
JWT_SECRET_KEY=<секретный ключ, min 32 символа>
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# MinIO
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET_NAME=pcf-files
MINIO_USE_SSL=false

# App
DEBUG=false
CORS_ORIGINS=http://localhost:3000

# ClickHouse
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_DB=pcf
```

## docker-compose.yml (структура)

```yaml
services:
  backend:
    build: ./backend
    env_file: .env
    depends_on: [db, minio]
    ports:
      - "8000:8000"

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: pcf
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - pgdata:/var/lib/postgresql/data

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - miniodata:/data
    ports:
      - "9000:9000"
      - "9001:9001"

  clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    environment:
      CLICKHOUSE_DB: pcf
      CLICKHOUSE_USER: default
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
    ports:
      - "8123:8123"   # HTTP interface (clickhouse-connect)
      - "9009:9000"   # Native protocol (внешний 9009, т.к. 9000 занят MinIO)
    volumes:
      - chdata:/var/lib/clickhouse

volumes:
  pgdata:
  miniodata:
  chdata:
```
