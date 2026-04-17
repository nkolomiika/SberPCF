# CONTEXT_ARCH.md — Контекст проекта SberPCF

> **Назначение файла:** сохранение рабочего контекста AI-агента для быстрого восстановления состояния в новых сессиях.  
> **Дата последнего обновления:** 2026-04-15  
> **Ссылка на историю чата:** [Основной чат разработки](995b8c89-6c62-4a95-8f79-60e5fbd217ea)

---

## 1. Что такое этот проект

**SberPCF** — внутренняя платформа для управления пентест-проектами (Pentest Collaboration Framework).  
Система предназначена для команд пентестеров Сбера. Позволяет:
- вести проекты и назначать участников;
- описывать инфраструктуру (хосты, порты, сервисы, эндпоинты);
- регистрировать уязвимости с привязкой к активам;
- загружать файлы-доказательства (скриншоты, логи) в MinIO;
- оставлять комментарии с @-упоминаниями;
- получать in-app уведомления;
- синхронизировать работу через WebSocket (реальное время);
- импортировать данные из собственного PCF-JSON;
- генерировать отчёты (Markdown / PDF / DOCX);
- вести audit log всех действий.

**Система закрытая**: самостоятельная регистрация недоступна. Аккаунты создаёт только Администратор.

---

## 2. Технологический стек

| Слой | Технология | Версия (requirements.txt) |
|------|-----------|--------------------------|
| Backend | Python + FastAPI | fastapi 0.115.5 |
| ASGI-сервер | Uvicorn | 0.32.1 |
| ORM | SQLAlchemy (async) | 2.0.36 |
| БД-драйвер | asyncpg | 0.30.0 |
| Миграции | Alembic | 1.14.0 |
| Валидация конфига | pydantic-settings | 2.6.1 |
| Аутентификация | python-jose (JWT) | 3.3.0 |
| Хэширование паролей | passlib[bcrypt] + bcrypt | 1.7.4 / 4.0.1 |
| Файлы (S3-совместимо) | MinIO SDK | 7.2.12 |
| MIME-детект | python-magic | 0.4.27 |
| Отчёты DOCX | python-docx | 1.1.2 |
| Отчёты PDF | reportlab | 4.2.5 |
| Отчёты MD | markdown | 3.7 |
| HTTP-клиент (тесты) | httpx | 0.28.0 |
| Тесты | pytest + pytest-asyncio | 8.3.4 / 0.24.0 |
| База данных | PostgreSQL | 16-alpine |
| **Хранилище аудит-логов** | **ClickHouse** | 24-alpine |
| ClickHouse Python-клиент | clickhouse-connect | (добавить в requirements.txt) |
| Хранилище файлов | MinIO | latest |
| Frontend | React + TypeScript | (Vite, см. frontend/) |
| HTTP-клиент FE | Axios | withCredentials: true |
| Контейнеризация | Docker Compose | v3+ |

---

## 3. Аутентификация — ВАЖНО

**Используются httpOnly cookies, НЕ Bearer токены.**

- `access_token` — короткоживущий JWT, передаётся в httpOnly cookie.
- `refresh_token` — долгоживущий JWT, передаётся в httpOnly cookie.
- CSRF-защита: `SameSite=Strict` + проверка заголовка `Origin` на бэкенде.
- Хэши refresh-токенов хранятся в таблице `refresh_tokens` (SHA-256, сам токен не хранится).
- При logout / смене пароля все активные refresh-токены пользователя отзываются (`revoked_at`).

### Зависимость FastAPI `get_current_user`
```python
async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")  # НЕ Authorization header
    if not token:
        raise ForbiddenError("Требуется аутентификация")
    ...
```

### Axios (Frontend)
```typescript
axios.defaults.withCredentials = true;  // cookie передаётся автоматически
// НЕТ: axios.defaults.headers.common['Authorization'] = ...
```

### WebSocket аутентификация
Cookie (`access_token`) передаётся браузером автоматически при WS-handshake.  
Параметр `?token=` в URL **не используется**.

---

## 4. Структура проекта

```
SberPCF/
├── ARCH.md              # Архитектура + полная Swagger-документация API
├── CONTEXT_ARCH.md      # Этот файл
├── DB_SCHEMA.md         # Схема БД (таблицы, ER-диаграмма, индексы)
├── DEV_RULES.md         # Правила разработки (Git flow, code style, безопасность)
├── DESIGN.md            # UI/UX дизайн-документ
├── TASK.md              # Техническое задание (источник правды)
├── TEST_CASES.md        # Тест-кейсы для QA (~169 кейсов, ~85% покрытие)
├── docker-compose.yml   # Оркестрация контейнеров
├── .env / .env.example  # Переменные окружения
├── .gitignore
├── backend/
│   ├── Dockerfile
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── migrations/      # Alembic миграции
│   ├── tests/
│   │   ├── test_security.py
│   │   └── test_dependencies.py
│   └── app/
│       ├── main.py          # Точка входа FastAPI, подключение роутеров
│       ├── config.py        # pydantic-settings конфиг
│       ├── database.py      # async engine, session factory, Base
│       ├── models.py        # SQLAlchemy ORM модели
│       ├── schemas.py       # Pydantic схемы (request/response)
│       ├── enums.py         # Python Enum-классы
│       ├── dependencies.py  # DI: get_current_user, get_db, get_current_admin
│       ├── exceptions.py    # Кастомные HTTP-исключения
│       ├── security.py      # JWT create/verify, bcrypt helpers
│       ├── services.py      # Бизнес-логика (Service Layer)
│       ├── pagination.py    # Offset pagination helper
│       ├── ws_manager.py    # WebSocket ConnectionManager
│       ├── storage/
│       │   └── minio_client.py
│       └── routers/
│           ├── auth.py
│           ├── users.py
│           ├── projects.py
│           ├── assets.py          # hosts / ports / services / endpoints
│           ├── vulnerabilities.py
│           ├── files.py
│           ├── comments.py
│           ├── notifications.py
│           ├── import_.py
│           ├── reports.py
│           ├── audit_logs.py
│           └── websocket.py
└── frontend/
    ├── src/
    │   ├── main.tsx
    │   ├── App.tsx
    │   ├── api.ts           # Axios instance с interceptors
    │   ├── store.ts         # Глобальный state (Context API / custom hooks)
    │   ├── types.ts         # TypeScript типы
    │   ├── components/
    │   │   └── ProjectTreeNav.tsx
    │   └── pages/
    │       ├── LoginPage.tsx
    │       ├── ProjectsPage.tsx
    │       ├── ProjectDetailPage.tsx
    │       └── HostDetailPage.tsx
    └── (Vite config, package.json, tsconfig.json...)
```

---

## 5. Docker Compose

```yaml
services:
  backend:    # FastAPI, порт 8000
  frontend:   # React/Vite, порт 3000
  db:         # PostgreSQL 16, порт 5433:5432 (внешний 5433)
  minio:      # MinIO, порт 9000 (API) + 9001 (Console)
  clickhouse: # ClickHouse 24, порт 8123 (HTTP) + 9009:9000 (Native)
```

**Volumes:** `pgdata` (PostgreSQL), `miniodata` (MinIO), `chdata` (ClickHouse)

---

## 6. База данных — все таблицы

### PostgreSQL таблицы

| Таблица | Назначение |
|---------|-----------|
| `users` | Пользователи (admin / pentester) |
| `refresh_tokens` | SHA-256 хэши refresh JWT, отзыв при logout/смене пароля |
| `projects` | Пентест-проекты |
| `project_members` | M2M: пользователи ↔ проекты |
| `hosts` | Хосты инфраструктуры (ip_address или hostname, или оба) |
| `ports` | Порты хоста (unique: host+port+protocol) |
| `services` | Сервисы на порту |
| `endpoints` | HTTP-эндпоинты, привязаны к хосту |
| `vulnerabilities` | Уязвимости, привязаны к проекту |
| `vulnerability_assets` | Полиморфная привязка уязвимости к активу (host/port/service/endpoint) |
| `files` | Метаданные файлов; сами файлы в MinIO (limit: 52428800 байт = 50 МБ) |
| `comments` | Комментарии к уязвимостям (редактируемые/удаляемые автором) |
| `comment_mentions` | M2M: комментарии ↔ упомянутые пользователи |
| `notifications` | In-app уведомления при @-упоминании |

### ClickHouse таблицы (`pcf_logs`)

| Таблица | Назначение |
|---------|-----------|
| `audit_logs` | Журнал действий пользователей (append-only, MergeTree, партиционирование по месяцу) |

**Ключевые поля:** `id` (UUID), `user_id`, `action`, `entity_type`, `entity_id`, `details` (JSON-строка), `ip_address`, `created_at` (DateTime64)  
**Движок:** `MergeTree() PARTITION BY toYYYYMM(created_at) ORDER BY (created_at, action)`

### Ключевые enum-типы (из `enums.py`)

| Enum | Значения |
|------|---------|
| `UserRole` | `admin`, `pentester` |
| `ProjectStatus` | `active`, `completed`, `archived` |
| `HostStatus` | `up`, `down`, `unknown` |
| `Protocol` | `tcp`, `udp` |
| `PortState` | `open`, `closed`, `filtered` |
| `HttpMethod` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `CvssVersion` | `3.1`, `4.0` |
| `VulnerabilityStatus` | `open`, `in_progress`, `fixed`, `wont_fix`, `accepted_risk` |
| `AssetType` | `host`, `port`, `service`, `endpoint` |
| `NotificationType` | `mention` |

---

## 7. API — общие соглашения

- Префикс: `/api/v1/`
- Аутентификация: httpOnly cookie `access_token` (автоматически)
- Пагинация: offset-based `?page=1&size=20`
- Формат ошибок:
  ```json
  { "detail": "Описание ошибки" }
  ```
- Стандартные коды: `400`, `401`, `403`, `404`, `409`, `422`
- Комментарии в коде — на **русском языке**

### Auth endpoints (Set-Cookie)
| Метод | Путь | Описание |
|-------|------|---------|
| POST | `/api/v1/auth/login` | Логин → Set-Cookie: access_token + refresh_token |
| POST | `/api/v1/auth/refresh` | Обновление access_token по refresh_token cookie |
| POST | `/api/v1/auth/logout` | Очистка cookies + отзыв refresh_token |
| GET | `/api/v1/auth/me` | Текущий пользователь |

### Основные ресурсы
| Ресурс | Базовый путь |
|--------|-------------|
| Пользователи | `/api/v1/users/` (только admin) |
| Проекты | `/api/v1/projects/` |
| Хосты | `/api/v1/projects/{id}/hosts/` |
| Порты | `/api/v1/hosts/{id}/ports/` |
| Сервисы | `/api/v1/ports/{id}/services/` |
| Эндпоинты | `/api/v1/hosts/{id}/endpoints/` |
| Уязвимости | `/api/v1/projects/{id}/vulnerabilities/` |
| Активы уязвимости | `/api/v1/vulnerabilities/{id}/assets/` |
| Файлы | `/api/v1/vulnerabilities/{id}/files/` |
| Комментарии | `/api/v1/vulnerabilities/{id}/comments/` |
| Уведомления | `/api/v1/notifications/` |
| Импорт | `/api/v1/projects/{id}/import/` |
| Отчёты | `/api/v1/projects/{id}/reports/` (format: md/pdf/docx) |
| Audit logs | `/api/v1/audit-logs/` (только admin) |
| WebSocket | `ws://host/ws/projects/{project_id}` |

---

## 8. Архитектурные паттерны

### Backend
- **Layered Architecture**: Router → Service → Repository → Model
- **Repository Pattern**: доступ к данным инкапсулирован в сервисах
- **Service Layer**: бизнес-логика отделена от роутеров
- **Dependency Injection**: FastAPI `Depends()` для сессии БД и текущего пользователя
- **Factory Pattern**: генерация отчётов разных форматов
- **Decorator Pattern**: запись audit logs через декоратор/middleware
- **WebSocket ConnectionManager**: `ws_manager.py` управляет подключениями по `project_id`

### Frontend
- **Context API + Custom Hooks**: глобальный state
- **Axios Interceptors**: автоматический refresh при 401
- **Feature-based structure**: страницы сгруппированы по фичам

---

## 9. Правила разработки (DEV_RULES.md)

- **Git flow**: `main` + `develop` + `feature/*` + `hotfix/*`
- **Коммиты**: Conventional Commits (`feat:`, `fix:`, `docs:` и т.д.)
- **Pull Request**: обязателен ревью минимум 1 человека
- **Комментарии в коде**: только на **русском языке**
- **Docstrings**: обязательны для всех публичных функций/классов
- **Linting**: `ruff` + `black` + `mypy` (backend), `eslint` + `prettier` + `tsc` (frontend)
- **Тесты**: минимум 70% покрытие сервисного слоя
- **Запрещено**:
  - Хранить токены в `localStorage` / `sessionStorage`
  - Передавать токен в URL (`?token=...`)
  - Вручную устанавливать `Authorization: Bearer`
  - Хардкодить секреты
  - SELECT * (использовать явный список колонок)
  - N+1 запросы (использовать joinedload/selectinload)

---

## 10. Безопасность

| Угроза | Защита |
|--------|--------|
| XSS | httpOnly cookie (JS не имеет доступа к токену) |
| CSRF | SameSite=Strict + проверка Origin header |
| SQLi | SQLAlchemy ORM / параметризованные запросы |
| IDOR | Проверка принадлежности ресурса к проекту на каждый запрос |
| Утечка токена | Токен только в cookie, не в теле/URL/localStorage |
| Brute-force | Rate limiting (рекомендовано на nginx/reverse proxy) |
| Секреты | Только через `.env` + `pydantic-settings` |

---

## 11. Файлы документации

| Файл | Описание | Строк |
|------|---------|-------|
| `TASK.md` | Техническое задание | ~300 |
| `DB_SCHEMA.md` | Схема БД, ERD, индексы | ~400 |
| `ARCH.md` | Архитектура + полная API-документация (Swagger-style) | ~1000+ |
| `DEV_RULES.md` | Правила разработки | ~400 |
| `DESIGN.md` | UI/UX дизайн | 466 |
| `TEST_CASES.md` | 169 тест-кейсов QA (~85% покрытие) | 2236 |

---

## 12. Что было реализовано (backend)

Реализованы (scaffolded) все роутеры, модели, схемы. Структура кода существует в:
- `backend/app/models.py` — все ORM модели
- `backend/app/enums.py` — все enum-типы
- `backend/app/routers/` — все 12 роутеров
- `backend/app/services.py` — бизнес-логика
- `backend/app/security.py` — JWT/bcrypt
- `backend/app/ws_manager.py` — WebSocket manager
- `backend/app/storage/minio_client.py` — MinIO клиент
- `backend/tests/` — unit-тесты

## 13. Что было реализовано (frontend)

- `frontend/src/pages/LoginPage.tsx` — страница входа
- `frontend/src/pages/ProjectsPage.tsx` — список проектов
- `frontend/src/pages/ProjectDetailPage.tsx` — детали проекта
- `frontend/src/pages/HostDetailPage.tsx` — детали хоста
- `frontend/src/components/ProjectTreeNav.tsx` — навигация по дереву проекта
- `frontend/src/api.ts` — Axios instance
- `frontend/src/store.ts` — глобальный state
- `frontend/src/types.ts` — TypeScript типы

---

## 14. Нерешённые вопросы / возможные следующие шаги

- [ ] Запустить и проверить стек через `docker compose up --build`  
      (ранее была ошибка: Docker Desktop не был запущен)
- [ ] Настроить Alembic миграции и применить к PostgreSQL БД
- [ ] Инициализировать ClickHouse: создать БД `pcf_logs` и таблицу `audit_logs` (DDL-скрипт в `backend/infrastructure/clickhouse_init.sql`)
- [ ] Добавить `clickhouse-connect` в `requirements.txt`
- [ ] Добавить `CLICKHOUSE_*` переменные в `.env` и `.env.example`
- [ ] Обновить `docker-compose.yml` — добавить сервис `clickhouse` и volume `chdata`
- [ ] Реализовать `backend/app/infrastructure/clickhouse_client.py`
- [ ] Дописать реализацию сервисного слоя (`services.py`)
- [ ] Дописать frontend-страницы (уязвимости, файлы, комментарии, отчёты)
- [ ] Добавить e2e тесты
- [ ] Настроить CI/CD pipeline
- [ ] Реализовать rate limiting на уровне nginx

---

## 15. Переменные окружения (`.env.example`)

```env
# PostgreSQL
DATABASE_URL=postgresql+asyncpg://user:password@db:5432/pcf

# JWT
SECRET_KEY=your-super-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# MinIO
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET=pcf-files
MINIO_SECURE=false

# ClickHouse
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_DB=pcf_logs
```
