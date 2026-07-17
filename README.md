# PCF — Pentest Collaboration Framework

Внутренняя платформа для совместной работы команды пентестеров.
Закрытая система — самостоятельной регистрации нет, аккаунты создаёт администратор.

## Возможности

- **Проекты и оргструктура**: проекты с папками, статусами и сроками; аккаунтная роль `admin / pentester` и проектная роль `lead / pentester` — обе глобальные и настраиваются только на странице `/members`. `lead` не даёт доступа к проекту сам по себе: он лишь открывает дополнительные возможности в тех проектах, где пользователь является участником.
- **Доступ по участию**: не-админ видит только те проекты, где он участник; состав команды правят админ, лид проекта или его создатель.
- **Инвентарь**: хосты (несколько IP), порты, сервисы, HTTP endpoints; импорт OpenAPI/Swagger.
- **Уязвимости**: CVSS 4.0 с авторасчётом из вектора (бэкенд — источник истины), workflow_steps, severity, статусы.
- **Активность проекта**: лента событий по проекту, видна всем его участникам.
- **Доказательная база**: evidence-файлы в MinIO (до 50 МБ, whitelist MIME).
- **Комментарии с `@mention`** и in-app уведомления + real-time push через WebSocket.
- **Confluence-like заметки** проекта с обсуждениями.
- **Word-отчёты** (кнопка «Generate report» на странице проекта): «Отчёт для сертификации» (СЗИ, `POST /projects/{id}/reports/szi`) и «Отчёт внутренней приёмки» (ПП, landscape, `POST /projects/{id}/reports/pp`).
- **Jira-интеграция**: экспорт уязвимости в issue (SSRF + DNS-rebind защита).
- **Audit-журнал** в PostgreSQL с фильтрами и full-text поиском.
- **Machine API `/v2`** для AI-агентов: bearer-токены, скоупы, white-list проектов.
- **Mail outbox**: RabbitMQ + воркер `aiosmtplib` (Gmail / корпоративный SMTP через `.env`).

## Стек

Backend: Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, Pydantic 2, JWT (cookie), bcrypt.
Storage: PostgreSQL 16, MinIO, RabbitMQ.
Frontend: React 18 + TypeScript + Vite 6, MUI 6, Zustand, TipTap, axios.

## Быстрый старт

```bash
cp .env.example .env
# при необходимости поправьте SMTP-секцию (mailpit / Gmail / корпоративный)
docker compose up --build
```

- Frontend: `https://localhost` или `https://localhost:3000`
  (перед приложением стоит nginx с самоподписанным сертификатом — браузер один раз спросит подтверждение)
- **HTTP автоматически редиректится на HTTPS**: `http://localhost` → `https://localhost`,
  `http://localhost:3000` → `https://localhost:3000`
- Backend Swagger: `http://localhost:8000/docs` (`/api/v1`), `http://localhost:8000/v2/docs` (агентский `/v2`)
- MinIO console: `http://localhost:9001` (`minioadmin` / `minioadmin`)
- Mailpit (dev SMTP): `http://localhost:8025`
- RabbitMQ management: `http://localhost:15672` (`guest` / `guest`)

## Учётные записи (локальный dev)

Стартовый админ создаётся при первом запуске из `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` в `.env`.
Демо-команду создаёт `backend/scripts/reset_and_seed.py`. Вход — по **username** (не по email).

| Логин | Пароль | Глобальная роль | Email |
|---------|---------|-----------|---------------------|
| `admin` | `admin` | admin | admin@example.com |
| `alice` | `admin` | pentester | alice@example.com |
| `bob` | `admin` | pentester | bob@example.com |
| `charlie` | `admin` | pentester | charlie@example.com |
| `diana` | `admin` | pentester | diana@example.com |
| `eve` | `admin` | pentester | eve@example.com |

> ⚠️ Это дефолты **только для локальной разработки**. На любом общем стенде смените пароли
> и `INITIAL_ADMIN_PASSWORD` в `.env`.

### Роли и доступ

- **admin** — видит все проекты, управляет пользователями, проектами и составом команд.
- **pentester** — видит **только** проекты, в которых он участник; в чужой проект доступа нет (403).
- **lead** — роль **внутри проекта**, а не глобальная: лид остаётся обычным пользователем
  (`pentester`), но может управлять составом команды своего проекта.
  Добавлять/удалять участников может: **админ, лид проекта или его создатель**.

Пересоздать демо-данные (пользователи сохраняются):

```bash
docker compose exec backend python scripts/reset_and_seed.py
```

В сиде первый участник каждого проекта назначается лидом — например, `alice` является
лидом в своих проектах, а `bob` в них же — обычный участник.

## Документация

| Файл | Содержание |
|------|-----------|
| [CONTEXT_ARCH.md](CONTEXT_ARCH.md) | Короткая ориентация для AI-агента / нового разработчика |
| [ARCH.md](ARCH.md) | Архитектура, сервисы, роутеры, API |
| [ARCH_DIAGRAMS.md](ARCH_DIAGRAMS.md) | Подробные Mermaid-диаграммы по каждому компоненту |
| [DB_SCHEMA.md](DB_SCHEMA.md) | Схема БД (таблицы, ERD, индексы) |
| [DESIGN.md](DESIGN.md) | UI/UX дизайн-документ |
| [DEV_RULES.md](DEV_RULES.md) | Правила разработки (стиль, безопасность, git flow) |
| [USE_CASES.md](USE_CASES.md) | Сценарии использования по ролям |
| [TASK.md](TASK.md) | Чек-лист реализованного и backlog |
| [TEST_CASES.md](TEST_CASES.md) | Тест-кейсы QA |
| [docs/openapi-v1.json](docs/openapi-v1.json) | Swagger / OpenAPI 3.1 — `/api/v1` (cookie-auth) |
| [docs/openapi-v2.json](docs/openapi-v2.json) | Swagger / OpenAPI 3.1 — `/v2` (Bearer для AI-агентов) |
| [docs/README.md](docs/README.md) | Как пересоздать OpenAPI-файлы |
