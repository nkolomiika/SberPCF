# PCF — Pentest Collaboration Framework

Внутренняя платформа Сбера для совместной работы команды пентестеров.
Закрытая система — самостоятельной регистрации нет, аккаунты создаёт администратор.

## Возможности

- **Проекты и оргструктура**: проекты с папками, статусами и сроками; роли `admin / pentester / developer`.
- **Инвентарь**: хосты (несколько IP), порты, сервисы, HTTP endpoints; импорт OpenAPI/Swagger.
- **Уязвимости**: CVSS v3.1/v4.0 с авторасчётом из вектора, workflow_steps, severity, статусы.
- **Доказательная база**: evidence-файлы в MinIO (до 50 МБ, whitelist MIME).
- **Комментарии с `@mention`** и in-app уведомления + real-time push через WebSocket.
- **Confluence-like заметки** проекта с обсуждениями.
- **Word-отчёты**: «План пентеста» (ПП, landscape) и «Состояние защищённости» (СЗИ).
- **Jira-интеграция**: экспорт уязвимости в issue (SSRF + DNS-rebind защита).
- **Audit-журнал** в PostgreSQL с фильтрами и full-text поиском.
- **Machine API `/api/v2`** для AI-агентов: bearer-токены, скоупы, white-list проектов.
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

- Frontend: `https://localhost:3000`
- Backend Swagger: `http://localhost:8000/docs` (`/api/v1`), `http://localhost:8000/api/v2/docs`
- MinIO console: `http://localhost:9001` (`minioadmin` / `minioadmin`)
- Mailpit (dev SMTP): `http://localhost:8025`
- RabbitMQ management: `http://localhost:15672` (`guest` / `guest`)

## Стартовый администратор

При первом запуске создаётся `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` из `.env`.
Дефолт: `admin` / `admin` (поменяйте при первом входе).

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
| [docs/openapi-v2.json](docs/openapi-v2.json) | Swagger / OpenAPI 3.1 — `/api/v2` (Bearer для AI-агентов) |
| [docs/README.md](docs/README.md) | Как пересоздать OpenAPI-файлы |
