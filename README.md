# PCF — Pentest Collaboration Framework

Полнофункциональное веб-приложение для совместной работы команды пентестеров.

## Что реализовано

- Backend на FastAPI (`/api/v1`) с JWT-аутентификацией через `httpOnly` cookie.
- PostgreSQL + SQLAlchemy + Alembic миграции.
- MinIO для хранения файлов доказательной базы.
- WebSocket-синхронизация CRUD-изменений по проектам.
- Импорт инфраструктуры из JSON-формата PCF (атомарно: ошибка = полный rollback).
- Генерация отчётов в форматах `md`, `pdf`, `docx`.
- Frontend на React + TypeScript + MUI.

## Быстрый старт

1. Скопируйте `.env.example` в `.env` (уже создано с локальными значениями).
2. Запустите:

```bash
docker compose up --build
```

3. Откройте:
- Frontend: `http://localhost:3000`
- Backend docs: `http://localhost:8000/docs`
- MinIO console: `http://localhost:9001`

## Учётные данные администратора

- Логин: `admin`
- Пароль: `admin`

(создаётся автоматически при первом старте, если таблица `users` пуста)
