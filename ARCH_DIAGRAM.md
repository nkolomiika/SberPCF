# PCF — Архитектурные диаграммы

Сопровождает [`ARCH.md`](./ARCH.md). Все диаграммы выполнены в Mermaid.

---

## 1. Архитектура контейнеров (Docker Compose)

```mermaid
graph LR
    User([Пользователь / Браузер])
    Agent([AI-агент])

    subgraph Frontend["Frontend (Vite + React, HTTPS:3000)"]
        FE[React SPA]
    end

    subgraph Backend["Backend (FastAPI, :8000)"]
        APIv1["/api/v1<br/>cookie JWT"]
        APIv2["/api/v2<br/>Bearer token"]
        WS["/ws/* WebSocket"]
    end

    subgraph Worker["mail-worker"]
        MW[mail_worker.py]
    end

    PG[(PostgreSQL<br/>основная БД)]
    CH[(ClickHouse<br/>audit logs)]
    MinIO[(MinIO<br/>files / avatars)]
    MQ{{RabbitMQ<br/>pcf.mail}}
    SMTP[Mailpit / SMTP]
    Jira[(Jira REST API)]

    User -->|HTTPS| FE
    FE -->|"/api proxy"| APIv1
    FE -->|"/ws proxy"| WS
    Agent -->|Bearer| APIv2

    APIv1 --> PG
    APIv2 --> PG
    WS --> PG

    APIv1 --> MinIO
    APIv1 --> CH
    APIv1 -->|publish MailJob| MQ
    APIv1 -.->|httpx, server-only| Jira

    MQ --> MW
    MW --> PG
    MW --> SMTP
```

---

## 2. Backend layered diagram

```mermaid
graph TB
    subgraph Routers["Routers (app/routers/*)"]
        R_auth[auth]
        R_users[users]
        R_proj[projects]
        R_notes[project_notes]
        R_assets[assets]
        R_vuln[vulnerabilities]
        R_files[files]
        R_comm[comments]
        R_notif[notifications]
        R_imp[import_]
        R_jira[jira]
        R_rep[reports]
        R_aud[audit_logs]
        R_at[agent_tokens]
        R_v2[v2_agent]
        R_ws[websocket]
    end

    subgraph Deps["Dependencies (app/dependencies.py)"]
        D_user[get_current_user]
        D_admin[require_admin]
        D_proj[require_project_access]
        D_csrf[enforce_csrf]
        D_agent["get_agent_token_context<br/>require_agent_scope<br/>require_agent_project_access"]
    end

    subgraph Services["Services (app/services.py — один файл)"]
        S_auth[AuthService]
        S_user[UserService]
        S_proj[ProjectService]
        S_asset[AssetService]
        S_vuln[VulnerabilityService]
        S_file[FileService]
        S_comm[CommentService]
        S_notes[ProjectNoteService]
        S_notif[NotificationService]
        S_imp[ImportService]
        S_rep[ReportService]
        S_aud[AuditService]
        S_at[AgentTokenService]
        S_jira[JiraIntegrationService]
    end

    subgraph Infra["Infra layer"]
        Models["models.py<br/>(SQLAlchemy)"]
        Schemas["schemas.py<br/>(Pydantic)"]
        DB[(PostgreSQL)]
        Mn[(MinIO)]
        Ch[(ClickHouse)]
        Mq{{RabbitMQ}}
        WSM[ws_manager]
    end

    Routers --> Deps
    Routers --> Services
    Routers --> Schemas
    Services --> Models
    Services --> Mn
    Services --> Ch
    Services --> Mq
    Services --> WSM
    Models --> DB
```

---

## 3. ER-диаграмма ключевых сущностей (краткая)

```mermaid
erDiagram
    User ||--o{ ProjectMember : "входит"
    User ||--o{ Project : "created_by"
    User ||--o{ RefreshToken : "владеет"
    User ||--o{ AgentApiToken : "created_by"
    User ||--o{ Notification : "получает"

    Project ||--o{ ProjectMember : "имеет"
    Project ||--o{ ProjectNote : "содержит"
    Project ||--o{ Host : "содержит"
    Project ||--o{ Vulnerability : "содержит"
    Project ||--o| ProjectJiraLink : "привязан к Jira"

    ProjectFolder ||--o{ ProjectFolder : "иерархия"

    ProjectNote ||--o{ ProjectNote : "иерархия"
    ProjectNote ||--o{ ProjectNoteComment : "комментарии"

    Host ||--o{ HostIpAddress : "несколько IP"
    Host ||--o{ Port : "порты"
    Host ||--o{ Endpoint : "HTTP endpoints"
    Port ||--o{ Service : "сервисы"

    Vulnerability ||--o{ VulnerabilityAsset : "привязана к активам"
    Vulnerability ||--o{ Comment : "обсуждение"
    Vulnerability ||--o{ File : "evidence"
    Vulnerability ||--o| JiraIssueLink : "Jira issue"

    Comment ||--o{ CommentMention : "@mentions"
    CommentMention }o--|| User : "упомянут"
    Notification }o--|| Comment : "ссылается"

    AgentApiToken ||--o{ AgentApiTokenProjectGrant : "доступ к проектам"
    AgentApiTokenProjectGrant }o--|| Project : "грант"

    JiraInstance ||--o{ ProjectJiraLink : "глобальный конфиг"

    User {
        uuid id PK
        string username
        string email
        enum role "admin/lead/pentester/developer"
        bool must_change_password
    }
    Project {
        uuid id PK
        string name
        string folder
        enum status
        datetime timeline_frozen_at
    }
    Vulnerability {
        uuid id PK
        string title
        enum severity
        enum status
        json workflow_steps
        decimal cvss_score
    }
    Host {
        uuid id PK
        string ip_address "primary IP, для совместимости"
        string hostname
    }
    AgentApiToken {
        uuid id PK
        string token_hash "SHA-256"
        string token_prefix
        json scopes
        bool all_projects
        datetime expires_at
        datetime revoked_at
    }
```

---

## 4. Auth: login + refresh с ротацией

```mermaid
sequenceDiagram
    autonumber
    participant FE as Frontend (axios, withCredentials)
    participant API as Backend /api/v1/auth
    participant DB as PostgreSQL

    Note over FE,API: Login

    FE->>API: POST /auth/login {username, password}<br/>Origin: https://localhost:3000
    API->>API: enforce_csrf (Origin in csrf_origins)
    API->>DB: SELECT User by username
    API->>API: bcrypt verify_password
    API->>DB: INSERT RefreshToken (hash = SHA256(refresh))
    API-->>FE: 200 + Set-Cookie:<br/>access_token (HttpOnly, Secure, /, 30 min)<br/>refresh_token (HttpOnly, Secure, /api/v1/auth/refresh, 30 days)

    Note over FE,API: Обычный запрос

    FE->>API: GET /api/v1/projects (cookie access_token)
    API->>API: get_current_user (decode JWT)
    API-->>FE: 200 OK

    Note over FE,API: Access истёк → refresh с ротацией

    FE->>API: POST /api/v1/auth/refresh (cookie refresh_token)
    API->>API: enforce_csrf
    API->>DB: SELECT RefreshToken WHERE token_hash=SHA256(rt) AND revoked_at IS NULL
    alt токен валиден
        API->>DB: UPDATE old RefreshToken SET revoked_at=now()
        API->>DB: INSERT new RefreshToken (rotation)
        API-->>FE: 200 + Set-Cookie новые access/refresh
    else токен уже отозван (reuse detected)
        API->>DB: UPDATE RefreshToken SET revoked_at=now()<br/>WHERE user_id=? AND revoked_at IS NULL
        Note right of API: Отзыв ВСЕХ активных<br/>refresh пользователя
        API-->>FE: 401 Unauthorized
    end
```

---

## 5. WebSocket flow: уведомление о @mention

```mermaid
sequenceDiagram
    autonumber
    participant U1 as User1 (комментирует)
    participant U2 as User2 (упомянут)
    participant FE1 as FE U1
    participant FE2 as FE U2 (открыто WS)
    participant API as Backend
    participant WS as ws_manager
    participant DB as PostgreSQL

    Note over FE2,WS: U2 ранее открыл WS<br/>WS /ws/notifications (auth по cookie)
    FE2->>API: WS connect /ws/notifications
    API->>API: _authenticate_websocket_user (JWT cookie)
    API->>WS: connect_user(user2_id, ws)

    Note over U1,API: U1 пишет комментарий с @user2

    U1->>FE1: ввод "@user2 посмотри"
    FE1->>API: POST /projects/{pid}/vulnerabilities/{vid}/comments<br/>{content: "@user2 посмотри"}
    API->>DB: INSERT Comment, CommentMention, Notification
    API->>WS: broadcast(project_id, comment.created)
    API->>WS: notify_user(user2_id, notification.created)
    WS-->>FE2: WS event {type: notification, ...}
    FE2->>FE2: showToast + bump unread badge

    Note over U2,FE2: User2 видит уведомление в реальном времени
```

---

## 6. Agent API v2 — поток вызова

```mermaid
sequenceDiagram
    autonumber
    participant Agent as AI-агент
    participant V2 as /api/v2 (FastAPI sub-app)
    participant DB as PostgreSQL
    participant Svc as ProjectNoteService

    Agent->>V2: POST /api/v2/projects/{pid}/notes<br/>Authorization: Bearer pcf_xxx...
    V2->>V2: get_agent_token_context<br/>(SHA256(token) → AgentApiToken)
    V2->>DB: lookup AgentApiToken<br/>check revoked_at, expires_at
    V2->>V2: require_agent_scope("notes:write")
    V2->>V2: require_agent_project_access(pid)<br/>(all_projects OR project in grants)
    V2->>DB: UPDATE AgentApiToken SET last_used_at=now()
    V2->>Svc: create_note(...)
    Svc->>DB: INSERT ProjectNote
    V2-->>Agent: 201 Created + ProjectNoteOut
```
