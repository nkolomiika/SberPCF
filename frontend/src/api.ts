import axios from "axios";
import type {
  AuthLoginResponse,
  VulnerabilityComment,
  VulnerabilityDetails,
  VulnerabilityFile,
  Endpoint,
  EndpointRequestHeader,
  Service,
  AuditLog,
  Host,
  HostDetails,
  ImportResult,
  OpenApiImportResult,
  Notification,
  OsType,
  PaginatedResponse,
  Port,
  Project,
  ProjectActivityItem,
  ProjectFolder,
  ProjectMember,
  ProjectStats,
  PasswordResetResult,
  User,
  ProjectNote,
  ProjectNoteComment,
  Vulnerability,
  VulnerabilityAsset,
  AgentApiToken,
} from "./types";

const api = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
});

const isBlank = (value: string | null | undefined): boolean => !value || value.trim().length === 0;

const assertRequired = (value: string | null | undefined, label: string): void => {
  if (isBlank(value)) {
    throw new Error(`Поле "${label}" обязательно`);
  }
};

const normalizeDetailMessage = (detail: unknown): string | null => {
  if (typeof detail === "string" && detail.trim()) {
    return detail.trim();
  }
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => normalizeDetailMessage(item)).filter((item): item is string => Boolean(item));
    return messages.length ? messages.join("; ") : null;
  }
  if (detail && typeof detail === "object") {
    if ("detail" in detail) {
      return normalizeDetailMessage((detail as { detail?: unknown }).detail);
    }
    if ("message" in detail) {
      return normalizeDetailMessage((detail as { message?: unknown }).message);
    }
  }
  return null;
};

/** HTTP-статус ошибки axios, если он есть (403 → показываем экран «нет доступа»). */
export const getApiErrorStatus = (error: unknown): number | null =>
  axios.isAxiosError(error) ? (error.response?.status ?? null) : null;

export const getApiErrorMessage = (error: unknown, fallback: string): string => {
  if (axios.isAxiosError(error)) {
    const detail = normalizeDetailMessage(error.response?.data);
    const status = error.response?.status;

    // Нет ответа вовсе — сеть/прокси/бэкенд недоступен. Самый частый случай при
    // локальном `npm run dev`, когда прокси указывает на несуществующий хост.
    if (!error.response) {
      if (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT") {
        return "Превышено время ожидания ответа сервера.";
      }
      return "Сервер недоступен — не удалось подключиться к бэкенду. Проверьте, что бэкенд запущен.";
    }

    if (status === 401) return detail || "Неверный логин или пароль.";
    if (status === 403) return detail || "Недостаточно прав для этого действия.";
    if (status === 404) return detail || "Запрашиваемый ресурс не найден.";
    if (status === 409) return detail || "Конфликт: ресурс уже существует или изменён.";
    if (status === 422) return detail || "Проверьте правильность заполнения полей.";
    if (status === 429) return detail || "Слишком много попыток. Попробуйте позже.";
    if (status && status >= 500) {
      // 500/502/503/504 — на сервере/прокси. Если это заглушка прокси Vite,
      // тела с detail обычно нет, поэтому даём понятную подсказку.
      const isGeneric = !detail || detail === "Internal Server Error";
      return isGeneric
        ? `Ошибка сервера (${status}). Возможно, бэкенд недоступен или упал.`
        : `Ошибка сервера (${status}): ${detail}`;
    }

    return detail || normalizeDetailMessage(error.message) || fallback;
  }
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return fallback;
};

let isRefreshing = false;
let waitingQueue: Array<{ resolve: () => void; reject: (error: unknown) => void }> = [];

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const requestUrl = String(originalRequest?.url ?? "");
    // /auth/login и /auth/refresh — сами по себе попытки аутентификации;
    // 401 здесь = «неверные креды / refresh-токен», а не «сессия истекла»,
    // повторный refresh замаскирует настоящую ошибку.
    // /users/me на старте — проверка наличия сессии: 401 ожидаем, без авторефреша.
    const shouldSkipRefresh =
      requestUrl.includes("/auth/login") ||
      requestUrl.includes("/auth/refresh") ||
      requestUrl.includes("/users/me");
    if (error.response?.status === 401 && !originalRequest?._retry && !shouldSkipRefresh) {
      originalRequest._retry = true;
      if (isRefreshing) {
        return new Promise<void>((resolve, reject) => waitingQueue.push({ resolve, reject })).then(() => api(originalRequest));
      }
      isRefreshing = true;
      try {
        await api.post("/auth/refresh");
        waitingQueue.forEach((entry) => entry.resolve());
        waitingQueue = [];
        return api(originalRequest);
      } catch (refreshError) {
        waitingQueue.forEach((entry) => entry.reject(refreshError));
        waitingQueue = [];
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  }
);

export async function login(username: string, password: string): Promise<AuthLoginResponse> {
  assertRequired(username, "Имя пользователя");
  assertRequired(password, "Пароль");
  const { data } = await api.post<AuthLoginResponse>("/auth/login", { username, password });
  return data;
}

export async function logout(): Promise<void> {
  await api.post("/auth/logout");
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>("/users/me");
  return data;
}

export async function getUsers(page = 1, size = 200): Promise<PaginatedResponse<User>> {
  const { data } = await api.get<PaginatedResponse<User>>("/users", { params: { page, size } });
  return data;
}

export async function createUser(payload: {
  username: string;
  email: string;
  full_name?: string;
  password?: string;
  role: User["role"];
  project_role?: User["project_role"];
  send_invite_email?: boolean;
}): Promise<User> {
  assertRequired(payload.username, "Имя пользователя");
  assertRequired(payload.email, "Email");
  const { data } = await api.post<User>("/users", payload);
  return data;
}

export async function updateUser(
  userId: number,
  payload: {
    username?: string;
    full_name?: string;
    role?: User["role"];
    project_role?: User["project_role"];
    is_active?: boolean;
  }
): Promise<User> {
  const { data } = await api.put<User>(`/users/${userId}`, payload);
  return data;
}

export async function resetUserPassword(userId: number): Promise<PasswordResetResult> {
  const { data } = await api.patch<PasswordResetResult>(`/users/${userId}/password`);
  return data;
}

export async function deleteUser(userId: number): Promise<void> {
  await api.delete(`/users/${userId}`);
}

export async function updateMyProfile(payload: {
  username?: string;
  email?: string;
  full_name?: string;
}): Promise<User> {
  const { data } = await api.patch<User>("/users/me", payload);
  return data;
}

export async function changeMyPassword(payload: { current_password: string; new_password: string }): Promise<User> {
  assertRequired(payload.current_password, "Текущий пароль");
  assertRequired(payload.new_password, "Новый пароль");
  const { data } = await api.patch<User>("/users/me/password", payload);
  return data;
}

export async function uploadMyAvatar(file: File): Promise<User> {
  if (!file) {
    throw new Error("Файл аватара обязателен");
  }
  const formData = new FormData();
  formData.append("avatar", file);
  const { data } = await api.post<User>("/users/me/avatar", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function getProjects(page = 1, size = 20, status?: Project["status"]): Promise<PaginatedResponse<Project>> {
  const { data } = await api.get<PaginatedResponse<Project>>("/projects", { params: { page, size, status } });
  return data;
}

export async function getProjectStats(): Promise<ProjectStats[]> {
  const { data } = await api.get<ProjectStats[]>("/projects/stats");
  return data;
}

export async function getProjectFolders(): Promise<ProjectFolder[]> {
  const { data } = await api.get<ProjectFolder[]>("/projects/folders");
  return data;
}

export async function createProjectFolder(payload: { name: string; parent_id?: number | null }): Promise<ProjectFolder> {
  assertRequired(payload.name, "Название папки");
  const { data } = await api.post<ProjectFolder>("/projects/folders", payload);
  return data;
}

export async function moveProjectFolder(folderId: number, payload: { parent_id?: number | null }): Promise<ProjectFolder> {
  const { data } = await api.patch<ProjectFolder>(`/projects/folders/${folderId}/move`, payload);
  return data;
}

export interface DeleteProjectFolderResult {
  path: string;
  deleted_folders: number;
  deleted_projects: number;
}

export async function deleteProjectFolder(folderId: number): Promise<DeleteProjectFolderResult> {
  const { data } = await api.delete<DeleteProjectFolderResult>(`/projects/folders/${folderId}`);
  return data;
}

export async function createProject(payload: {
  name: string;
  folder?: string;
  description?: string;
  start_date?: string;
  end_date?: string;
}): Promise<Project> {
  assertRequired(payload.name, "Название проекта");
  const { data } = await api.post<Project>("/projects", payload);
  return data;
}

export async function getProject(projectId: number): Promise<Project> {
  const { data } = await api.get<Project>(`/projects/${projectId}`);
  return data;
}

export async function updateProject(
  projectId: number,
  payload: {
    name?: string;
    folder?: string;
    description?: string;
    start_date?: string;
    end_date?: string;
    status?: Project["status"];
  }
): Promise<Project> {
  const { data } = await api.put<Project>(`/projects/${projectId}`, payload);
  return data;
}

export async function getProjectMembers(projectId: number): Promise<ProjectMember[]> {
  const { data } = await api.get<ProjectMember[]>(`/projects/${projectId}/members`);
  return data;
}

export async function addProjectMember(projectId: number, userId: number): Promise<void> {
  if (!userId) {
    throw new Error("Нужно выбрать пользователя");
  }
  await api.post(`/projects/${projectId}/members`, { user_id: userId });
}

export async function removeProjectMember(projectId: number, userId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/members/${userId}`);
}

/** Лента активности проекта — доступна любому участнику (в отличие от админского /audit-logs). */
export async function getProjectActivity(projectId: number, limit = 50): Promise<ProjectActivityItem[]> {
  const { data } = await api.get<ProjectActivityItem[]>(`/projects/${projectId}/activity`, { params: { limit } });
  return data;
}

export async function listProjectNotes(projectId: number): Promise<ProjectNote[]> {
  const { data } = await api.get<ProjectNote[]>(`/projects/${projectId}/notes`);
  return data;
}

export type ProjectNoteActivity = {
  id: number;
  action: "CREATE" | "UPDATE" | "DELETE";
  note_id: number | null;
  note_title: string | null;
  user_id: number | null;
  username: string | null;
  created_at: string;
};

export async function listProjectNotesActivity(
  projectId: number,
  limit = 30,
): Promise<ProjectNoteActivity[]> {
  const { data } = await api.get<ProjectNoteActivity[]>(
    `/projects/${projectId}/notes-activity`,
    { params: { limit } },
  );
  return data;
}

export async function getProjectNote(projectId: number, noteId: number): Promise<ProjectNote> {
  const { data } = await api.get<ProjectNote>(`/projects/${projectId}/notes/${noteId}`);
  return data;
}

export async function createProjectNote(
  projectId: number,
  payload: { title: string; parent_id?: number | null; content?: string | null }
): Promise<ProjectNote> {
  assertRequired(payload.title, "Название страницы");
  const { data } = await api.post<ProjectNote>(`/projects/${projectId}/notes`, payload);
  return data;
}

export async function updateProjectNote(
  projectId: number,
  noteId: number,
  payload: { title?: string; content?: string | null }
): Promise<ProjectNote> {
  if (payload.title !== undefined) {
    assertRequired(payload.title, "Название страницы");
  }
  const { data } = await api.put<ProjectNote>(`/projects/${projectId}/notes/${noteId}`, payload);
  return data;
}

export async function moveProjectNote(
  projectId: number,
  noteId: number,
  payload: { parent_id?: number | null }
): Promise<ProjectNote> {
  const { data } = await api.patch<ProjectNote>(`/projects/${projectId}/notes/${noteId}/move`, payload);
  return data;
}

export async function reorderProjectNotes(
  projectId: number,
  payload: { parent_id?: number | null; items: Array<{ id: number; sort_order: number }> }
): Promise<ProjectNote[]> {
  if (!payload.items.length) {
    throw new Error("Нужно передать хотя бы одну страницу для сортировки");
  }
  const { data } = await api.patch<ProjectNote[]>(`/projects/${projectId}/notes/reorder`, payload);
  return data;
}

export async function deleteProjectNote(projectId: number, noteId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/notes/${noteId}`);
}

export async function listProjectNoteComments(projectId: number, noteId: number): Promise<PaginatedResponse<ProjectNoteComment>> {
  const { data } = await api.get<PaginatedResponse<ProjectNoteComment>>(`/projects/${projectId}/notes/${noteId}/comments`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createProjectNoteComment(
  projectId: number,
  noteId: number,
  content: string
): Promise<ProjectNoteComment> {
  assertRequired(content, "Комментарий");
  const { data } = await api.post<ProjectNoteComment>(`/projects/${projectId}/notes/${noteId}/comments`, { content });
  return data;
}

export async function updateProjectNoteComment(
  projectId: number,
  noteId: number,
  commentId: number,
  content: string
): Promise<ProjectNoteComment> {
  assertRequired(content, "Комментарий");
  const { data } = await api.put<ProjectNoteComment>(`/projects/${projectId}/notes/${noteId}/comments/${commentId}`, { content });
  return data;
}

export async function deleteProjectNoteComment(projectId: number, noteId: number, commentId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/notes/${noteId}/comments/${commentId}`);
}

export async function deleteProject(projectId: number): Promise<void> {
  await api.delete(`/projects/${projectId}`);
}

export async function getHosts(projectId: number): Promise<PaginatedResponse<Host>> {
  const { data } = await api.get<PaginatedResponse<Host>>(`/projects/${projectId}/hosts`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createHost(
  projectId: number,
  payload: {
    ip_address?: string;
    ip_addresses?: string[];
    hostname?: string;
    notes?: string;
    status?: "up" | "down" | "unknown";
    os_type?: OsType;
  }
): Promise<Host> {
  if (isBlank(payload.ip_address) && isBlank(payload.hostname)) {
    throw new Error('Нужно указать хотя бы "IP-адрес" или "Hostname"');
  }
  const { data } = await api.post<Host>(`/projects/${projectId}/hosts`, payload);
  return data;
}

export async function getHost(projectId: number, hostId: number): Promise<HostDetails> {
  const { data } = await api.get<HostDetails>(`/projects/${projectId}/hosts/${hostId}`);
  return data;
}

export async function updateHost(
  projectId: number,
  hostId: number,
  payload: {
    ip_address?: string;
    ip_addresses?: Array<{ ip_address: string; label?: string | null; is_primary?: boolean }>;
    hostname?: string;
    notes?: string | null;
    status?: "up" | "down" | "unknown";
    os_type?: OsType;
  }
): Promise<Host> {
  const { data } = await api.put<Host>(`/projects/${projectId}/hosts/${hostId}`, payload);
  return data;
}

export async function deleteHost(projectId: number, hostId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}`);
}

export async function getPorts(projectId: number, hostId: number): Promise<Port[]> {
  const { data } = await api.get<Port[]>(`/projects/${projectId}/hosts/${hostId}/ports`);
  return data;
}

export async function createPort(
  projectId: number,
  hostId: number,
  payload: {
    ip_address_id: number;
    port_number: number;
    protocol?: "tcp" | "udp";
    state?: "open" | "closed" | "filtered";
  }
): Promise<Port> {
  if (!Number.isFinite(payload.port_number)) {
    throw new Error("Порт должен быть числом");
  }
  if (!payload.ip_address_id) {
    throw new Error("Не выбран IP-адрес");
  }
  const { data } = await api.post<Port>(`/projects/${projectId}/hosts/${hostId}/ports`, payload);
  return data;
}

export async function updatePort(
  projectId: number,
  hostId: number,
  portId: number,
  payload: {
    ip_address_id?: number;
    port_number?: number;
    protocol?: "tcp" | "udp";
    state?: "open" | "closed" | "filtered";
  }
): Promise<Port> {
  const { data } = await api.put<Port>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`, payload);
  return data;
}

export async function deletePort(projectId: number, hostId: number, portId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`);
}

export async function getServices(projectId: number, hostId: number, portId: number): Promise<Service[]> {
  const { data } = await api.get<Service[]>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`);
  return data;
}

export async function createService(
  projectId: number,
  hostId: number,
  portId: number,
  payload: { name: string; version?: string; banner?: string }
): Promise<Service> {
  assertRequired(payload.name, "Название сервиса");
  const { data } = await api.post<Service>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`, payload);
  return data;
}

export async function updateService(
  projectId: number,
  hostId: number,
  portId: number,
  serviceId: number,
  payload: { name?: string; version?: string; banner?: string }
): Promise<Service> {
  if (payload.name !== undefined) {
    assertRequired(payload.name, "Название сервиса");
  }
  const { data } = await api.put<Service>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`, payload);
  return data;
}

export async function deleteService(projectId: number, hostId: number, portId: number, serviceId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`);
}

export async function getEndpoints(projectId: number, hostId: number): Promise<Endpoint[]> {
  const { data } = await api.get<Endpoint[]>(`/projects/${projectId}/hosts/${hostId}/endpoints`);
  return data;
}

export async function createEndpoint(
  projectId: number,
  hostId: number,
  payload: {
    path?: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";
    description?: string | null;
    request_raw?: string;
    query_params?: { name: string; value?: string | null; required?: boolean; description?: string | null }[];
    request_body?: string | null;
    request_content_type?: string | null;
    request_headers?: EndpointRequestHeader[];
  }
): Promise<Endpoint> {
  if (isBlank(payload.path) && isBlank(payload.request_raw)) {
    throw new Error('Нужно указать хотя бы "Путь" или "Raw request"');
  }
  const { data } = await api.post<Endpoint>(`/projects/${projectId}/hosts/${hostId}/endpoints`, payload);
  return data;
}

export async function updateEndpoint(
  projectId: number,
  hostId: number,
  endpointId: number,
  payload: {
    path?: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";
    description?: string | null;
    request_raw?: string;
    query_params?: { name: string; value?: string | null; required?: boolean; description?: string | null }[];
    request_body?: string | null;
    request_content_type?: string | null;
    request_headers?: EndpointRequestHeader[];
  }
): Promise<Endpoint> {
  if (payload.path !== undefined && isBlank(payload.path) && isBlank(payload.request_raw)) {
    throw new Error('Нужно указать хотя бы "Путь" или "Raw request"');
  }
  const { data } = await api.put<Endpoint>(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`, payload);
  return data;
}

export async function deleteEndpoint(projectId: number, hostId: number, endpointId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`);
}

export async function getVulnerabilities(projectId: number): Promise<PaginatedResponse<Vulnerability>> {
  const { data } = await api.get<PaginatedResponse<Vulnerability>>(`/projects/${projectId}/vulnerabilities`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createVulnerability(
  projectId: number,
  payload: {
    host_id: number;
    title: string;
    description?: string | null;
    severity: "critical" | "high" | "medium" | "low" | "info";
    cvss_version?: "4.0" | null;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cwe_id?: string | null;
    status?: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
    workflow_steps?: Array<{
      id: string;
      description?: string | null;
      image_file_ids?: number[];
      endpoint_id?: number | null;
      endpoint_request_raw?: string | null;
    }>;
    steps_to_reproduce?: string | null;
    impact?: string | null;
    recommendations?: string | null;
  }
): Promise<Vulnerability> {
  if (!payload.host_id) {
    throw new Error("Нужно выбрать хост");
  }
  assertRequired(payload.title, "Название уязвимости");
  const { data } = await api.post<Vulnerability>(`/projects/${projectId}/vulnerabilities`, payload);
  return data;
}

export async function updateVulnerability(
  projectId: number,
  vulnerabilityId: number,
  payload: {
    title?: string;
    description?: string | null;
    severity?: "critical" | "high" | "medium" | "low" | "info";
    cvss_version?: "4.0" | null;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cwe_id?: string | null;
    status?: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
    workflow_steps?: Array<{
      id: string;
      description?: string | null;
      image_file_ids?: number[];
      endpoint_id?: number | null;
      endpoint_request_raw?: string | null;
    }>;
    steps_to_reproduce?: string | null;
    impact?: string | null;
    recommendations?: string | null;
  }
): Promise<Vulnerability> {
  if (payload.title !== undefined) {
    assertRequired(payload.title, "Название уязвимости");
  }
  const { data } = await api.put<Vulnerability>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`, payload);
  return data;
}

export async function deleteVulnerability(projectId: number, vulnerabilityId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
}

export async function getVulnerability(projectId: number, vulnerabilityId: number): Promise<VulnerabilityDetails> {
  const { data } = await api.get<VulnerabilityDetails>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
  return data;
}

export async function getHostVulnerabilities(projectId: number, hostId: number): Promise<PaginatedResponse<Vulnerability>> {
  const { data } = await api.get<PaginatedResponse<Vulnerability>>(`/projects/${projectId}/hosts/${hostId}/vulnerabilities`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function addVulnerabilityAsset(
  projectId: number,
  vulnerabilityId: number,
  payload: {
    asset_type: "host" | "port" | "service" | "endpoint";
    asset_id: number;
  }
): Promise<VulnerabilityAsset> {
  const { data } = await api.post<VulnerabilityAsset>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets`, payload);
  return data;
}

export async function deleteVulnerabilityAsset(projectId: number, vulnerabilityId: number, assetLinkId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets/${assetLinkId}`);
}

export async function listVulnerabilityFiles(projectId: number, vulnerabilityId: number): Promise<VulnerabilityFile[]> {
  const { data } = await api.get<VulnerabilityFile[]>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`);
  return data;
}

export async function uploadVulnerabilityFile(projectId: number, vulnerabilityId: number, file: File): Promise<VulnerabilityFile> {
  if (!file) {
    throw new Error("Нужно выбрать файл");
  }
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<VulnerabilityFile>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function deleteVulnerabilityFile(projectId: number, vulnerabilityId: number, fileId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files/${fileId}`);
}

export async function listVulnerabilityComments(projectId: number, vulnerabilityId: number): Promise<PaginatedResponse<VulnerabilityComment>> {
  const { data } = await api.get<PaginatedResponse<VulnerabilityComment>>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createVulnerabilityComment(projectId: number, vulnerabilityId: number, content: string): Promise<VulnerabilityComment> {
  assertRequired(content, "Комментарий");
  const { data } = await api.post<VulnerabilityComment>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, { content });
  return data;
}

export async function updateVulnerabilityComment(
  projectId: number,
  vulnerabilityId: number,
  commentId: number,
  content: string
): Promise<VulnerabilityComment> {
  assertRequired(content, "Комментарий");
  const { data } = await api.put<VulnerabilityComment>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`, { content });
  return data;
}

export async function deleteVulnerabilityComment(projectId: number, vulnerabilityId: number, commentId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`);
}

export async function importProjectData(projectId: number, file: File): Promise<ImportResult> {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<ImportResult>(`/projects/${projectId}/import`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function importOpenApiFile(projectId: number, hostId: number, file: File): Promise<OpenApiImportResult> {
  if (!file) {
    throw new Error("Нужно выбрать Swagger/OpenAPI файл");
  }
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<OpenApiImportResult>(`/projects/${projectId}/hosts/${hostId}/import-openapi`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function exportOpenApiFile(projectId: number, hostId: number): Promise<Blob> {
  const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}/export-openapi`, {
    responseType: "blob",
  });
  return data as Blob;
}

export async function downloadProjectCertificationReport(projectId: number): Promise<Blob> {
  const { data } = await api.post(`/projects/${projectId}/reports/szi`, null, {
    responseType: "blob",
  });
  return data as Blob;
}

export async function downloadProjectAcceptanceReport(projectId: number): Promise<Blob> {
  const { data } = await api.post(`/projects/${projectId}/reports/pp`, null, {
    responseType: "blob",
  });
  return data as Blob;
}

export async function listAgentTokens(): Promise<AgentApiToken[]> {
  const { data } = await api.get<AgentApiToken[]>("/agent-tokens");
  return data;
}

export async function createAgentToken(payload: {
  name: string;
  scopes: string[];
  project_ids: number[];
  all_projects: boolean;
  expires_at?: string | null;
}): Promise<AgentApiToken & { token: string }> {
  const { data } = await api.post<AgentApiToken & { token: string }>("/agent-tokens", payload);
  return data;
}

export async function revokeAgentToken(tokenId: number): Promise<void> {
  await api.delete(`/agent-tokens/${tokenId}`);
}

export async function listNotifications(options?: { is_read?: boolean }): Promise<PaginatedResponse<Notification>> {
  const params: Record<string, number | boolean> = { page: 1, size: 20 };
  if (options?.is_read !== undefined) {
    params.is_read = options.is_read;
  }
  const { data } = await api.get<PaginatedResponse<Notification>>("/notifications", { params });
  return data;
}

export async function unreadCount(): Promise<number> {
  const { data } = await api.get<{ count: number }>("/notifications/unread-count");
  return data.count;
}

export async function markNotificationRead(notificationId: number): Promise<void> {
  await api.patch(`/notifications/${notificationId}/read`);
}

export async function markAllNotificationsRead(): Promise<void> {
  await api.patch("/notifications/read-all");
}

export async function getAuditLogs(
  page = 1,
  size = 50,
  filters?: {
    user_id?: string;
    username?: string;
    action?: string;
    entity_type?: string;
    entity_id?: string;
    ip_address?: string;
    query?: string;
    created_from?: string;
    created_to?: string;
  }
): Promise<PaginatedResponse<AuditLog>> {
  const { data } = await api.get<PaginatedResponse<AuditLog>>("/audit-logs", {
    params: { page, size, ...filters },
  });
  return data;
}
