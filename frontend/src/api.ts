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
  PaginatedResponse,
  Port,
  Project,
  ProjectFolder,
  ProjectMember,
  PasswordResetResult,
  User,
  Vulnerability,
  VulnerabilityAsset,
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

export const getApiErrorMessage = (error: unknown, fallback: string): string => {
  if (axios.isAxiosError(error)) {
    return (
      normalizeDetailMessage(error.response?.data) ||
      normalizeDetailMessage(error.message) ||
      fallback
    );
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
    const shouldSkipRefresh = requestUrl.includes("/auth/refresh") || requestUrl.includes("/users/me");
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
  tags?: string[];
  password?: string;
  role: User["role"];
  send_invite_email?: boolean;
}): Promise<User> {
  assertRequired(payload.username, "Имя пользователя");
  assertRequired(payload.email, "Email");
  const { data } = await api.post<User>("/users", payload);
  return data;
}

export async function updateUser(
  userId: string,
  payload: {
    username?: string;
    full_name?: string;
    tags?: string[];
    role?: User["role"];
    is_active?: boolean;
  }
): Promise<User> {
  const { data } = await api.put<User>(`/users/${userId}`, payload);
  return data;
}

export async function resetUserPassword(userId: string): Promise<PasswordResetResult> {
  const { data } = await api.patch<PasswordResetResult>(`/users/${userId}/password`);
  return data;
}

export async function deleteUser(userId: string): Promise<void> {
  await api.delete(`/users/${userId}`);
}

export async function updateMyProfile(payload: {
  username?: string;
  email?: string;
  full_name?: string;
  tags?: string[];
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

export async function forceChangePassword(newPassword: string): Promise<User> {
  assertRequired(newPassword, "Новый пароль");
  const { data } = await api.post<User>("/auth/force-change-password", { new_password: newPassword });
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

export async function getProjectFolders(): Promise<ProjectFolder[]> {
  const { data } = await api.get<ProjectFolder[]>("/projects/folders");
  return data;
}

export async function createProjectFolder(payload: { name: string; parent_id?: string | null }): Promise<ProjectFolder> {
  assertRequired(payload.name, "Название папки");
  const { data } = await api.post<ProjectFolder>("/projects/folders", payload);
  return data;
}

export async function moveProjectFolder(folderId: string, payload: { parent_id?: string | null }): Promise<ProjectFolder> {
  const { data } = await api.patch<ProjectFolder>(`/projects/folders/${folderId}/move`, payload);
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

export async function getProject(projectId: string): Promise<Project> {
  const { data } = await api.get<Project>(`/projects/${projectId}`);
  return data;
}

export async function updateProject(
  projectId: string,
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

export async function getProjectMembers(projectId: string): Promise<ProjectMember[]> {
  const { data } = await api.get<ProjectMember[]>(`/projects/${projectId}/members`);
  return data;
}

export async function addProjectMember(projectId: string, userId: string): Promise<void> {
  if (!userId) {
    throw new Error("Нужно выбрать пользователя");
  }
  await api.post(`/projects/${projectId}/members`, { user_id: userId });
}

export async function removeProjectMember(projectId: string, userId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/members/${userId}`);
}

export async function deleteProject(projectId: string): Promise<void> {
  await api.delete(`/projects/${projectId}`);
}

export async function getHosts(projectId: string): Promise<PaginatedResponse<Host>> {
  const { data } = await api.get<PaginatedResponse<Host>>(`/projects/${projectId}/hosts`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createHost(
  projectId: string,
  payload: {
    ip_address?: string;
    hostname?: string;
    notes?: string;
    status?: "up" | "down" | "unknown";
  }
): Promise<Host> {
  if (isBlank(payload.ip_address) && isBlank(payload.hostname)) {
    throw new Error('Нужно указать хотя бы "IP-адрес" или "Hostname"');
  }
  const { data } = await api.post<Host>(`/projects/${projectId}/hosts`, payload);
  return data;
}

export async function getHost(projectId: string, hostId: string): Promise<HostDetails> {
  const { data } = await api.get<HostDetails>(`/projects/${projectId}/hosts/${hostId}`);
  return data;
}

export async function updateHost(
  projectId: string,
  hostId: string,
  payload: {
    ip_address?: string;
    hostname?: string;
    notes?: string;
    status?: "up" | "down" | "unknown";
  }
): Promise<Host> {
  const { data } = await api.put<Host>(`/projects/${projectId}/hosts/${hostId}`, payload);
  return data;
}

export async function deleteHost(projectId: string, hostId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}`);
}

export async function getPorts(projectId: string, hostId: string): Promise<Port[]> {
  const { data } = await api.get<Port[]>(`/projects/${projectId}/hosts/${hostId}/ports`);
  return data;
}

export async function createPort(
  projectId: string,
  hostId: string,
  payload: {
    port_number: number;
    protocol?: "tcp" | "udp";
    state?: "open" | "closed" | "filtered";
  }
): Promise<Port> {
  if (!Number.isFinite(payload.port_number)) {
    throw new Error("Порт должен быть числом");
  }
  const { data } = await api.post<Port>(`/projects/${projectId}/hosts/${hostId}/ports`, payload);
  return data;
}

export async function updatePort(
  projectId: string,
  hostId: string,
  portId: string,
  payload: {
    port_number?: number;
    protocol?: "tcp" | "udp";
    state?: "open" | "closed" | "filtered";
  }
): Promise<Port> {
  const { data } = await api.put<Port>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`, payload);
  return data;
}

export async function deletePort(projectId: string, hostId: string, portId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`);
}

export async function getServices(projectId: string, hostId: string, portId: string): Promise<Service[]> {
  const { data } = await api.get<Service[]>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`);
  return data;
}

export async function createService(
  projectId: string,
  hostId: string,
  portId: string,
  payload: { name: string; version?: string; banner?: string }
): Promise<Service> {
  assertRequired(payload.name, "Название сервиса");
  const { data } = await api.post<Service>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`, payload);
  return data;
}

export async function updateService(
  projectId: string,
  hostId: string,
  portId: string,
  serviceId: string,
  payload: { name?: string; version?: string; banner?: string }
): Promise<Service> {
  if (payload.name !== undefined) {
    assertRequired(payload.name, "Название сервиса");
  }
  const { data } = await api.put<Service>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`, payload);
  return data;
}

export async function deleteService(projectId: string, hostId: string, portId: string, serviceId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`);
}

export async function getEndpoints(projectId: string, hostId: string): Promise<Endpoint[]> {
  const { data } = await api.get<Endpoint[]>(`/projects/${projectId}/hosts/${hostId}/endpoints`);
  return data;
}

export async function createEndpoint(
  projectId: string,
  hostId: string,
  payload: {
    path?: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
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
  projectId: string,
  hostId: string,
  endpointId: string,
  payload: {
    path?: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
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

export async function deleteEndpoint(projectId: string, hostId: string, endpointId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`);
}

export async function getVulnerabilities(projectId: string): Promise<PaginatedResponse<Vulnerability>> {
  const { data } = await api.get<PaginatedResponse<Vulnerability>>(`/projects/${projectId}/vulnerabilities`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createVulnerability(
  projectId: string,
  payload: {
    host_id: string;
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
      title: string;
      description?: string | null;
      image_file_ids?: string[];
      endpoint_id?: string | null;
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
  projectId: string,
  vulnerabilityId: string,
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
      title: string;
      description?: string | null;
      image_file_ids?: string[];
      endpoint_id?: string | null;
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

export async function deleteVulnerability(projectId: string, vulnerabilityId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
}

export async function getVulnerability(projectId: string, vulnerabilityId: string): Promise<VulnerabilityDetails> {
  const { data } = await api.get<VulnerabilityDetails>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
  return data;
}

export async function getHostVulnerabilities(projectId: string, hostId: string): Promise<PaginatedResponse<Vulnerability>> {
  const { data } = await api.get<PaginatedResponse<Vulnerability>>(`/projects/${projectId}/hosts/${hostId}/vulnerabilities`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function addVulnerabilityAsset(
  projectId: string,
  vulnerabilityId: string,
  payload: {
    asset_type: "host" | "port" | "service" | "endpoint";
    asset_id: string;
  }
): Promise<VulnerabilityAsset> {
  const { data } = await api.post<VulnerabilityAsset>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets`, payload);
  return data;
}

export async function deleteVulnerabilityAsset(projectId: string, vulnerabilityId: string, assetLinkId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets/${assetLinkId}`);
}

export async function listVulnerabilityFiles(projectId: string, vulnerabilityId: string): Promise<VulnerabilityFile[]> {
  const { data } = await api.get<VulnerabilityFile[]>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`);
  return data;
}

export async function uploadVulnerabilityFile(projectId: string, vulnerabilityId: string, file: File): Promise<VulnerabilityFile> {
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

export async function deleteVulnerabilityFile(projectId: string, vulnerabilityId: string, fileId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files/${fileId}`);
}

export async function listVulnerabilityComments(projectId: string, vulnerabilityId: string): Promise<PaginatedResponse<VulnerabilityComment>> {
  const { data } = await api.get<PaginatedResponse<VulnerabilityComment>>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createVulnerabilityComment(projectId: string, vulnerabilityId: string, content: string): Promise<VulnerabilityComment> {
  assertRequired(content, "Комментарий");
  const { data } = await api.post<VulnerabilityComment>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, { content });
  return data;
}

export async function updateVulnerabilityComment(
  projectId: string,
  vulnerabilityId: string,
  commentId: string,
  content: string
): Promise<VulnerabilityComment> {
  assertRequired(content, "Комментарий");
  const { data } = await api.put<VulnerabilityComment>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`, { content });
  return data;
}

export async function deleteVulnerabilityComment(projectId: string, vulnerabilityId: string, commentId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`);
}

export async function importProjectData(projectId: string, file: File): Promise<ImportResult> {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<ImportResult>(`/projects/${projectId}/import`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function importOpenApiFile(projectId: string, hostId: string, file: File): Promise<OpenApiImportResult> {
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

export async function generateProjectReport(projectId: string, format: "md" | "pdf" | "docx"): Promise<Blob> {
  const { data } = await api.post(`/projects/${projectId}/reports/generate`, null, {
    params: { format },
    responseType: "blob",
  });
  return data as Blob;
}

export async function listNotifications(): Promise<PaginatedResponse<Notification>> {
  const { data } = await api.get<PaginatedResponse<Notification>>("/notifications", { params: { page: 1, size: 20 } });
  return data;
}

export async function unreadCount(): Promise<number> {
  const { data } = await api.get<{ count: number }>("/notifications/unread-count");
  return data.count;
}

export async function markNotificationRead(notificationId: string): Promise<void> {
  await api.patch(`/notifications/${notificationId}/read`);
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
