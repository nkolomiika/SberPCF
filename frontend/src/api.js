import axios from "axios";
const api = axios.create({
    baseURL: "/api/v1",
    withCredentials: true,
});
const isBlank = (value) => !value || value.trim().length === 0;
const assertRequired = (value, label) => {
    if (isBlank(value)) {
        throw new Error(`Поле "${label}" обязательно`);
    }
};
const normalizeDetailMessage = (detail) => {
    if (typeof detail === "string" && detail.trim()) {
        return detail.trim();
    }
    if (Array.isArray(detail)) {
        const messages = detail.map((item) => normalizeDetailMessage(item)).filter((item) => Boolean(item));
        return messages.length ? messages.join("; ") : null;
    }
    if (detail && typeof detail === "object") {
        if ("detail" in detail) {
            return normalizeDetailMessage(detail.detail);
        }
        if ("message" in detail) {
            return normalizeDetailMessage(detail.message);
        }
    }
    return null;
};
export const getApiErrorMessage = (error, fallback) => {
    if (axios.isAxiosError(error)) {
        return (normalizeDetailMessage(error.response?.data) ||
            normalizeDetailMessage(error.message) ||
            fallback);
    }
    if (error instanceof Error && error.message.trim()) {
        return error.message;
    }
    return fallback;
};
let isRefreshing = false;
let waitingQueue = [];
api.interceptors.response.use((response) => response, async (error) => {
    const originalRequest = error.config;
    const requestUrl = String(originalRequest?.url ?? "");
    const shouldSkipRefresh = requestUrl.includes("/auth/refresh") || requestUrl.includes("/users/me");
    if (error.response?.status === 401 && !originalRequest?._retry && !shouldSkipRefresh) {
        originalRequest._retry = true;
        if (isRefreshing) {
            return new Promise((resolve, reject) => waitingQueue.push({ resolve, reject })).then(() => api(originalRequest));
        }
        isRefreshing = true;
        try {
            await api.post("/auth/refresh");
            waitingQueue.forEach((entry) => entry.resolve());
            waitingQueue = [];
            return api(originalRequest);
        }
        catch (refreshError) {
            waitingQueue.forEach((entry) => entry.reject(refreshError));
            waitingQueue = [];
            return Promise.reject(refreshError);
        }
        finally {
            isRefreshing = false;
        }
    }
    return Promise.reject(error);
});
export async function login(username, password) {
    assertRequired(username, "Имя пользователя");
    assertRequired(password, "Пароль");
    const { data } = await api.post("/auth/login", { username, password });
    return data;
}
export async function logout() {
    await api.post("/auth/logout");
}
export async function getMe() {
    const { data } = await api.get("/users/me");
    return data;
}
export async function getUsers(page = 1, size = 200) {
    const { data } = await api.get("/users", { params: { page, size } });
    return data;
}
export async function createUser(payload) {
    assertRequired(payload.username, "Имя пользователя");
    assertRequired(payload.email, "Email");
    const { data } = await api.post("/users", payload);
    return data;
}
export async function updateUser(userId, payload) {
    const { data } = await api.put(`/users/${userId}`, payload);
    return data;
}
export async function resetUserPassword(userId) {
    const { data } = await api.patch(`/users/${userId}/password`);
    return data;
}
export async function deleteUser(userId) {
    await api.delete(`/users/${userId}`);
}
export async function updateMyProfile(payload) {
    const { data } = await api.patch("/users/me", payload);
    return data;
}
export async function changeMyPassword(payload) {
    assertRequired(payload.current_password, "Текущий пароль");
    assertRequired(payload.new_password, "Новый пароль");
    const { data } = await api.patch("/users/me/password", payload);
    return data;
}
export async function forceChangePassword(newPassword) {
    assertRequired(newPassword, "Новый пароль");
    const { data } = await api.post("/auth/force-change-password", { new_password: newPassword });
    return data;
}
export async function uploadMyAvatar(file) {
    if (!file) {
        throw new Error("Файл аватара обязателен");
    }
    const formData = new FormData();
    formData.append("avatar", file);
    const { data } = await api.post("/users/me/avatar", formData, {
        headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
}
export async function getProjects(page = 1, size = 20, status) {
    const { data } = await api.get("/projects", { params: { page, size, status } });
    return data;
}
export async function getProjectFolders() {
    const { data } = await api.get("/projects/folders");
    return data;
}
export async function createProjectFolder(payload) {
    assertRequired(payload.name, "Название папки");
    const { data } = await api.post("/projects/folders", payload);
    return data;
}
export async function moveProjectFolder(folderId, payload) {
    const { data } = await api.patch(`/projects/folders/${folderId}/move`, payload);
    return data;
}
export async function createProject(payload) {
    assertRequired(payload.name, "Название проекта");
    const { data } = await api.post("/projects", payload);
    return data;
}
export async function getProject(projectId) {
    const { data } = await api.get(`/projects/${projectId}`);
    return data;
}
export async function updateProject(projectId, payload) {
    const { data } = await api.put(`/projects/${projectId}`, payload);
    return data;
}
export async function getProjectMembers(projectId) {
    const { data } = await api.get(`/projects/${projectId}/members`);
    return data;
}
export async function addProjectMember(projectId, userId) {
    if (!userId) {
        throw new Error("Нужно выбрать пользователя");
    }
    await api.post(`/projects/${projectId}/members`, { user_id: userId });
}
export async function removeProjectMember(projectId, userId) {
    await api.delete(`/projects/${projectId}/members/${userId}`);
}
export async function deleteProject(projectId) {
    await api.delete(`/projects/${projectId}`);
}
export async function getHosts(projectId) {
    const { data } = await api.get(`/projects/${projectId}/hosts`, {
        params: { page: 1, size: 100 },
    });
    return data;
}
export async function createHost(projectId, payload) {
    if (isBlank(payload.ip_address) && isBlank(payload.hostname)) {
        throw new Error('Нужно указать хотя бы "IP-адрес" или "Hostname"');
    }
    const { data } = await api.post(`/projects/${projectId}/hosts`, payload);
    return data;
}
export async function getHost(projectId, hostId) {
    const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}`);
    return data;
}
export async function updateHost(projectId, hostId, payload) {
    const { data } = await api.put(`/projects/${projectId}/hosts/${hostId}`, payload);
    return data;
}
export async function deleteHost(projectId, hostId) {
    await api.delete(`/projects/${projectId}/hosts/${hostId}`);
}
export async function getPorts(projectId, hostId) {
    const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}/ports`);
    return data;
}
export async function createPort(projectId, hostId, payload) {
    if (!Number.isFinite(payload.port_number)) {
        throw new Error("Порт должен быть числом");
    }
    const { data } = await api.post(`/projects/${projectId}/hosts/${hostId}/ports`, payload);
    return data;
}
export async function updatePort(projectId, hostId, portId, payload) {
    const { data } = await api.put(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`, payload);
    return data;
}
export async function deletePort(projectId, hostId, portId) {
    await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`);
}
export async function getServices(projectId, hostId, portId) {
    const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`);
    return data;
}
export async function createService(projectId, hostId, portId, payload) {
    assertRequired(payload.name, "Название сервиса");
    const { data } = await api.post(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`, payload);
    return data;
}
export async function updateService(projectId, hostId, portId, serviceId, payload) {
    if (payload.name !== undefined) {
        assertRequired(payload.name, "Название сервиса");
    }
    const { data } = await api.put(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`, payload);
    return data;
}
export async function deleteService(projectId, hostId, portId, serviceId) {
    await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`);
}
export async function getEndpoints(projectId, hostId) {
    const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}/endpoints`);
    return data;
}
export async function createEndpoint(projectId, hostId, payload) {
    if (isBlank(payload.path) && isBlank(payload.request_raw)) {
        throw new Error('Нужно указать хотя бы "Путь" или "Raw request"');
    }
    const { data } = await api.post(`/projects/${projectId}/hosts/${hostId}/endpoints`, payload);
    return data;
}
export async function updateEndpoint(projectId, hostId, endpointId, payload) {
    if (payload.path !== undefined && isBlank(payload.path) && isBlank(payload.request_raw)) {
        throw new Error('Нужно указать хотя бы "Путь" или "Raw request"');
    }
    const { data } = await api.put(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`, payload);
    return data;
}
export async function deleteEndpoint(projectId, hostId, endpointId) {
    await api.delete(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`);
}
export async function getVulnerabilities(projectId) {
    const { data } = await api.get(`/projects/${projectId}/vulnerabilities`, {
        params: { page: 1, size: 100 },
    });
    return data;
}
export async function createVulnerability(projectId, payload) {
    if (!payload.host_id) {
        throw new Error("Нужно выбрать хост");
    }
    assertRequired(payload.title, "Название уязвимости");
    const { data } = await api.post(`/projects/${projectId}/vulnerabilities`, payload);
    return data;
}
export async function updateVulnerability(projectId, vulnerabilityId, payload) {
    if (payload.title !== undefined) {
        assertRequired(payload.title, "Название уязвимости");
    }
    const { data } = await api.put(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`, payload);
    return data;
}
export async function deleteVulnerability(projectId, vulnerabilityId) {
    await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
}
export async function getVulnerability(projectId, vulnerabilityId) {
    const { data } = await api.get(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
    return data;
}
export async function getHostVulnerabilities(projectId, hostId) {
    const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}/vulnerabilities`, {
        params: { page: 1, size: 100 },
    });
    return data;
}
export async function addVulnerabilityAsset(projectId, vulnerabilityId, payload) {
    const { data } = await api.post(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets`, payload);
    return data;
}
export async function deleteVulnerabilityAsset(projectId, vulnerabilityId, assetLinkId) {
    await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets/${assetLinkId}`);
}
export async function listVulnerabilityFiles(projectId, vulnerabilityId) {
    const { data } = await api.get(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`);
    return data;
}
export async function uploadVulnerabilityFile(projectId, vulnerabilityId, file) {
    if (!file) {
        throw new Error("Нужно выбрать файл");
    }
    const formData = new FormData();
    formData.append("file", file);
    const { data } = await api.post(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
}
export async function deleteVulnerabilityFile(projectId, vulnerabilityId, fileId) {
    await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files/${fileId}`);
}
export async function listVulnerabilityComments(projectId, vulnerabilityId) {
    const { data } = await api.get(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, {
        params: { page: 1, size: 100 },
    });
    return data;
}
export async function createVulnerabilityComment(projectId, vulnerabilityId, content) {
    assertRequired(content, "Комментарий");
    const { data } = await api.post(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, { content });
    return data;
}
export async function updateVulnerabilityComment(projectId, vulnerabilityId, commentId, content) {
    assertRequired(content, "Комментарий");
    const { data } = await api.put(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`, { content });
    return data;
}
export async function deleteVulnerabilityComment(projectId, vulnerabilityId, commentId) {
    await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`);
}
export async function importProjectData(projectId, file) {
    const formData = new FormData();
    formData.append("file", file);
    const { data } = await api.post(`/projects/${projectId}/import`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
}
export async function importOpenApiFile(projectId, hostId, file) {
    if (!file) {
        throw new Error("Нужно выбрать Swagger/OpenAPI файл");
    }
    const formData = new FormData();
    formData.append("file", file);
    const { data } = await api.post(`/projects/${projectId}/hosts/${hostId}/import-openapi`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
}
export async function generateProjectReport(projectId, format) {
    const { data } = await api.post(`/projects/${projectId}/reports/generate`, null, {
        params: { format },
        responseType: "blob",
    });
    return data;
}
export async function listNotifications() {
    const { data } = await api.get("/notifications", { params: { page: 1, size: 20 } });
    return data;
}
export async function unreadCount() {
    const { data } = await api.get("/notifications/unread-count");
    return data.count;
}
export async function markNotificationRead(notificationId) {
    await api.patch(`/notifications/${notificationId}/read`);
}
export async function getAuditLogs(page = 1, size = 50, filters) {
    const { data } = await api.get("/audit-logs", {
        params: { page, size, ...filters },
    });
    return data;
}
