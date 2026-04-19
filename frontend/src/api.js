import axios from "axios";
const api = axios.create({
    baseURL: "/api/v1",
    withCredentials: true,
});
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
    const { data } = await api.patch("/users/me/password", payload);
    return data;
}
export async function forceChangePassword(newPassword) {
    const { data } = await api.post("/auth/force-change-password", { new_password: newPassword });
    return data;
}
export async function uploadMyAvatar(file) {
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
    const { data } = await api.post("/projects/folders", payload);
    return data;
}
export async function moveProjectFolder(folderId, payload) {
    const { data } = await api.patch(`/projects/folders/${folderId}/move`, payload);
    return data;
}
export async function createProject(payload) {
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
    const { data } = await api.post(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`, payload);
    return data;
}
export async function updateService(projectId, hostId, portId, serviceId, payload) {
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
    const { data } = await api.post(`/projects/${projectId}/hosts/${hostId}/endpoints`, payload);
    return data;
}
export async function updateEndpoint(projectId, hostId, endpointId, payload) {
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
    const { data } = await api.post(`/projects/${projectId}/vulnerabilities`, payload);
    return data;
}
export async function updateVulnerability(projectId, vulnerabilityId, payload) {
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
    const { data } = await api.post(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, { content });
    return data;
}
export async function updateVulnerabilityComment(projectId, vulnerabilityId, commentId, content) {
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
export async function getAuditLogs(page = 1, size = 50, filters) {
    const { data } = await api.get("/audit-logs", {
        params: { page, size, ...filters },
    });
    return data;
}
