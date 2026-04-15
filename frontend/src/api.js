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
    await api.post("/auth/login", { username, password });
}
export async function logout() {
    await api.post("/auth/logout");
}
export async function getMe() {
    const { data } = await api.get("/users/me");
    return data;
}
export async function getProjects(page = 1, size = 20) {
    const { data } = await api.get("/projects", { params: { page, size } });
    return data;
}
export async function createProject(payload) {
    const { data } = await api.post("/projects", payload);
    return data;
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
export async function listNotifications() {
    const { data } = await api.get("/notifications", { params: { page: 1, size: 20 } });
    return data;
}
export async function unreadCount() {
    const { data } = await api.get("/notifications/unread-count");
    return data.count;
}
