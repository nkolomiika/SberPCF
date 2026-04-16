import axios from "axios";
import type { Endpoint, Host, HostDetails, Notification, PaginatedResponse, Port, Project, ProjectMember, User, Vulnerability, VulnerabilityAsset } from "./types";

const api = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
});

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

export async function login(username: string, password: string): Promise<void> {
  await api.post("/auth/login", { username, password });
}

export async function logout(): Promise<void> {
  await api.post("/auth/logout");
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>("/users/me");
  return data;
}

export async function getProjects(page = 1, size = 20): Promise<PaginatedResponse<Project>> {
  const { data } = await api.get<PaginatedResponse<Project>>("/projects", { params: { page, size } });
  return data;
}

export async function createProject(payload: {
  name: string;
  description?: string;
  start_date?: string;
  end_date?: string;
}): Promise<Project> {
  const { data } = await api.post<Project>("/projects", payload);
  return data;
}

export async function getProjectMembers(projectId: string): Promise<ProjectMember[]> {
  const { data } = await api.get<ProjectMember[]>(`/projects/${projectId}/members`);
  return data;
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

export async function getEndpoints(projectId: string, hostId: string): Promise<Endpoint[]> {
  const { data } = await api.get<Endpoint[]>(`/projects/${projectId}/hosts/${hostId}/endpoints`);
  return data;
}

export async function createEndpoint(
  projectId: string,
  hostId: string,
  payload: {
    path: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
    description?: string;
  }
): Promise<Endpoint> {
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
    description?: string;
  }
): Promise<Endpoint> {
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
    title: string;
    description?: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    status?: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
  }
): Promise<Vulnerability> {
  const { data } = await api.post<Vulnerability>(`/projects/${projectId}/vulnerabilities`, payload);
  return data;
}

export async function updateVulnerability(
  projectId: string,
  vulnerabilityId: string,
  payload: {
    title?: string;
    description?: string;
    severity?: "critical" | "high" | "medium" | "low" | "info";
    status?: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
  }
): Promise<Vulnerability> {
  const { data } = await api.put<Vulnerability>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`, payload);
  return data;
}

export async function deleteVulnerability(projectId: string, vulnerabilityId: string): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
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

export async function listNotifications(): Promise<PaginatedResponse<Notification>> {
  const { data } = await api.get<PaginatedResponse<Notification>>("/notifications", { params: { page: 1, size: 20 } });
  return data;
}

export async function unreadCount(): Promise<number> {
  const { data } = await api.get<{ count: number }>("/notifications/unread-count");
  return data.count;
}
