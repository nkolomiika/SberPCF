import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, vi } from "vitest";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { StormApp } from "./StormApp";
import { useAuthStore } from "../store";
import * as api from "../api";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  const mk = (id: number, name: string, status: string) => ({
    id, name, folder: "", description: `${name} — assessment`, start_date: "2026-04-27",
    end_date: "2026-07-27", timeline_frozen_at: null, status, created_by: 1,
    created_at: "2026-01-01T00:00:00Z", updated_at: "2026-07-10T00:00:00Z",
  });
  const projects = [
    mk(1, "Acme Corp — External Perimeter", "active"),
    mk(2, "Northwind API", "active"),
    mk(3, "Globex VPN Audit", "archived"),
  ];
  const mkUser = (id: number, username: string, role: string, isLead: boolean) => ({
    id, username, email: `${username}@example.com`, full_name: null, avatar_url: null,
    role, project_role: isLead ? "lead" : "pentester", is_active: true, password_changed_at: null,
    created_at: "2026-01-01T00:00:00Z",
  });
  const users = [
    mkUser(1, "admin", "admin", true),
    mkUser(2, "alice", "pentester", true),
    mkUser(5, "diana", "pentester", false),
  ];
  const ts = { created_at: "2026-01-01T00:00:00Z", updated_at: "2026-07-10T00:00:00Z" };
  const mkService = (id: number, portId: number, name: string) => ({
    id, port_id: portId, name, version: "1.25.3", banner: null, ...ts,
  });
  const mkPort = (id: number, hostId: number, ipId: number, n: number, svc: string) => ({
    id, host_id: hostId, ip_address_id: ipId, port_number: n, protocol: "tcp",
    state: "open", services: [mkService(id * 10, id, svc)], ...ts,
  });
  const mkIp = (id: number, hostId: number, ip: string, ports: unknown[]) => ({
    id, host_id: hostId, ip_address: ip, label: null, is_primary: true, ports, ...ts,
  });
  // Backend-shaped hosts: ports hang off ip_addresses, services off ports.
  const hosts = [
    {
      id: 11, project_id: 2, ip_address: "203.0.113.10", hostname: "api.northwind.test",
      ip_addresses: [mkIp(101, 11, "203.0.113.10", [mkPort(1001, 11, 101, 443, "nginx")])],
      status: "up", os_type: "linux", notes: null, ...ts,
    },
    {
      id: 12, project_id: 2, ip_address: null, hostname: "test.com",
      ip_addresses: [mkIp(102, 12, "203.0.113.11", [mkPort(1002, 12, 102, 22, "openssh")])],
      status: "unknown", os_type: "unknown", notes: null, ...ts,
    },
  ];
  const endpointsByHost: Record<number, unknown[]> = {
    11: [{
      id: 501, host_id: 11, path: "/v1/orders", method: "GET", description: null,
      query_params: [], request_body: null, request_content_type: null, ...ts,
    }],
    12: [],
  };
  // Backend-shaped findings. `created_by_username` is resolved server-side, so the
  // author renders without the (admin-only) users list.
  const mkVuln = (id: number, title: string, severity: string, status: string, author: string) => ({
    id, project_id: 2, title, description: "", severity, status,
    cvss_version: null, cvss_score: null, cvss_vector: null, cwe_id: null,
    workflow_steps: [], steps_to_reproduce: null, impact: null, recommendations: null,
    created_by: 4, created_by_username: author, ...ts,
  });
  const vulns = [
    mkVuln(71, "IDOR on GET /orders/{id}", "critical", "open", "d.petrov"),
    mkVuln(72, "JWT algorithm confusion (alg=none)", "high", "open", "d.petrov"),
    mkVuln(73, "Mass assignment on order update", "medium", "in_progress", "m.antonov"),
  ];
  const mkNote = (id: number, title: string, content: string, author: string) => ({
    id, project_id: 2, parent_id: null, title, content, sort_order: 0,
    created_by: 4, created_by_username: author, updated_by: null, ...ts,
  });
  const notes = [mkNote(81, "Auth model", "Keycloak realms with bearer tokens.", "d.petrov")];
  const mkToken = (id: number, name: string, prefix: string) => ({
    id, name, token_prefix: prefix, scopes: ["read:hosts"], all_projects: true,
    created_by: 1, expires_at: null, revoked_at: null, last_used_at: null,
    project_ids: [], ...ts,
  });
  return {
    ...actual,
    getProjects: vi.fn(async () => ({ items: projects, total: projects.length, page: 1, size: 100, pages: 1 })),
    getUsers: vi.fn(async () => ({ items: users, total: users.length, page: 1, size: 200, pages: 1 })),
    createUser: vi.fn(async () => users[0]),
    updateUser: vi.fn(async () => users[0]),
    deleteUser: vi.fn(async () => undefined),
    getProjectStats: vi.fn(async () =>
      projects.map((p) => ({ project_id: p.id, status: p.status, hosts_count: 2, total_findings: 3, open_findings: 1 }))
    ),
    getVulnerabilities: vi.fn(async () => ({ items: vulns, total: vulns.length, page: 1, size: 100, pages: 1 })),
    getVulnerability: vi.fn(async (_p: number, id: number) => ({
      ...vulns.find((v) => v.id === id), assets: [{ id: 1, vulnerability_id: id, asset_type: "host", asset_id: 11 }],
      files: [], comments_count: 0,
    })),
    createVulnerability: vi.fn(async () => vulns[0]),
    updateVulnerability: vi.fn(async () => vulns[0]),
    deleteVulnerability: vi.fn(async () => undefined),
    listProjectNotes: vi.fn(async () => notes),
    createProjectNote: vi.fn(async () => notes[0]),
    updateProjectNote: vi.fn(async () => notes[0]),
    deleteProjectNote: vi.fn(async () => undefined),
    getProjectMembers: vi.fn(async () => []),
    getProjectActivity: vi.fn(async () => [
      {
        id: 900, action: "CREATE", entity_type: "vulnerability", entity_id: 71, user_id: 4,
        username: "d.petrov", title: "IDOR on GET /orders/{id}", severity: "critical",
        url: "/projects/2/vulns/71", details: null, created_at: "2026-07-10T00:00:00Z",
      },
      // Ports never reach the feed; the UPDATE row has no details, so its host
      // name has to be resolved from the loaded hosts.
      {
        id: 901, action: "CREATE", entity_type: "port", entity_id: 1001, user_id: 1,
        username: "admin", title: null, severity: null, url: null,
        details: { port: "443/tcp", service: "nginx" }, created_at: "2026-07-10T00:00:00Z",
      },
      {
        id: 902, action: "UPDATE", entity_type: "host", entity_id: 11, user_id: 1,
        username: "admin", title: null, severity: null, url: null, details: null,
        created_at: "2026-07-10T00:00:00Z",
      },
      {
        id: 903, action: "CREATE", entity_type: "host_ip_address", entity_id: 101, user_id: 1,
        username: "admin", title: null, severity: null, url: null,
        details: { ip_address: "203.0.113.10", label: "internal" }, created_at: "2026-07-10T00:00:00Z",
      },
    ]),
    /* Empty by default: the bell renders project and finding names, and a populated
       panel would collide with the same names in the main view. The notification
       tests below opt in with mockResolvedValue. */
    listNotifications: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 20, pages: 1 })),
    markNotificationRead: vi.fn(async () => undefined),
    listAgentTokens: vi.fn(async () => [mkToken(1, "CI pipeline", "pcf_ci"), mkToken(2, "Slack alerts bot", "pcf_sl")]),
    createProject: vi.fn(async () => projects[0]),
    updateProject: vi.fn(async () => projects[0]),
    deleteProject: vi.fn(async () => undefined),
    getHosts: vi.fn(async () => ({ items: hosts, total: hosts.length, page: 1, size: 100, pages: 1 })),
    getHost: vi.fn(async (_projectId: number, hostId: number) => ({
      ...hosts.find((h) => h.id === hostId),
      endpoints: endpointsByHost[hostId] ?? [],
    })),
    createHost: vi.fn(async () => hosts[1]),
    updateHost: vi.fn(async () => hosts[0]),
    deleteHost: vi.fn(async () => undefined),
  };
});

describe("StormApp (design prototype port)", () => {
  // StormApp only ever renders behind auth, and admin-only surfaces (the
  // workspace Members page) key off the signed-in user — so sign one in.
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: 1, username: "admin", email: "admin@sbertech.ru", full_name: null, avatar_url: null,
        role: "admin", project_role: "lead", is_active: true, password_changed_at: null,
        created_at: "2026-01-01T00:00:00Z",
      },
      isInitialized: true,
    });
    // mockResolvedValue survives the test that set it — reset it so the bell stays
    // empty for everyone else (its rows repeat project/finding names).
    vi.mocked(api.listNotifications).mockResolvedValue({ items: [], total: 0, page: 1, size: 20, pages: 1 });
  });
  afterEach(() => {
    useAuthStore.setState({ user: null, isInitialized: false });
  });

  it("renders the Projects landing with backend rows and sidebar", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    expect(await screen.findByText("Acme Corp — External Perimeter")).toBeInTheDocument();
    expect(screen.getByText("Northwind API")).toBeInTheDocument();
    expect(screen.getAllByText("STORM").length).toBeGreaterThan(0);
    expect(screen.getByText("My Tasks")).toBeInTheDocument();
  });

  it("switches to the Archived tab", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    await screen.findByText("Acme Corp — External Perimeter");
    expect(screen.queryByText("Globex VPN Audit")).not.toBeInTheDocument();
    const archivedTab = screen.getAllByText("Archived").find((n) => n.closest(".tab"));
    fireEvent.click(archivedTab as HTMLElement);
    expect(await screen.findByText("Globex VPN Audit")).toBeInTheDocument();
    expect(screen.queryByText("Northwind API")).not.toBeInTheDocument();
  });

  it("opens a project and lists its Vulnerabilities from the backend", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByText("Vulnerabilities"));
    expect(await screen.findByText("IDOR on GET /orders/{id}")).toBeInTheDocument();
    expect(screen.getByText("JWT algorithm confusion (alg=none)")).toBeInTheDocument();
    expect(vi.mocked(api.getVulnerabilities)).toHaveBeenCalledWith(2);
  });

  it("filters vulnerabilities by author (AND logic)", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByText("Vulnerabilities"));
    await screen.findByText("IDOR on GET /orders/{id}");
    fireEvent.change(screen.getByPlaceholderText("Filter by author…"), { target: { value: "m.antonov" } });
    expect(screen.getByText("Mass assignment on order update")).toBeInTheDocument();
    expect(screen.queryByText("IDOR on GET /orders/{id}")).not.toBeInTheDocument();
  });

  it("opens a vulnerability detail page and can add a reproduction step", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByText("Vulnerabilities"));
    fireEvent.click(await screen.findByText("IDOR on GET /orders/{id}"));
    expect(screen.getByText("All findings")).toBeInTheDocument();
    const before = screen.getAllByPlaceholderText("Describe this step… (paste a screenshot to attach)").length;
    fireEvent.click(screen.getByText("Add step"));
    expect(screen.getAllByPlaceholderText("Describe this step… (paste a screenshot to attach)").length).toBe(before + 1);
  });

  // A finding's card is deep-linkable: its real id goes into the URL, which is
  // what notification and activity-feed links point at.
  it("puts the vulnerability id in the URL when its card is opened", async () => {
    render(<MemoryRouter initialEntries={["/projects/2/vulns"]}><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("IDOR on GET /orders/{id}"));
    expect(await screen.findByDisplayValue("IDOR on GET /orders/{id}")).toBeInTheDocument();
  });

  // The reverse: landing straight on /projects/2/vulns/72 must open that finding.
  it("opens a vulnerability directly from a deep link", async () => {
    render(<MemoryRouter initialEntries={["/projects/2/vulns/72"]}><StormApp /></MemoryRouter>);
    expect(await screen.findByDisplayValue("JWT algorithm confusion (alg=none)")).toBeInTheDocument();
  });

  it("derives vulnerability severity from a CVSS 4.0 vector", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByText("Vulnerabilities"));
    fireEvent.click(await screen.findByText("IDOR on GET /orders/{id}"));
    const vector = screen.getByPlaceholderText(/CVSS:4\.0/);
    fireEvent.change(vector, { target: { value: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" } });
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("opens a read-only viewer for a note authored by someone else", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByText("Notes"));
    fireEvent.click(await screen.findByText("Auth model"));
    expect(screen.getByText("Read only")).toBeInTheDocument();
  });

  it("creates a new project through the backend API", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    await screen.findByText("Acme Corp — External Perimeter");
    fireEvent.click(screen.getByRole("button", { name: /New project/i }));
    fireEvent.change(screen.getByPlaceholderText("e.g. Acme Corp — External Perimeter"), { target: { value: "Initech Web App" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(vi.mocked(api.createProject)).toHaveBeenCalledWith(expect.objectContaining({ name: "Initech Web App" }));
  });

  // "API keys" are the backend's agent tokens; only their prefix is ever shown.
  it("navigates to Profile and lists API keys from the backend", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(screen.getByText("Profile"));
    expect(screen.getByRole("heading", { name: "Profile Settings" })).toBeInTheDocument();
    fireEvent.click(screen.getByText("API & Automation"));
    expect(await screen.findByText("CI pipeline")).toBeInTheDocument();
    expect(screen.getByText("Slack alerts bot")).toBeInTheDocument();
    expect(vi.mocked(api.listAgentTokens)).toHaveBeenCalled();
  });

  it("opens the workspace Members admin page with users from the backend", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(screen.getByText("Members"));
    expect(screen.getByRole("heading", { name: "Members" })).toBeInTheDocument();
    expect(await screen.findByText("alice@example.com")).toBeInTheDocument();
    expect(screen.getByText("diana@example.com")).toBeInTheDocument();
  });

  const openHostsSection = async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    const hostsCard = screen.getAllByText("Hosts").find((n) => n.closest(".statc"));
    fireEvent.click(hostsCard as HTMLElement);
  };

  it("renders hosts loaded from the backend", async () => {
    await openHostsSection();
    // `.hostname` scopes to the hosts table (the export modal lists the same names).
    expect(await screen.findByText("api.northwind.test", { selector: ".hostname" })).toBeInTheDocument();
    expect(screen.getByText("test.com", { selector: ".hostname" })).toBeInTheDocument();
    expect(vi.mocked(api.getHosts)).toHaveBeenCalledWith(2);
    // Ports come from the nested ip_addresses[].ports of the API payload.
    expect(screen.getByText("443/tcp")).toBeInTheDocument();
    expect(screen.getByText("22/tcp")).toBeInTheDocument();
  });

  it("populates host endpoints from the backend on the Recon → Endpoints view", async () => {
    await openHostsSection();
    await screen.findByText("api.northwind.test", { selector: ".hostname" });
    const endpointsItem = screen.getAllByText("Endpoints").find((n) => n.closest(".menu"));
    fireEvent.click(endpointsItem as HTMLElement);
    // Only host 11 has endpoints, so it is the sole group; expand it to list them.
    const group = screen.getAllByText("api.northwind.test").find((n) => n.closest(".prow"));
    fireEvent.click(group as HTMLElement);
    expect(await screen.findByText("/v1/orders")).toBeInTheDocument();
    expect(vi.mocked(api.getHost)).toHaveBeenCalledWith(2, 11);
  });

  it("adds a hostname-only host through the backend API", async () => {
    await openHostsSection();
    await screen.findByText("api.northwind.test", { selector: ".hostname" });
    fireEvent.click(screen.getByRole("button", { name: /Add host/i }));
    fireEvent.change(screen.getByPlaceholderText("e.g. app.acme-corp.com"), { target: { value: "test.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(vi.mocked(api.createHost)).toHaveBeenCalledWith(2, expect.objectContaining({ hostname: "test.com" }));
  });

  it("toggles the project sort order", () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    const sortBtn = screen.getAllByText("Last updated").find((el) => el.closest(".iconbtn"));
    fireEvent.click(sortBtn as HTMLElement);
    expect(screen.getByText("First updated")).toBeInTheDocument();
  });

  // The project detail is backend-backed, so editing it must PUT to the API
  // (the rename then comes back via a reload, not from local state).
  it("edits the project detail through the backend API", async () => {
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    const main = document.querySelector("main") as HTMLElement;
    fireEvent.click(within(main).getByRole("button", { name: /Edit/i }));
    const modal = screen.getByText("Edit project").closest(".modalcard") as HTMLElement;
    const nameInput = within(modal).getByDisplayValue("Northwind API");
    fireEvent.change(nameInput, { target: { value: "Northwind API v2" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Save" }));
    expect(vi.mocked(api.updateProject)).toHaveBeenCalledWith(2, expect.objectContaining({ name: "Northwind API v2" }));
  });

  // Report generation is backed by the two Word templates the backend already has:
  // "szi" (certification) and "pp" (internal acceptance).
  it("generates a certification report through the backend API", async () => {
    const spy = vi.spyOn(api, "downloadProjectCertificationReport").mockResolvedValue(new Blob(["x"]));
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByRole("button", { name: /Generate report/i }));
    fireEvent.click(screen.getByText("Скачать .docx"));
    expect(spy).toHaveBeenCalledWith(2);
  });

  it("generates an internal-acceptance report when that type is picked", async () => {
    const spy = vi.spyOn(api, "downloadProjectAcceptanceReport").mockResolvedValue(new Blob(["x"]));
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    fireEvent.click(screen.getByRole("button", { name: /Generate report/i }));
    fireEvent.click(screen.getByText("Отчёт внутренней приёмки"));
    fireEvent.click(screen.getByText("Скачать .docx"));
    expect(spy).toHaveBeenCalledWith(2);
  });

  /** One notification of each kind — the four reasons the backend ever sends one. */
  const mockNotifications = () => {
    const ctx = {
      vulnerability_id: null, vulnerability_title: null, note_id: null, note_title: null,
      project_id: 2, project_name: "Northwind API", host_id: null, commenter_username: "admin", status: null,
    };
    vi.mocked(api.listNotifications).mockResolvedValue({
      items: [
        {
          id: 1, type: "mention", comment_id: 5, note_comment_id: null, is_read: false,
          created_at: "2026-07-10T00:00:00Z",
          context: { ...ctx, vulnerability_id: 71, vulnerability_title: "IDOR on GET /orders/{id}", host_id: 11, commenter_username: "alice" },
        },
        { id: 2, type: "project_member_added", comment_id: null, note_comment_id: null, is_read: false, created_at: "2026-07-10T00:00:00Z", context: { ...ctx } },
        {
          id: 3, type: "vuln_status_changed", comment_id: null, note_comment_id: null, is_read: true,
          created_at: "2026-07-10T00:00:00Z",
          context: { ...ctx, vulnerability_id: 72, vulnerability_title: "JWT algorithm confusion (alg=none)", status: "wont_fix" },
        },
        { id: 4, type: "project_status_changed", comment_id: null, note_comment_id: null, is_read: true, created_at: "2026-07-10T00:00:00Z", context: { ...ctx, status: "freeze" } },
      ],
      total: 4, page: 1, size: 20, pages: 1,
    });
  };

  /* There are exactly four reasons to be notified, and each reads as its own
     sentence — not everything is "mentioned you in". */
  it("words each kind of notification for what it is", async () => {
    mockNotifications();
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    expect(await screen.findByText("mentioned you in")).toBeInTheDocument();
    expect(screen.getByText("added you to")).toBeInTheDocument();
    expect(screen.getByText("set your finding to Won't fix —")).toBeInTheDocument();
    expect(screen.getByText("changed the project status to Freeze —")).toBeInTheDocument();
    // Two of the four are unread.
    expect(screen.getByText("2 new")).toBeInTheDocument();
  });

  // Clicking a finding notification opens that finding, not just its project.
  it("opens the finding a notification points at", async () => {
    mockNotifications();
    render(<MemoryRouter><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("IDOR on GET /orders/{id}"));
    expect(await screen.findByDisplayValue("IDOR on GET /orders/{id}")).toBeInTheDocument();
    expect(vi.mocked(api.markNotificationRead)).toHaveBeenCalledWith(1);
  });

  it("renders the activity feed without ports, tags or IP labels", async () => {
    render(<MemoryRouter initialEntries={["/projects/2/activity"]}><StormApp /></MemoryRouter>);
    // Each entity type is its own action, counted inline after the verb.
    expect(await screen.findByText("reported", { exact: false })).toBeInTheDocument();
    // Ports are excluded outright.
    expect(screen.queryByText("443/tcp", { exact: false })).not.toBeInTheDocument();
    // No HOST/IP/ENDPOINT tags — the header already says what these are.
    expect(screen.queryByText("IP", { selector: "span.mono", exact: true })).not.toBeInTheDocument();
    // The IP shows bare, without its "(internal)" label.
    expect(screen.getByText("203.0.113.10")).toBeInTheDocument();
    expect(screen.queryByText("203.0.113.10 (internal)")).not.toBeInTheDocument();
    // An UPDATE row has no details: the host name comes from the loaded hosts.
    expect(screen.getByText("api.northwind.test")).toBeInTheDocument();
  });

  // Activity → "Show details" → back must land on the findings list, not hang.
  it("returns from a finding opened via the activity feed", async () => {
    render(<MemoryRouter initialEntries={["/projects/2/activity"]}><StormApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Show details"));
    expect(await screen.findByDisplayValue("IDOR on GET /orders/{id}")).toBeInTheDocument();
    fireEvent.click(screen.getByText("All findings"));
    expect(screen.queryByDisplayValue("IDOR on GET /orders/{id}")).not.toBeInTheDocument();
  });

  /* Browser Back after opening a finding from the activity feed. This used to be
     broken: the URL changed, but the state → URL effect still held the previous
     screen and navigated forward again, so Back never landed. `navigate(-1)` is
     exactly what the browser's Back button does at the router level. */
  it("honours browser Back from a finding opened via the activity feed", async () => {
    const Back = () => {
      const navigate = useNavigate();
      const { pathname } = useLocation();
      return (
        <>
          <button onClick={() => navigate(-1)}>test-back</button>
          <span data-testid="path">{pathname}</span>
        </>
      );
    };
    render(
      <MemoryRouter initialEntries={["/projects/2/activity"]}>
        <StormApp />
        <Back />
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByText("Show details"));
    await screen.findByDisplayValue("IDOR on GET /orders/{id}");
    expect(screen.getByTestId("path")).toHaveTextContent("/projects/2/vulns/71");

    fireEvent.click(screen.getByText("test-back"));

    expect(await screen.findByText("Show details")).toBeInTheDocument();
    expect(screen.getByTestId("path")).toHaveTextContent("/projects/2/activity");
    expect(screen.queryByDisplayValue("IDOR on GET /orders/{id}")).not.toBeInTheDocument();
  });

  // A project the backend refuses (403) must not render as an empty project.
  it("shows the no-access page when the backend refuses the project", async () => {
    vi.mocked(api.getProjectMembers).mockRejectedValueOnce(
      Object.assign(new Error("forbidden"), { isAxiosError: true, response: { status: 403 } })
    );
    render(<MemoryRouter initialEntries={["/projects/2"]}><StormApp /></MemoryRouter>);
    expect(await screen.findByText("Доступа нет")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Вернуться к проектам/i })).toBeInTheDocument();
  });
});
