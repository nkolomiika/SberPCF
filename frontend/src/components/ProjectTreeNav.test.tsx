import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ProjectTreeNav } from "./ProjectTreeNav";
import { renderWithProviders } from "../test/renderWithProviders";

describe("ProjectTreeNav", () => {
  it("opens a host section with the requested target section", async () => {
    const onSelectHost = vi.fn();
    const onSelectSection = vi.fn();
    const onOpenHost = vi.fn();

    renderWithProviders(
      <ProjectTreeNav
        viewMode="host"
        hosts={[
          {
            id: "host-b",
            project_id: "project-1",
            ip_address: "10.0.0.2",
            ip_addresses: [],
            hostname: "host-b",
            status: "up",
            notes: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ]}
        selectedHostId="host-b"
        selectedSection="hosts"
        isCollapsed={false}
        portsCount={0}
        endpointsCount={0}
        vulnerabilitiesCount={0}
        hostStatsById={{ "host-b": { portsCount: 4, ipAddressesCount: 2, endpointsCount: 2, vulnerabilitiesCount: 1 } }}
        onToggleCollapsed={() => undefined}
        onSelectSection={onSelectSection}
        onSelectHost={onSelectHost}
        onOpenHost={onOpenHost}
      />
    );

    await userEvent.click(screen.getByText("IP-адреса (2)"));

    expect(onSelectHost).toHaveBeenCalledWith("host-b");
    expect(onSelectSection).toHaveBeenCalledWith("ports");
    expect(onOpenHost).toHaveBeenCalledWith("host-b", "ports");
  });

  it("selects notes section from root navigation", async () => {
    const onSelectSection = vi.fn();

    renderWithProviders(
      <ProjectTreeNav
        hosts={[]}
        selectedHostId={null}
        selectedSection="overview"
        isCollapsed={false}
        portsCount={0}
        endpointsCount={0}
        vulnerabilitiesCount={0}
        onToggleCollapsed={() => undefined}
        onSelectSection={onSelectSection}
        onSelectHost={() => undefined}
      />
    );

    await userEvent.click(screen.getByText("Заметки"));
    expect(onSelectSection).toHaveBeenCalledWith("notes");
  });
});
