import { jsx as _jsx } from "react/jsx-runtime";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ProjectTreeNav } from "./ProjectTreeNav";
import { renderWithProviders } from "../test/renderWithProviders";
describe("ProjectTreeNav", () => {
    it("opens a host section with the requested target section", async () => {
        const onSelectHost = vi.fn();
        const onSelectSection = vi.fn();
        const onOpenHost = vi.fn();
        renderWithProviders(_jsx(ProjectTreeNav, { hosts: [
                {
                    id: "host-b",
                    project_id: "project-1",
                    ip_address: "10.0.0.2",
                    hostname: "host-b",
                    status: "up",
                    notes: null,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString(),
                },
            ], selectedHostId: "host-a", selectedSection: "overview", isCollapsed: false, portsCount: 0, endpointsCount: 0, vulnerabilitiesCount: 0, hostStatsById: { "host-b": { portsCount: 4, endpointsCount: 2, vulnerabilitiesCount: 1 } }, onToggleCollapsed: () => undefined, onSelectSection: onSelectSection, onSelectHost: onSelectHost, onOpenHost: onOpenHost }));
        await userEvent.click(screen.getByTestId("KeyboardArrowRightIcon").closest("button"));
        await userEvent.click(screen.getByText("Порты (4)"));
        expect(onSelectHost).toHaveBeenCalledWith("host-b");
        expect(onSelectSection).toHaveBeenCalledWith("ports");
        expect(onOpenHost).toHaveBeenCalledWith("host-b", "ports");
    });
});
