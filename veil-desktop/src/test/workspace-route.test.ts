import { describe, expect, it } from "vitest";
import { workspaceRouteMatchesScope, type WorkspaceRoute, type WorkspaceRouteScope } from "@/stores/app";

const scope = (generation: string): WorkspaceRouteScope => ({
  canonicalServerOrigin: "https://node.example:443",
  bindingGeneration: generation,
});

describe("origin-scoped workspace route", () => {
  it("does not carry a Space or Room across a binding generation", () => {
    const route: WorkspaceRoute = {
      kind: "space",
      spaceId: "11111111-1111-4111-8111-111111111111",
      roomId: "22222222-2222-4222-8222-222222222222",
      scope: scope("generation-a"),
    };
    expect(workspaceRouteMatchesScope(route, scope("generation-a"))).toBe(true);
    expect(workspaceRouteMatchesScope(route, scope("generation-b"))).toBe(false);
    expect(workspaceRouteMatchesScope(route, null)).toBe(false);
  });

  it("keeps unauthenticated Home separate from an authenticated Node", () => {
    const route: WorkspaceRoute = { kind: "home", view: "overview", scope: null };
    expect(workspaceRouteMatchesScope(route, null)).toBe(true);
    expect(workspaceRouteMatchesScope(route, scope("generation-a"))).toBe(false);
  });

  it("never equates identical IDs from different self-hosted origins", () => {
    const route: WorkspaceRoute = {
      kind: "circle",
      circleId: "33333333-3333-4333-8333-333333333333",
      scope: scope("generation-a"),
    };
    expect(workspaceRouteMatchesScope(route, {
      canonicalServerOrigin: "https://other-node.example:443",
      bindingGeneration: "generation-a",
    })).toBe(false);
  });
});
