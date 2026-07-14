import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CommandPalette } from "@/components/ui/CommandPalette";
import { appStore, type AuthenticatedServerScope } from "@/stores/app";
import type { SearchHitDto } from "@/lib/identityIpcBoundary";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

const SCOPE: AuthenticatedServerScope = {
  canonicalServerOrigin: "https://chat.example.test:443",
  userId: "550e8400-e29b-41d4-a716-446655440001",
  bindingGeneration: "1",
};

const hit = (id: string, body: string): SearchHitDto => ({
  id,
  conversationId: `conversation-${id}`,
  body,
  ts: 1,
  score: 1,
});

function renderPalette(onNavigate: (selected: SearchHitDto) => Promise<boolean>) {
  const Harness = () => {
    const [open, setOpen] = createSignal(true);
    return (
      <>
        <div id="island-portal" />
        <CommandPalette
          open={open()}
          onClose={() => setOpen(false)}
          onNavigate={onNavigate}
          onOpenIdentity={() => undefined}
        />
      </>
    );
  };
  return render(() => <Harness />);
}

function searchInvocation(query: string): boolean {
  return invokeMock.mock.calls.some(([command, args]) => (
    command === "search_messages"
    && (args as { query?: unknown } | undefined)?.query === query
  ));
}

describe("message search product boundary", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    vi.spyOn(appStore, "authenticatedServerScope").mockReturnValue(SCOPE);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("ignores an older search response that arrives after the current query", async () => {
    let resolveOlder!: (value: unknown) => void;
    let resolveCurrent!: (value: unknown) => void;
    invokeMock.mockImplementation((command: string, args?: unknown) => {
      if (command === "get_search_coverage") return Promise.resolve(null);
      if (command !== "search_messages") return Promise.resolve(undefined);
      const query = (args as { query: string }).query;
      if (query === "older") {
        return new Promise((resolve) => { resolveOlder = resolve; });
      }
      if (query === "current") {
        return new Promise((resolve) => { resolveCurrent = resolve; });
      }
      return Promise.resolve([]);
    });
    renderPalette(async () => true);
    const input = screen.getByRole("combobox", { name: "Search messages" });

    fireEvent.input(input, { target: { value: "older" } });
    await waitFor(() => expect(searchInvocation("older")).toBe(true));
    fireEvent.input(input, { target: { value: "current" } });
    await waitFor(() => expect(searchInvocation("current")).toBe(true));

    resolveCurrent([hit("current", "current result")]);
    const option = await screen.findByRole("option");
    expect(option).toHaveTextContent("current result");

    resolveOlder([hit("older", "obsolete result")]);
    await waitFor(() => expect(option).not.toHaveTextContent("obsolete result"));
    expect(option).toHaveTextContent("current result");
  });

  it("presents a search failure distinctly from an empty result", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_search_coverage") return Promise.resolve(null);
      if (command === "search_messages") return Promise.reject(new Error("local index unavailable"));
      return Promise.resolve(undefined);
    });
    renderPalette(async () => true);

    fireEvent.input(screen.getByRole("combobox", { name: "Search messages" }), {
      target: { value: "cipher" },
    });

    expect(await screen.findByText("Search unavailable")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Search failed. Your local index was not changed.",
    );
    expect(screen.queryByText(/No matches for/)).not.toBeInTheDocument();
  });

  it("shows the persisted truncation warning reported by automatic indexing", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_search_coverage") {
        return Promise.resolve({
          indexedMessages: 12_345,
          indexedSourceBytes: 64 * 1024 * 1024,
          maxSourceBytes: 64 * 1024 * 1024,
          truncated: true,
        });
      }
      if (command === "search_messages") return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
    renderPalette(async () => true);

    const warning = await screen.findByTestId("search-coverage-warning");
    expect(warning).toHaveTextContent("Search covers the newest 12,345 messages");
    expect(warning).toHaveTextContent("Older local history is omitted");
    expect(invokeMock).toHaveBeenCalledWith("get_search_coverage");
  });

  it("reports unknown completeness without turning it into a search failure", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_search_coverage") {
        return Promise.reject(new Error("coverage IPC unavailable"));
      }
      if (command === "search_messages") return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
    renderPalette(async () => true);

    const note = await screen.findByTestId("search-coverage-unknown");
    expect(note).toHaveTextContent("Search completeness is unknown");
    expect(note).toHaveTextContent("Search itself remains available");
    expect(screen.queryByText("Search unavailable")).not.toBeInTheDocument();
  });

  it("reports that the current session has no published coverage snapshot", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_search_coverage") return Promise.resolve(null);
      if (command === "search_messages") return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
    renderPalette(async () => true);

    const note = await screen.findByTestId("search-coverage-unknown");
    expect(note).toHaveTextContent("this session has no published index snapshot");
    expect(note).toHaveTextContent("Search itself remains available");
    expect(screen.queryByText("Search unavailable")).not.toBeInTheDocument();
  });

  it("keeps the dialog open on exact-navigation failure and blocks duplicate opens", async () => {
    let finishNavigation!: (opened: boolean) => void;
    const navigate = vi.fn(() => new Promise<boolean>((resolve) => {
      finishNavigation = resolve;
    }));
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_search_coverage") return Promise.resolve(null);
      if (command === "search_messages") return Promise.resolve([hit("target", "exact target")]);
      return Promise.resolve(undefined);
    });
    renderPalette(navigate);
    const input = screen.getByRole("combobox", { name: "Search messages" });
    fireEvent.input(input, { target: { value: "target" } });
    const option = await screen.findByRole("option");

    fireEvent.click(option);
    fireEvent.click(option);
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith(expect.objectContaining({
      id: "target",
      conversationId: "conversation-target",
    }));
    fireEvent.keyDown(document, { key: "Escape", code: "Escape" });
    expect(screen.getByRole("dialog", { name: "Search messages" })).toBeInTheDocument();

    finishNavigation(false);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not open that exact message",
    );
    expect(screen.getByRole("dialog", { name: "Search messages" })).toBeInTheDocument();
    await waitFor(() => expect(input).toHaveFocus());
  });

  it("keeps the modal open until exact navigation reports a rendered target", async () => {
    let confirmRendered!: (opened: boolean) => void;
    const navigate = vi.fn(() => new Promise<boolean>((resolve) => {
      confirmRendered = resolve;
    }));
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_search_coverage") return Promise.resolve(null);
      if (command === "search_messages") return Promise.resolve([hit("rendered", "rendered target")]);
      return Promise.resolve(undefined);
    });
    renderPalette(navigate);
    const input = screen.getByRole("combobox", { name: "Search messages" });
    fireEvent.input(input, { target: { value: "rendered" } });
    fireEvent.click(await screen.findByRole("option"));

    expect(screen.getByRole("dialog", { name: "Search messages" })).toBeInTheDocument();
    confirmRendered(true);
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Search messages" })).not.toBeInTheDocument();
    });
  });
});
