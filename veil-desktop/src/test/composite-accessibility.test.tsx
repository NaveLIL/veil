import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FriendsPanel } from "@/components/chat/FriendsPanel";
import { CommandPalette } from "@/components/ui/CommandPalette";
import { EmojiPicker } from "@/components/ui/emoji-picker";
import { IslandDialog } from "@/components/ui/IslandDialog";
import { appStore, type Friend, type FriendRequest } from "@/stores/app";
import { IDENTITY_ROW_RENDER_BUDGET } from "@/components/identity/identityRenderBudget";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

const axeOptions = {
  rules: {
    // jsdom does not perform layout or resolve CSS custom properties.
    "color-contrast": { enabled: false },
  },
};

describe("composite widget accessibility", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("provides a searchable, named emoji popover with roving category tabs", async () => {
    const onSelect = vi.fn();
    render(() => (
      <div>
        <EmojiPicker onSelect={onSelect} />
        <div id="island-portal" />
      </div>
    ));
    const user = userEvent.setup();
    const trigger = screen.getByRole("button", { name: "Choose emoji" });

    await user.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("dialog", { name: "Choose emoji" })).toBeInTheDocument();

    const search = screen.getByRole("textbox", { name: "Search emoji" });
    await waitFor(() => expect(search).toHaveFocus());

    const frequent = screen.getByRole("tab", { name: "Frequently used" });
    frequent.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Smileys & People" })).toHaveAttribute("aria-selected", "true");

    await user.click(search);
    await user.type(search, "pizza");
    const pizza = screen.getByRole("button", { name: "Insert pizza" });
    expect(pizza).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Insert red apple" })).not.toBeInTheDocument();

    await user.click(pizza);
    expect(onSelect).toHaveBeenCalledWith("🍕");
    await waitFor(() => expect(trigger).toHaveFocus());
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });

  it("exposes Friends filters as arrow-key navigable tabs and panels", async () => {
    render(() => <FriendsPanel />);
    const user = userEvent.setup();
    const all = screen.getByRole("tab", { name: "All" });

    expect(all).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel", { name: "All" })).toBeInTheDocument();

    all.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: /Online/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel", { name: /Online/ })).toBeInTheDocument();

    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Add" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel", { name: "Add" })).toBeInTheDocument();
  });

  it("bounds remote friend and request rows to the active presentation window", async () => {
    const friends: Friend[] = Array.from({ length: 300 }, (_, index) => ({
      userId: `550e8400-e29b-41d4-a716-${(index + 1).toString(16).padStart(12, "0")}`,
      username: `friend-${index + 1}`,
      status: 1,
    }));
    const requests: FriendRequest[] = Array.from({ length: 300 }, (_, index) => ({
      requestId: `request-${index + 1}`,
      fromUserId: `550e8400-e29b-41d4-a716-${(index + 301).toString(16).padStart(12, "0")}`,
      fromUsername: `requester-${index + 1}`,
      timestamp: index,
      outgoing: false,
    }));
    vi.spyOn(appStore, "friends").mockReturnValue(friends);
    vi.spyOn(appStore, "friendRequests").mockReturnValue(requests);

    const user = userEvent.setup();
    const { container } = render(() => <FriendsPanel />);

    expect(container.querySelectorAll("[data-user-avatar]")).toHaveLength(IDENTITY_ROW_RENDER_BUDGET);
    expect(screen.getByRole("status")).toHaveTextContent("Showing the first 256 of 300 friends");

    await user.click(screen.getByRole("tab", { name: /Pending/ }));
    expect(container.querySelectorAll("[data-user-avatar]")).toHaveLength(IDENTITY_ROW_RENDER_BUDGET);
    expect(screen.getByRole("status")).toHaveTextContent("Showing the first 256 of 300 requests");
  });

  it("restores focus when a controlled island dialog closes with Escape", async () => {
    const Harness = () => {
      const [open, setOpen] = createSignal(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Open details</button>
          <IslandDialog open={open()} onClose={() => setOpen(false)} title="Details">
            <button type="button">Dialog action</button>
          </IslandDialog>
          <div id="island-portal" />
        </>
      );
    };
    render(() => <Harness />);
    const user = userEvent.setup();
    const launcher = screen.getByRole("button", { name: "Open details" });

    await user.click(launcher);
    expect(screen.getByRole("dialog", { name: "Details" })).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Details" })).not.toBeInTheDocument());
    await waitFor(() => expect(launcher).toHaveFocus());
  });

  it("uses combobox/listbox semantics and restores focus after opening a result", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command !== "search_messages") return 0;
      return [
        { id: "m1", conversationId: "c1", sender: "alice", body: "first cipher result", ts: 1, score: 2 },
        { id: "m2", conversationId: "c2", sender: "bob", body: "second cipher result", ts: 2, score: 1 },
      ];
    });
    const navigate = vi.fn(async () => undefined);
    const Harness = () => {
      const [open, setOpen] = createSignal(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Open search</button>
          <CommandPalette open={open()} onClose={() => setOpen(false)} onNavigate={navigate} />
          <div id="island-portal" />
        </>
      );
    };
    render(() => <Harness />);
    const user = userEvent.setup();
    const launcher = screen.getByRole("button", { name: "Open search" });

    await user.click(launcher);
    const combobox = screen.getByRole("combobox", { name: "Search messages" });
    await waitFor(() => expect(combobox).toHaveFocus());
    expect(screen.getByRole("dialog", { name: "Search messages" })).toBeInTheDocument();

    fireEvent.input(combobox, { target: { value: "cipher" } });
    const options = await screen.findAllByRole("option");
    expect(options).toHaveLength(2);
    expect(combobox).toHaveAttribute("aria-expanded", "true");
    expect(combobox).toHaveAttribute("aria-activedescendant", options[0].id);

    await user.keyboard("{ArrowDown}");
    expect(options[1]).toHaveAttribute("aria-selected", "true");
    expect(combobox).toHaveAttribute("aria-activedescendant", options[1].id);
    await user.keyboard("{Enter}");

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("c2"));
    await waitFor(() => expect(launcher).toHaveFocus());
  });

  it("has no structural axe violations in the open emoji picker", async () => {
    render(() => (
      <div>
        <EmojiPicker onSelect={() => undefined} />
        <div id="island-portal" />
      </div>
    ));
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Choose emoji" }));

    const result = await axe.run(document.body, axeOptions);
    expect(result.violations).toEqual([]);
  });
});
