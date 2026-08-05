import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

const appWindowMock = vi.hoisted(() => ({
  close: vi.fn(),
  isMaximized: vi.fn(async () => false),
  maximize: vi.fn(),
  minimize: vi.fn(),
  onResized: vi.fn(async () => () => undefined),
  startDragging: vi.fn(),
  unmaximize: vi.fn(),
}));

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => appWindowMock,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

import {
  composerOwnsFocus,
  scheduleComposerFocusRestore,
  useUnhandledNativeContextMenuSuppression,
} from "@/App";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
  EmojiPicker,
  isDesktopEmojiCompatible,
} from "@/components/ui/emoji-picker";

describe("App interaction regressions", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps a real Kobalte context menu available while suppressing only the native fallback", async () => {
    const Harness = () => {
      useUnhandledNativeContextMenuSuppression();
      return (
        <ContextMenu>
          <ContextMenuTrigger>
            <button type="button">Conversation actions</button>
          </ContextMenuTrigger>
          <ContextMenuContent>
            <ContextMenuItem>Rename conversation</ContextMenuItem>
          </ContextMenuContent>
        </ContextMenu>
      );
    };
    const { unmount } = render(() => <Harness />);

    fireEvent.contextMenu(screen.getByRole("button", { name: "Conversation actions" }), {
      clientX: 24,
      clientY: 36,
    });

    expect(await screen.findByRole("menuitem", { name: "Rename conversation" }))
      .toBeInTheDocument();

    const unhandled = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    document.body.dispatchEvent(unhandled);
    expect(unhandled.defaultPrevented).toBe(true);

    unmount();
    const afterCleanup = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    document.body.dispatchEvent(afterCleanup);
    expect(afterCleanup.defaultPrevented).toBe(false);
  });

  it("restores composer focus only while the original conversation context still owns it", async () => {
    const { container } = render(() => (
      <>
        <div class="veil-message-composer">
          <textarea aria-label="Message Alice" />
          <button type="button">Send message</button>
        </div>
        <button type="button">Open settings</button>
      </>
    ));
    const input = screen.getByRole("textbox", { name: "Message Alice" }) as HTMLTextAreaElement;
    const send = screen.getByRole("button", { name: "Send message" });
    const settings = screen.getByRole("button", { name: "Open settings" });

    input.focus();
    expect(composerOwnsFocus(input)).toBe(true);
    send.focus();
    expect(composerOwnsFocus(input)).toBe(true);

    // A temporarily disabled composer loses focus in WebView2. Once the ACK
    // arrives, it should regain focus while the same context is still active.
    send.blur();
    scheduleComposerFocusRestore(input, () => true);
    await waitFor(() => expect(input).toHaveFocus());

    // Deliberate navigation/focus changes must win over the pending restore.
    input.blur();
    settings.focus();
    scheduleComposerFocusRestore(input, () => true);
    await Promise.resolve();
    expect(settings).toHaveFocus();

    settings.blur();
    scheduleComposerFocusRestore(input, () => false);
    await Promise.resolve();
    expect(input).not.toHaveFocus();
    expect(container.querySelector(".veil-message-composer")).toBeInTheDocument();
  });

  it("bounds the emoji grid and omits native glyphs that render as tofu on Windows", async () => {
    render(() => (
      <div>
        <EmojiPicker onSelect={() => undefined} />
        <div id="island-portal" />
      </div>
    ));
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Choose emoji" }));
    await user.click(screen.getByRole("tab", { name: "Gestures & Body" }));

    const scrollRegion = document.querySelector<HTMLElement>("[data-emoji-scroll-region]");
    const grid = document.querySelector<HTMLElement>("[data-emoji-grid]");
    expect(scrollRegion).not.toBeNull();
    expect(scrollRegion?.style.overflowX).toBe("hidden");
    expect(scrollRegion?.style.minWidth).toBe("0px");
    expect(grid?.style.gridTemplateColumns).toBe("repeat(8, minmax(0, 1fr))");
    expect(grid?.style.minWidth).toBe("0px");

    const renderedEmoji = Array.from(
      document.querySelectorAll<HTMLElement>("[data-emoji-value]"),
      (element) => element.dataset.emojiValue ?? "",
    );
    expect(renderedEmoji).toContain("👋");
    expect(renderedEmoji.every(isDesktopEmojiCompatible)).toBe(true);
    expect(renderedEmoji).not.toContain("🫱");
    expect(renderedEmoji).not.toContain("🫲");
    expect(isDesktopEmojiCompatible("🫶")).toBe(false);
    expect(isDesktopEmojiCompatible("🤌")).toBe(false);
    expect(isDesktopEmojiCompatible("🦾")).toBe(false);
    expect(isDesktopEmojiCompatible("🍕")).toBe(true);
  });
});
