import { Component, createSignal, For, Show, onMount, onCleanup } from "solid-js";

/* ── Emoji categories with curated sets ────────────── */
const CATEGORIES = [
  {
    id: "frequent",
    icon: "🕐",
    label: "Frequently used",
    emojis: ["👍", "❤️", "😂", "🔥", "😭", "🥺", "✨", "🙏", "😊", "🎉", "💀", "😍", "🤣", "😢", "👀", "💜", "🤔", "😮", "👎", "💯", "😎", "🫡", "🤝", "👋"],
  },
  {
    id: "smileys",
    icon: "😀",
    label: "Smileys & People",
    emojis: [
      "😀", "😃", "😄", "😁", "😆", "😅", "🤣", "😂", "🙂", "😊",
      "😇", "🥰", "😍", "🤩", "😘", "😗", "😚", "😙", "🥲", "😋",
      "😛", "😜", "🤪", "😝", "🤑", "🤗", "🤭", "🫢", "🫣", "🤫",
      "🤔", "🫡", "🤐", "🤨", "😐", "😑", "😶", "🫥", "😏", "😒",
      "🙄", "😬", "🤥", "😌", "😔", "😪", "🤤", "😴", "😷", "🤒",
      "🤕", "🤢", "🤮", "🥵", "🥶", "🥴", "😵", "🤯", "🤠", "🥳",
      "🥸", "😎", "🤓", "🧐", "😕", "🫤", "😟", "🙁", "😮", "😯",
      "😲", "😳", "🥺", "🥹", "😦", "😧", "😨", "😰", "😥", "😢",
      "😭", "😱", "😖", "😣", "😞", "😓", "😩", "😫", "🥱", "😤",
      "😡", "😠", "🤬", "😈", "👿", "💀", "☠️", "💩", "🤡", "👹",
      "👻", "👽", "👾", "🤖", "😺", "😸", "😹", "😻", "😼", "😽",
      "🙀", "😿", "😾",
    ],
  },
  {
    id: "gestures",
    icon: "👋",
    label: "Gestures & Body",
    emojis: [
      "👋", "🤚", "🖐️", "✋", "🖖", "🫱", "🫲", "🫳", "🫴", "🫷",
      "🫸", "👌", "🤌", "🤏", "✌️", "🤞", "🫰", "🤟", "🤘", "🤙",
      "👈", "👉", "👆", "🖕", "👇", "☝️", "🫵", "👍", "👎", "✊",
      "👊", "🤛", "🤜", "👏", "🙌", "🫶", "👐", "🤲", "🤝", "🙏",
      "✍️", "💅", "🤳", "💪", "🦾", "🦿", "🦵", "🦶", "👂", "🦻",
      "👃", "🧠", "🫀", "🫁", "🦷", "🦴", "👀", "👁️", "👅", "👄",
    ],
  },
  {
    id: "hearts",
    icon: "❤️",
    label: "Hearts & Symbols",
    emojis: [
      "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔",
      "❤️‍🔥", "❤️‍🩹", "❣️", "💕", "💞", "💓", "💗", "💖", "💘", "💝",
      "💟", "☮️", "✝️", "☪️", "🕉️", "☸️", "✡️", "🔯", "🕎", "☯️",
      "♾️", "🔱", "⚜️", "🔰", "⭕", "✅", "☑️", "✔️", "❌", "❎",
      "➕", "➖", "➗", "✖️", "💲", "💱",
    ],
  },
  {
    id: "nature",
    icon: "🌿",
    label: "Animals & Nature",
    emojis: [
      "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐻‍❄️", "🐨",
      "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🙈", "🙉", "🙊", "🐒",
      "🐔", "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇", "🐺", "🐗",
      "🐴", "🦄", "🐝", "🪱", "🐛", "🦋", "🐌", "🐞", "🐜", "🪰",
      "🌸", "💮", "🏵️", "🌹", "🥀", "🌺", "🌻", "🌼", "🌷", "🌱",
      "🪴", "🌲", "🌳", "🌴", "🌵", "🌾", "🌿", "☘️", "🍀", "🍁",
    ],
  },
  {
    id: "food",
    icon: "🍕",
    label: "Food & Drink",
    emojis: [
      "🍎", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐", "🍈", "🍒",
      "🍑", "🥭", "🍍", "🥥", "🥝", "🍅", "🍆", "🥑", "🥦", "🥬",
      "🌶️", "🫑", "🌽", "🥕", "🫒", "🧄", "🧅", "🥔", "🍞", "🥐",
      "🥖", "🫓", "🥨", "🧀", "🍕", "🍔", "🍟", "🌭", "🍿", "🧂",
      "🥩", "🍖", "🍗", "🥚", "🍳", "🥞", "🧇", "🥓", "🍰", "🎂",
      "🍩", "🍪", "🍫", "🍬", "🍭", "☕", "🍵", "🧃", "🥤", "🍺",
    ],
  },
  {
    id: "objects",
    icon: "💡",
    label: "Objects & Activities",
    emojis: [
      "⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🎱", "🏓", "🎮",
      "🕹️", "🎲", "🧩", "🎯", "🎪", "🎨", "🎬", "🎤", "🎧", "🎵",
      "🎶", "🎹", "🥁", "🎷", "🎺", "🎸", "🪕", "🎻", "💻", "⌨️",
      "🖥️", "📱", "📞", "💾", "💿", "📷", "📸", "🔍", "🔎", "🔬",
      "🔭", "💡", "🔦", "🔧", "🔨", "⚙️", "🗝️", "🔑", "🔒", "🔓",
      "📎", "✂️", "📌", "📍", "🗑️", "📦", "✉️", "📧", "💰", "💎",
    ],
  },
  {
    id: "flags",
    icon: "🚩",
    label: "Travel & Flags",
    emojis: [
      "🚗", "🚕", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "✈️", "🚀",
      "🛸", "🚁", "⛵", "🚢", "🏠", "🏡", "🏢", "🏣", "🏥", "🏦",
      "⛪", "🕌", "🕍", "⛩️", "🏰", "🏯", "🗼", "🗽", "🗿", "🌍",
      "🌎", "🌏", "🌐", "🗺️", "🧭", "⛰️", "🏔️", "🌋", "🏕️", "🏖️",
      "🏝️", "🏜️", "🚩", "🏁", "🎌", "🏳️", "🏴", "🏳️‍🌈", "🏳️‍⚧️", "🏴‍☠️",
    ],
  },
] as const;

type EmojiCategory = typeof CATEGORIES[number];

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
}

const EmojiPicker: Component<EmojiPickerProps> = (props) => {
  const [open, setOpen] = createSignal(false);
  const [activeCategory, setActiveCategory] = createSignal<string>("frequent");
  const [search, setSearch] = createSignal("");
  let containerRef: HTMLDivElement | undefined;
  let triggerRef: HTMLButtonElement | undefined;

  /* Close on Escape or outside click */
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") setOpen(false);
  };
  const handleClickOutside = (e: MouseEvent) => {
    if (containerRef && !containerRef.contains(e.target as Node) && triggerRef && !triggerRef.contains(e.target as Node)) {
      setOpen(false);
    }
  };

  onMount(() => {
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("mousedown", handleClickOutside);
  });
  onCleanup(() => {
    document.removeEventListener("keydown", handleKeyDown);
    document.removeEventListener("mousedown", handleClickOutside);
  });

  const selectEmoji = (emoji: string) => {
    props.onSelect(emoji);
    setOpen(false);
  };

  return (
    <div style={{ position: "relative", display: "flex", "align-items": "center" }}>
      {/* Trigger button */}
      <button
        ref={triggerRef}
        onClick={() => setOpen(!open())}
        style={{
          width: "32px", height: "32px", "border-radius": "8px",
          border: "none", background: open() ? "rgba(124,107,245,0.15)" : "transparent",
          color: open() ? "#7c6bf5" : "#666", cursor: "pointer",
          display: "flex", "align-items": "center", "justify-content": "center",
          transition: "background 0.2s, color 0.2s", "flex-shrink": "0",
        }}
        onMouseEnter={(e) => {
          if (!open()) e.currentTarget.style.background = "rgba(255,255,255,0.06)";
        }}
        onMouseLeave={(e) => {
          if (!open()) e.currentTarget.style.background = "transparent";
        }}
        title="Emoji"
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M8 14s1.5 2 4 2 4-2 4-2" />
          <line x1="9" y1="9" x2="9.01" y2="9" stroke-width="2.5" />
          <line x1="15" y1="9" x2="15.01" y2="9" stroke-width="2.5" />
        </svg>
      </button>

      {/* Picker popover */}
      <Show when={open()}>
        <div
          ref={containerRef}
          style={{
            position: "absolute",
            bottom: "calc(100% + 8px)",
            right: "0",
            width: "352px",
            height: "420px",
            background: "#2B2D31",
            "border-radius": "12px",
            "box-shadow": "0 8px 32px rgba(0,0,0,0.45), 0 0 0 1px rgba(255,255,255,0.06)",
            display: "flex",
            "flex-direction": "column",
            overflow: "hidden",
            "z-index": "1000",
            animation: "emojiPickerIn 0.18s ease-out",
          }}
        >
          {/* Search bar */}
          <div style={{ padding: "12px 12px 8px", "flex-shrink": "0" }}>
            <div style={{
              display: "flex", "align-items": "center", gap: "8px",
              background: "#1E1F22", "border-radius": "8px", padding: "0 10px",
              height: "34px",
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style={{ "flex-shrink": "0" }}>
                <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <input
                style={{
                  flex: "1", background: "transparent", border: "none",
                  color: "#ccc", "font-size": "13px", outline: "none",
                }}
                placeholder="Search emoji..."
                value={search()}
                onInput={(e) => setSearch(e.currentTarget.value)}
                autofocus
              />
              <Show when={search()}>
                <button
                  style={{
                    width: "18px", height: "18px", "border-radius": "4px",
                    background: "transparent", border: "none", color: "#666",
                    cursor: "pointer", display: "flex", "align-items": "center",
                    "justify-content": "center",
                  }}
                  onClick={() => setSearch("")}
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </Show>
            </div>
          </div>

          {/* Category tabs */}
          <div style={{
            display: "flex", padding: "0 8px", gap: "2px", "flex-shrink": "0",
            "border-bottom": "1px solid rgba(255,255,255,0.06)",
          }}>
            <For each={CATEGORIES as unknown as EmojiCategory[]}>
              {(cat) => (
                <button
                  onClick={() => {
                    setActiveCategory(cat.id);
                    setSearch("");
                    /* Scroll into view */
                    const el = document.getElementById(`emoji-cat-${cat.id}`);
                    el?.scrollIntoView({ behavior: "smooth", block: "start" });
                  }}
                  style={{
                    flex: "1", height: "36px", border: "none", cursor: "pointer",
                    background: activeCategory() === cat.id ? "rgba(124,107,245,0.12)" : "transparent",
                    "border-bottom": activeCategory() === cat.id ? "2px solid #7c6bf5" : "2px solid transparent",
                    "border-radius": "0", display: "flex", "align-items": "center",
                    "justify-content": "center", "font-size": "16px",
                    transition: "background 0.15s, border-color 0.15s",
                    opacity: activeCategory() === cat.id ? "1" : "0.5",
                    "padding-bottom": "2px",
                  }}
                  onMouseEnter={(e) => {
                    if (activeCategory() !== cat.id) e.currentTarget.style.background = "rgba(255,255,255,0.04)";
                  }}
                  onMouseLeave={(e) => {
                    if (activeCategory() !== cat.id) e.currentTarget.style.background = "transparent";
                  }}
                  title={cat.label}
                >
                  {cat.icon}
                </button>
              )}
            </For>
          </div>

          {/* Emoji grid — scrollable */}
          <div
            style={{
              flex: "1", "overflow-y": "auto", padding: "8px 10px",
              "min-height": "0",
            }}
            onScroll={(e) => {
              /* Update active tab on scroll */
              const container = e.currentTarget;
              const kids = container.querySelectorAll("[data-cat-id]");
              let closestId = "frequent";
              let closestDist = Infinity;
              kids.forEach((kid) => {
                const top = (kid as HTMLElement).offsetTop - container.scrollTop;
                if (top <= 20 && Math.abs(top) < closestDist) {
                  closestDist = Math.abs(top);
                  closestId = (kid as HTMLElement).dataset.catId ?? "frequent";
                }
              });
              setActiveCategory(closestId);
            }}
          >
            <Show when={!search()}>
              <For each={CATEGORIES as unknown as EmojiCategory[]}>
                {(cat) => (
                  <div id={`emoji-cat-${cat.id}`} data-cat-id={cat.id}>
                    <div style={{
                      "font-size": "11px", "font-weight": "600", color: "#777",
                      "text-transform": "uppercase", "letter-spacing": "0.05em",
                      padding: "8px 4px 6px",
                    }}>
                      {cat.label}
                    </div>
                    <div style={{
                      display: "grid",
                      "grid-template-columns": "repeat(8, 1fr)",
                      gap: "2px",
                    }}>
                      <For each={cat.emojis as unknown as string[]}>
                        {(emoji) => (
                          <button
                            onClick={() => selectEmoji(emoji)}
                            style={{
                              width: "100%", "aspect-ratio": "1",
                              "border-radius": "6px", border: "none",
                              background: "transparent", cursor: "pointer",
                              "font-size": "22px", display: "flex",
                              "align-items": "center", "justify-content": "center",
                              transition: "background 0.12s, transform 0.12s",
                            }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.background = "rgba(124,107,245,0.12)";
                              e.currentTarget.style.transform = "scale(1.15)";
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.background = "transparent";
                              e.currentTarget.style.transform = "scale(1)";
                            }}
                          >
                            {emoji}
                          </button>
                        )}
                      </For>
                    </div>
                  </div>
                )}
              </For>
            </Show>

            {/* Search results — flat grid of all matching */}
            <Show when={!!search()}>
              {(() => {
                /* For now, show all emojis — web emoji search needs a name map.
                   We flatten all categories and user can visually scan. */
                const allEmojis = CATEGORIES.flatMap(c => c.emojis as unknown as string[]);
                return (
                  <div style={{
                    display: "grid",
                    "grid-template-columns": "repeat(8, 1fr)",
                    gap: "2px",
                  }}>
                    <For each={allEmojis}>
                      {(emoji) => (
                        <button
                          onClick={() => selectEmoji(emoji)}
                          style={{
                            width: "100%", "aspect-ratio": "1",
                            "border-radius": "6px", border: "none",
                            background: "transparent", cursor: "pointer",
                            "font-size": "22px", display: "flex",
                            "align-items": "center", "justify-content": "center",
                            transition: "background 0.12s, transform 0.12s",
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.background = "rgba(124,107,245,0.12)";
                            e.currentTarget.style.transform = "scale(1.15)";
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.background = "transparent";
                            e.currentTarget.style.transform = "scale(1)";
                          }}
                        >
                          {emoji}
                        </button>
                      )}
                    </For>
                  </div>
                );
              })()}
            </Show>
          </div>
        </div>
      </Show>
    </div>
  );
};

export { EmojiPicker };
