import { Popover as KPopover } from "@kobalte/core/popover";
import { Tabs as KTabs } from "@kobalte/core/tabs";
import { Component, For, Show, createMemo, createSignal } from "solid-js";
import {
  Clock3,
  Flag,
  Gamepad2,
  Hand,
  Heart,
  Leaf,
  Pizza,
  Search,
  Smile,
  X,
  type LucideIcon,
} from "lucide-solid";
import { Z } from "@/lib/zIndex";

/* ── Emoji categories with curated sets ────────────── */
const CATEGORIES = [
  {
    id: "frequent",
    label: "Frequently used",
    emojis: ["👍", "❤️", "😂", "🔥", "😭", "🥺", "✨", "🙏", "😊", "🎉", "💀", "😍", "🤣", "😢", "👀", "💜", "🤔", "😮", "👎", "💯", "😎", "🫡", "🤝", "👋"],
  },
  {
    id: "smileys",
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

const CATEGORY_ICONS: Record<EmojiCategory["id"], LucideIcon> = {
  frequent: Clock3,
  smileys: Smile,
  gestures: Hand,
  hearts: Heart,
  nature: Leaf,
  food: Pizza,
  objects: Gamepad2,
  flags: Flag,
};

// The native emoji glyph remains visible, while common search terms and button
// names stay deterministic across the different Windows/Linux emoji fonts.
const EMOJI_NAMES: Readonly<Record<string, string>> = {
  "👍": "thumbs up",
  "👎": "thumbs down",
  "❤️": "red heart",
  "😂": "face with tears of joy",
  "🤣": "rolling on the floor laughing",
  "🔥": "fire",
  "😭": "loudly crying face",
  "🥺": "pleading face",
  "✨": "sparkles",
  "🙏": "folded hands",
  "😊": "smiling face with smiling eyes",
  "🎉": "party popper",
  "💀": "skull",
  "😍": "smiling face with heart eyes",
  "😢": "crying face",
  "👀": "eyes",
  "💜": "purple heart",
  "🤔": "thinking face",
  "😮": "face with open mouth",
  "💯": "hundred points",
  "😎": "smiling face with sunglasses",
  "🫡": "saluting face",
  "🤝": "handshake",
  "👋": "waving hand",
  "😀": "grinning face",
  "😃": "grinning face with big eyes",
  "😄": "grinning face with smiling eyes",
  "😁": "beaming face with smiling eyes",
  "😆": "grinning squinting face",
  "😅": "grinning face with sweat",
  "🙂": "slightly smiling face",
  "🥰": "smiling face with hearts",
  "😘": "face blowing a kiss",
  "🤗": "hugging face",
  "🤫": "shushing face",
  "😡": "enraged face",
  "🤬": "face with symbols on mouth",
  "👻": "ghost",
  "🤖": "robot",
  "💩": "pile of poo",
  "🤡": "clown face",
  "✌️": "victory hand",
  "👏": "clapping hands",
  "💪": "flexed biceps",
  "🧠": "brain",
  "🖤": "black heart",
  "💔": "broken heart",
  "✅": "check mark button",
  "❌": "cross mark",
  "🐶": "dog face",
  "🐱": "cat face",
  "🦊": "fox",
  "🐻": "bear",
  "🐼": "panda",
  "🌸": "cherry blossom",
  "🌹": "rose",
  "🌻": "sunflower",
  "🌿": "herb",
  "🍀": "four leaf clover",
  "🍎": "red apple",
  "🍕": "pizza",
  "🍔": "hamburger",
  "🍟": "french fries",
  "☕": "hot beverage",
  "🍺": "beer mug",
  "⚽": "soccer ball",
  "🏀": "basketball",
  "🎮": "video game",
  "🎨": "artist palette",
  "🎧": "headphones",
  "💻": "laptop",
  "📱": "mobile phone",
  "💡": "light bulb",
  "🔒": "locked",
  "🔑": "key",
  "🚗": "car",
  "✈️": "airplane",
  "🚀": "rocket",
  "🏠": "house",
  "🌍": "globe showing Europe and Africa",
  "🗺️": "world map",
  "🚩": "triangular flag",
  "🏳️‍🌈": "rainbow flag",
};

interface EmojiEntry {
  emoji: string;
  category: EmojiCategory;
}

// Segoe UI Emoji coverage differs across supported Windows releases. Keep the
// native-text picker on the Emoji 11 baseline and omit later additions that
// render as tofu on older Windows builds. This list is deliberately explicit:
// future additions must either ship with a bundled renderer or be reviewed for
// the supported Windows baseline.
const WINDOWS_NATIVE_EMOJI_EXCLUSIONS = new Set([
  "🫡", "🥲", "🫢", "🫣", "🫥", "🥸", "🫤", "🥹", "🥱",
  "🫱", "🫲", "🫳", "🫴", "🫷", "🫸", "🤌", "🤏", "🫰", "🫵", "🫶",
  "🦾", "🦿", "🦻", "🫀", "🫁", "🤍", "🤎", "❤️‍🔥", "❤️‍🩹", "🐻‍❄️",
  "🪱", "🪰", "🪴", "🫐", "🫑", "🫒", "🧄", "🧅", "🫓", "🧇", "🧃",
  "🪕", "🏳️‍⚧️",
]);

export function isDesktopEmojiCompatible(emoji: string): boolean {
  return !WINDOWS_NATIVE_EMOJI_EXCLUSIONS.has(emoji);
}

function compatibleEntries(category: EmojiCategory): EmojiEntry[] {
  return (category.emojis as unknown as string[])
    .filter(isDesktopEmojiCompatible)
    .map((emoji) => ({ emoji, category }));
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

function emojiName(entry: EmojiEntry): string {
  return EMOJI_NAMES[entry.emoji] ?? `${entry.category.label} emoji ${entry.emoji}`;
}

const EmojiGrid: Component<{ entries: EmojiEntry[]; onSelect: (emoji: string) => void }> = (props) => (
  <div data-emoji-grid style={{
    display: "grid",
    width: "100%",
    "min-width": "0",
    "grid-template-columns": "repeat(8, minmax(0, 1fr))",
    gap: "2px",
    overflow: "hidden",
  }}>
    <For each={props.entries}>
      {(entry) => (
        <button
          type="button"
          aria-label={`Insert ${emojiName(entry)}`}
          title={emojiName(entry)}
          data-emoji-value={entry.emoji}
          onClick={() => props.onSelect(entry.emoji)}
          style={{
            width: "100%", "min-width": "0", "aspect-ratio": "1", overflow: "hidden",
            "border-radius": "6px", border: "none",
            background: "transparent", cursor: "pointer",
            "font-size": "22px", display: "flex",
            "align-items": "center", "justify-content": "center",
            transition: "background 0.12s, transform 0.12s",
          }}
          onMouseEnter={(event) => {
            event.currentTarget.style.background = "color-mix(in srgb, var(--veil-accent) 12%, transparent)";
            event.currentTarget.style.transform = "scale(1.15)";
          }}
          onMouseLeave={(event) => {
            event.currentTarget.style.background = "transparent";
            event.currentTarget.style.transform = "scale(1)";
          }}
        >
          <span aria-hidden="true" style={{
            display: "block", "max-width": "100%", "line-height": "1",
            "font-family": "'Segoe UI Emoji', 'Apple Color Emoji', 'Noto Color Emoji', sans-serif",
          }}>{entry.emoji}</span>
        </button>
      )}
    </For>
  </div>
);

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
}

const EmojiPicker: Component<EmojiPickerProps> = (props) => {
  const [open, setOpen] = createSignal(false);
  const [activeCategory, setActiveCategory] = createSignal<EmojiCategory["id"]>("frequent");
  const [search, setSearch] = createSignal("");
  let triggerRef: HTMLButtonElement | undefined;
  let searchRef: HTMLInputElement | undefined;

  const allEntries = createMemo<EmojiEntry[]>(() => {
    const seen = new Set<string>();
    const entries: EmojiEntry[] = [];
    for (const category of CATEGORIES as unknown as EmojiCategory[]) {
      for (const { emoji } of compatibleEntries(category)) {
        if (seen.has(emoji)) continue;
        seen.add(emoji);
        entries.push({ emoji, category });
      }
    }
    return entries;
  });

  const searchResults = createMemo(() => {
    const query = search().trim().toLocaleLowerCase();
    if (!query) return [];
    return allEntries().filter((entry) => {
      const name = emojiName(entry).toLocaleLowerCase();
      const category = entry.category.label.toLocaleLowerCase();
      return entry.emoji.includes(query) || name.includes(query) || category.includes(query);
    });
  });

  const selectEmoji = (emoji: string) => {
    props.onSelect(emoji);
    setSearch("");
    setOpen(false);
  };

  return (
    <KPopover
      open={open()}
      onOpenChange={(nextOpen) => {
        setOpen(nextOpen);
        if (!nextOpen) setSearch("");
      }}
      placement="top-end"
      gutter={8}
    >
      <KPopover.Trigger
        ref={triggerRef}
        aria-label="Choose emoji"
        style={{
          width: "32px", height: "32px", "border-radius": "8px",
          border: "none", background: open() ? "color-mix(in srgb, var(--veil-accent) 15%, transparent)" : "transparent",
          color: open() ? "var(--veil-accent)" : "var(--veil-text-faint)", cursor: "pointer",
          display: "flex", "align-items": "center", "justify-content": "center",
          transition: "background 0.2s, color 0.2s", "flex-shrink": "0",
        }}
        onMouseEnter={(event: MouseEvent) => {
          if (!open()) (event.currentTarget as HTMLButtonElement).style.background = "color-mix(in srgb, var(--veil-text-strong) 6%, transparent)";
        }}
        onMouseLeave={(event: MouseEvent) => {
          if (!open()) (event.currentTarget as HTMLButtonElement).style.background = "transparent";
        }}
        title="Choose emoji"
      >
        <Smile size={20} strokeWidth={1.8} />
      </KPopover.Trigger>

      <KPopover.Portal mount={portalHost()}>
        <KPopover.Content
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            queueMicrotask(() => searchRef?.focus());
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            queueMicrotask(() => {
              if (triggerRef?.isConnected) triggerRef.focus();
            });
          }}
          style={{
            width: "352px",
            height: "420px",
            background: "var(--veil-island)",
            "border-radius": "12px",
            "box-shadow": "0 8px 32px var(--veil-shadow-strong), 0 0 0 1px var(--veil-border)",
            display: "flex",
            "flex-direction": "column",
            overflow: "hidden",
            "z-index": Z.DROPDOWN,
            animation: "emojiPickerIn 0.18s ease-out",
          }}
        >
          <KPopover.Title style={{
            position: "absolute", width: "1px", height: "1px", padding: "0",
            margin: "-1px", overflow: "hidden", clip: "rect(0, 0, 0, 0)",
            "white-space": "nowrap", border: "0",
          }}>
            Choose emoji
          </KPopover.Title>

          <div style={{ padding: "12px 12px 8px", "flex-shrink": "0" }}>
            <div style={{
              display: "flex", "align-items": "center", gap: "8px",
              background: "var(--veil-control)", "border-radius": "8px", padding: "0 10px",
              height: "34px",
            }}>
              <Search size={14} color="var(--veil-text-faint)" strokeWidth={2} style={{ "flex-shrink": "0" }} />
              <input
                ref={searchRef}
                aria-label="Search emoji"
                style={{
                  flex: "1", background: "transparent", border: "none",
                  color: "var(--veil-text)", "font-size": "13px", outline: "none",
                }}
                placeholder="Search emoji..."
                value={search()}
                onInput={(e) => setSearch(e.currentTarget.value)}
              />
              <Show when={search()}>
                <button
                  type="button"
                  aria-label="Clear emoji search"
                  style={{
                    width: "18px", height: "18px", "border-radius": "4px",
                    background: "transparent", border: "none", color: "var(--veil-text-faint)",
                    cursor: "pointer", display: "flex", "align-items": "center",
                    "justify-content": "center",
                  }}
                  onClick={() => setSearch("")}
                >
                  <X size={12} strokeWidth={2.5} />
                </button>
              </Show>
            </div>
          </div>

          <KTabs
            value={activeCategory()}
            onChange={(value) => {
              setActiveCategory(value as EmojiCategory["id"]);
              setSearch("");
            }}
            activationMode="automatic"
            style={{ display: "flex", "flex-direction": "column", flex: "1", "min-height": "0" }}
          >
            <KTabs.List
              aria-label="Emoji categories"
              style={{
                display: search().trim() ? "none" : "flex",
                padding: "0 8px", gap: "2px", "flex-shrink": "0",
                "border-bottom": "1px solid var(--veil-border)",
              }}
            >
              <For each={CATEGORIES as unknown as EmojiCategory[]}>
                {(cat) => (
                  <KTabs.Trigger
                    value={cat.id}
                    aria-label={cat.label}
                    title={cat.label}
                    style={{
                      flex: "1", height: "36px", border: "none", cursor: "pointer",
                      background: activeCategory() === cat.id ? "color-mix(in srgb, var(--veil-accent) 12%, transparent)" : "transparent",
                      "border-bottom": activeCategory() === cat.id ? "2px solid var(--veil-accent)" : "2px solid transparent",
                      "border-radius": "0", display: "flex", "align-items": "center",
                      "justify-content": "center",
                      transition: "background 0.15s, border-color 0.15s",
                      opacity: activeCategory() === cat.id ? "1" : "0.55",
                      "padding-bottom": "2px", color: "var(--veil-text-muted)",
                    }}
                  >
                    {(() => {
                      const Icon = CATEGORY_ICONS[cat.id];
                      return <Icon size={16} strokeWidth={1.8} aria-hidden="true" />;
                    })()}
                  </KTabs.Trigger>
                )}
              </For>
            </KTabs.List>

            <div data-emoji-scroll-region style={{
              flex: "1", "overflow-y": "auto", "overflow-x": "hidden",
              padding: "8px 10px", "min-height": "0", "min-width": "0",
            }}>
              <Show when={search().trim()}>
                <section aria-label="Emoji search results">
                  <Show
                    when={searchResults().length > 0}
                    fallback={
                      <p role="status" style={{
                        margin: "28px 8px", "text-align": "center",
                        color: "var(--veil-text-muted)", "font-size": "12px",
                      }}>
                        No emoji found for “{search().trim()}”.
                      </p>
                    }
                  >
                    <EmojiGrid entries={searchResults()} onSelect={selectEmoji} />
                  </Show>
                </section>
              </Show>
              <div style={{ display: search().trim() ? "none" : "block" }}>
                <For each={CATEGORIES as unknown as EmojiCategory[]}>
                  {(cat) => (
                    <KTabs.Content value={cat.id}>
                      <div style={{
                        "font-size": "11px", "font-weight": "600", color: "var(--veil-text-faint)",
                        "text-transform": "uppercase", "letter-spacing": "0.05em",
                        padding: "8px 4px 6px",
                      }}>
                        {cat.label}
                      </div>
                      <EmojiGrid
                        entries={compatibleEntries(cat)}
                        onSelect={selectEmoji}
                      />
                    </KTabs.Content>
                  )}
                </For>
              </div>
            </div>
          </KTabs>
        </KPopover.Content>
      </KPopover.Portal>
    </KPopover>
  );
};

export { EmojiPicker };
