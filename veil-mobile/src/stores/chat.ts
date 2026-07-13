import { create } from "zustand";

export type ServerId = string;
export type ChannelId = string;
export type DmId = string;

export interface Server {
  id: ServerId;
  name: string;
  initials: string;
  color: string;
  unread?: number;
}

export interface Channel {
  id: ChannelId;
  serverId: ServerId;
  name: string;
  topic?: string;
  unread?: number;
  category?: string;
}

export interface Member {
  id: string;
  canonicalServerOrigin: string;
  userId: string;
  identityKey: string;
  username: string;
  name: string;
  nickname?: string;
  about?: string;
  status: "online" | "idle" | "dnd" | "offline";
  role?: "owner" | "admin" | "member";
  color: string;
}

const origin = "https://veil.example:443";
const member = (id: string, userId: string, identityByte: string, name: string, status: Member["status"], role: Member["role"], color: string, about?: string): Member => ({
  id, canonicalServerOrigin: origin, userId, identityKey: identityByte.repeat(32),
  username: name.toLowerCase(), name, status, role, color, about,
});

export interface DmConversation {
  id: DmId;
  name: string;
  isGroup: boolean;
  lastMessage?: string;
  lastAt?: string;
  unread?: number;
  color: string;
}

export interface Message {
  id: string;
  authorId: string;
  authorName: string;
  authorColor: string;
  text: string;
  ts: string;
}

/** Special pseudo-server id representing the DM/Groups inbox. */
export const DM_HOME_ID: ServerId = "__dm__";

const SERVERS: Server[] = [
  { id: DM_HOME_ID, name: "Direct messages", initials: "DM", color: "#7c6bf5" },
  { id: "veil", name: "Veil", initials: "V", color: "#7c6bf5", unread: 3 },
  { id: "rust", name: "Rust Crypto", initials: "RC", color: "#d97706" },
  { id: "design", name: "Design Lab", initials: "DL", color: "#10b981", unread: 1 },
  { id: "music", name: "Late Night Music", initials: "LN", color: "#ec4899" },
];

const CHANNELS: Channel[] = [
  // Veil
  { id: "veil-general", serverId: "veil", name: "general", category: "TEXT", unread: 2 },
  { id: "veil-dev", serverId: "veil", name: "dev", category: "TEXT" },
  { id: "veil-design", serverId: "veil", name: "design", category: "TEXT", unread: 1 },
  { id: "veil-random", serverId: "veil", name: "random", category: "TEXT" },
  { id: "veil-voice", serverId: "veil", name: "Lounge", category: "VOICE" },
  // Rust Crypto
  { id: "rust-help", serverId: "rust", name: "help", category: "TEXT" },
  { id: "rust-internals", serverId: "rust", name: "internals", category: "TEXT" },
  { id: "rust-async", serverId: "rust", name: "async", category: "TEXT" },
  // Design
  { id: "design-feedback", serverId: "design", name: "feedback", category: "TEXT", unread: 1 },
  { id: "design-share", serverId: "design", name: "share", category: "TEXT" },
  // Music
  { id: "music-now", serverId: "music", name: "now-playing", category: "TEXT" },
  { id: "music-discover", serverId: "music", name: "discover", category: "TEXT" },
];

const DMS: DmConversation[] = [
  { id: "dm-anya", name: "Anya", isGroup: false, lastMessage: "see you tomorrow ✨", lastAt: "21:04", color: "#ec4899", unread: 2 },
  { id: "dm-collab", name: "Veil core team", isGroup: true, lastMessage: "merged the ratchet PR", lastAt: "20:11", color: "#7c6bf5" },
  { id: "dm-mark", name: "Mark", isGroup: false, lastMessage: "ok thanks!", lastAt: "Yesterday", color: "#10b981" },
  { id: "dm-fam", name: "Family 🏡", isGroup: true, lastMessage: "mum: don't forget", lastAt: "Yesterday", color: "#fbbf24", unread: 5 },
  { id: "dm-leo", name: "Leo", isGroup: false, lastMessage: "🔥🔥🔥", lastAt: "Mon", color: "#f43f5e" },
];

export const MEMBERS_BY_SERVER: Record<ServerId, Member[]> = {
  veil: [
    member("u1", "10000000-0000-4000-8000-000000000001", "11", "dimon", "online", "owner", "#7c6bf5", "Building Veil carefully."),
    member("u2", "10000000-0000-4000-8000-000000000002", "22", "anya", "online", "admin", "#ec4899", "Design and privacy."),
    member("u3", "10000000-0000-4000-8000-000000000003", "33", "leo", "idle", "member", "#f43f5e"),
    member("u4", "10000000-0000-4000-8000-000000000004", "44", "mark", "dnd", "member", "#10b981"),
    member("u5", "10000000-0000-4000-8000-000000000005", "55", "iris", "offline", "member", "#fbbf24"),
    member("u6", "10000000-0000-4000-8000-000000000006", "66", "noa", "offline", "member", "#94a3b8"),
  ],
  rust: [
    member("r1", "20000000-0000-4000-8000-000000000001", "71", "alice", "online", "owner", "#d97706"),
    member("r2", "20000000-0000-4000-8000-000000000002", "72", "bob", "online", "member", "#7c6bf5"),
    member("r3", "20000000-0000-4000-8000-000000000003", "73", "carol", "offline", "member", "#10b981"),
  ],
  design: [
    member("d1", "30000000-0000-4000-8000-000000000001", "81", "sasha", "online", "owner", "#10b981"),
    member("d2", "30000000-0000-4000-8000-000000000002", "82", "yulia", "online", "member", "#ec4899"),
  ],
  music: [
    member("m1", "40000000-0000-4000-8000-000000000001", "91", "dj", "online", "owner", "#ec4899"),
  ],
};

function makeMessages(channelName: string): Message[] {
  return [
    { id: "m1", authorId: "u2", authorName: "anya", authorColor: "#ec4899", ts: "20:41", text: `welcome to #${channelName}` },
    { id: "m2", authorId: "u3", authorName: "leo", authorColor: "#f43f5e", ts: "20:42", text: "hey 👋" },
    { id: "m3", authorId: "u1", authorName: "dimon", authorColor: "#7c6bf5", ts: "20:50", text: "shipping the new island layout today" },
    { id: "m4", authorId: "u2", authorName: "anya", authorColor: "#ec4899", ts: "20:51", text: "looks 🔥" },
    { id: "m5", authorId: "u4", authorName: "mark", authorColor: "#10b981", ts: "21:02", text: "swipe between islands feels native" },
  ];
}

interface ChatState {
  servers: Server[];
  channels: Channel[];
  dms: DmConversation[];
  selectedServerId: ServerId;
  selectedChannelId: ChannelId | null;
  selectedDmId: DmId | null;
  messagesByChannel: Record<string, Message[]>;
  selectServer: (id: ServerId) => void;
  selectChannel: (id: ChannelId) => void;
  selectDm: (id: DmId) => void;
  sendMessage: (text: string) => void;
  channelsForServer: (id: ServerId) => Channel[];
  membersForServer: (id: ServerId) => Member[];
  currentMessages: () => Message[];
  currentChatTitle: () => string;
}

export const useChatStore = create<ChatState>((set, get) => ({
  servers: SERVERS,
  channels: CHANNELS,
  dms: DMS,
  selectedServerId: DM_HOME_ID,
  selectedChannelId: null,
  selectedDmId: "dm-anya",
  messagesByChannel: {
    "dm-anya": [
      { id: "a1", authorId: "anya", authorName: "Anya", authorColor: "#ec4899", ts: "20:58", text: "are we still on for 9?" },
      { id: "a2", authorId: "me", authorName: "you", authorColor: "#7c6bf5", ts: "20:59", text: "yes 🤝" },
      { id: "a3", authorId: "anya", authorName: "Anya", authorColor: "#ec4899", ts: "21:04", text: "see you tomorrow ✨" },
    ],
  },

  selectServer: (id) =>
    set((s) => {
      if (id === DM_HOME_ID) {
        return { selectedServerId: id, selectedChannelId: null };
      }
      const first = s.channels.find((c) => c.serverId === id);
      return {
        selectedServerId: id,
        selectedChannelId: first?.id ?? null,
        selectedDmId: null,
      };
    }),

  selectChannel: (id) =>
    set((s) => {
      const ch = s.channels.find((c) => c.id === id);
      const next = { ...s.messagesByChannel };
      if (ch && !next[id]) next[id] = makeMessages(ch.name);
      return { selectedChannelId: id, messagesByChannel: next };
    }),

  selectDm: (id) =>
    set((s) => {
      const next = { ...s.messagesByChannel };
      if (!next[id]) {
        const dm = s.dms.find((d) => d.id === id);
        next[id] = makeMessages(dm?.name ?? "dm");
      }
      return { selectedDmId: id, selectedServerId: DM_HOME_ID, selectedChannelId: null, messagesByChannel: next };
    }),

  sendMessage: (text) =>
    set((s) => {
      const key =
        s.selectedServerId === DM_HOME_ID ? s.selectedDmId : s.selectedChannelId;
      if (!key) return s;
      const msg: Message = {
        id: `local-${Date.now()}`,
        authorId: "me",
        authorName: "you",
        authorColor: "#7c6bf5",
        ts: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        text,
      };
      const list = s.messagesByChannel[key] ?? [];
      return { messagesByChannel: { ...s.messagesByChannel, [key]: [...list, msg] } };
    }),

  channelsForServer: (id) => get().channels.filter((c) => c.serverId === id),
  membersForServer: (id) => MEMBERS_BY_SERVER[id] ?? [],

  currentMessages: () => {
    const s = get();
    const key = s.selectedServerId === DM_HOME_ID ? s.selectedDmId : s.selectedChannelId;
    if (!key) return [];
    return s.messagesByChannel[key] ?? [];
  },

  currentChatTitle: () => {
    const s = get();
    if (s.selectedServerId === DM_HOME_ID) {
      return s.dms.find((d) => d.id === s.selectedDmId)?.name ?? "Direct messages";
    }
    const ch = s.channels.find((c) => c.id === s.selectedChannelId);
    return ch ? `# ${ch.name}` : "Channel";
  },
}));
