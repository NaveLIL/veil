export interface DesignPreviewMember {
  id: string;
  name: string;
  initials: string;
  color: string;
  role: "Owner" | "Admin" | "Member";
  presence: "Online" | "Away" | "Offline";
}

export interface DesignPreviewRoom {
  id: string;
  name: string;
  category: string;
  kind: "text" | "voice";
  topic: string;
  unread: boolean;
  mentions: number;
  participantMemberIds?: string[];
}

export interface DesignPreviewMessage {
  id: string;
  authorId: string;
  time: string;
  text: string;
  mentionsYou?: boolean;
}

export const DESIGN_MEMBERS: DesignPreviewMember[] = [
  { id: "mira", name: "Mira", initials: "MI", color: "#a78bfa", role: "Owner", presence: "Online" },
  { id: "noah", name: "Noah", initials: "NO", color: "#34d399", role: "Admin", presence: "Online" },
  { id: "lena", name: "Lena", initials: "LE", color: "#f472b6", role: "Member", presence: "Away" },
  { id: "alex", name: "Alex", initials: "AL", color: "#60a5fa", role: "Member", presence: "Offline" },
];

export const DESIGN_ROOMS: DesignPreviewRoom[] = [
  {
    id: "mobile-design",
    name: "mobile-design",
    category: "Product",
    kind: "text",
    topic: "Shape the Android experience",
    unread: true,
    mentions: 2,
  },
  {
    id: "security",
    name: "security",
    category: "Product",
    kind: "text",
    topic: "Protocol and threat-model review",
    unread: true,
    mentions: 0,
  },
  {
    id: "general",
    name: "general",
    category: "Common",
    kind: "text",
    topic: "Everyday Space conversation",
    unread: false,
    mentions: 0,
  },
  {
    id: "announcements",
    name: "announcements",
    category: "Common",
    kind: "text",
    topic: "Important Space updates",
    unread: true,
    mentions: 1,
  },
  {
    id: "lounge",
    name: "Lounge",
    category: "Voice",
    kind: "voice",
    topic: "Drop-in conversation",
    unread: false,
    mentions: 0,
    participantMemberIds: ["mira", "noah"],
  },
];

export const DESIGN_CIRCLE_MESSAGES: DesignPreviewMessage[] = [
  { id: "c1", authorId: "mira", time: "18:42", text: "The Circle opens straight into one shared conversation." },
  { id: "c2", authorId: "noah", time: "18:44", text: "No room list here — that keeps a small group lightweight." },
  { id: "c3", authorId: "lena", time: "18:46", text: "@you, the mention remains visible in Updates.", mentionsYou: true },
];

export const DESIGN_ROOM_MESSAGES: Record<string, DesignPreviewMessage[]> = {
  "mobile-design": [
    { id: "r1", authorId: "mira", time: "19:03", text: "The full-screen glow is gone from working surfaces." },
    { id: "r2", authorId: "noah", time: "19:05", text: "Home, Spaces and Updates now keep stable positions." },
    { id: "r3", authorId: "lena", time: "19:08", text: "@you, does this Room hierarchy read clearly?", mentionsYou: true },
  ],
  security: [
    { id: "s1", authorId: "noah", time: "17:20", text: "A Room is a separate Sender Keys security domain." },
    { id: "s2", authorId: "mira", time: "17:24", text: "The UI must never infer access from presentation data." },
  ],
  general: [
    { id: "g1", authorId: "alex", time: "Yesterday", text: "This is the calm default Room layout." },
  ],
  announcements: [
    { id: "a1", authorId: "mira", time: "16:10", text: "Design preview only — no message was sent to a Node." },
  ],
};

export function designRoom(roomId: string): DesignPreviewRoom | null {
  return DESIGN_ROOMS.find((room) => room.id === roomId) ?? null;
}
