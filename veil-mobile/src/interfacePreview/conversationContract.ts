import type { Attachment, Transfer } from './attachmentContract';

/** Presentation only. Domain delivery is supplied by the source, never a timer. */
export type Delivery = 'accepted' | 'queued' | 'failed' | 'unknown';
export type TimelineMessage = {
  id: string;
  text: string;
  own: boolean;
  time: string;
  day?: string;
  delivery?: Delivery;
  author?: string;
  replyTo?: string;
  edited?: boolean;
  deleted?: boolean;
  attachment?: Attachment;
  transfer?: Transfer;
};
export type TimelineConversation = {
  id: string;
  name: string;
  initials: string;
  color: string;
  username: string;
  unread: number;
  pinned?: boolean;
  kind?: 'direct' | 'group' | 'channel';
  space?: string;
  category?: string;
  messages: TimelineMessage[];
};
export type ConversationCapabilities = {
  copy: boolean;
  reply: boolean;
  edit: boolean;
  delete: boolean;
  attachments: boolean;
  retry: boolean;
  receipts: boolean;
  loadOlder: boolean;
};
export const designCapabilities: ConversationCapabilities = {
  copy: true,
  reply: true,
  edit: true,
  delete: true,
  attachments: true,
  retry: true,
  receipts: false,
  loadOlder: true,
};
export const directTextCapabilities: ConversationCapabilities = {
  copy: true,
  reply: false,
  edit: false,
  delete: false,
  attachments: false,
  retry: false,
  receipts: false,
  loadOlder: false,
};
