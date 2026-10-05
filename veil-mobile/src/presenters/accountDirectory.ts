import type { DmConversation } from '../stores/chat';

export type DirectoryEntry = { id: string; name: string; preview: string; time?: string;
  hasDraft: boolean; avatarIdentity: DmConversation['avatarIdentity'] };
/** Projection facts cannot supply unread, mute, pin or receipt semantics. */
export function directoryEntry(dm: DmConversation, draft?: string): DirectoryEntry {
  return { id: dm.id, name: dm.name, time: dm.lastAt, avatarIdentity: dm.avatarIdentity,
    hasDraft: !!draft, preview: draft ? `Черновик: ${draft}` : dm.lastMessage !== undefined
      ? `${dm.lastDirection === 'outgoing' ? 'Вы: ' : ''}${dm.lastMessage}`
      : 'История откроется после выбора чата' };
}
