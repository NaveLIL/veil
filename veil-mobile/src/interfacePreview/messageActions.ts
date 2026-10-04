import { DemoMessage, DemoSession, sendDemo } from './model';

export type MessageAction = 'reply' | 'copy' | 'edit' | 'delete';
export function availableActions(message: DemoMessage): MessageAction[] {
  if (message.deleted) return [];
  return message.own && message.delivery !== 'unknown'
    ? ['reply', 'copy', 'edit', 'delete']
    : ['reply', 'copy'];
}
export function findMessage(session: DemoSession, chatId: string, id: string) {
  return session.chats
    .find((chat) => chat.id === chatId)
    ?.messages.find((m) => m.id === id);
}
export function startReply(
  session: DemoSession,
  chatId: string,
  id: string,
): DemoSession {
  const message = findMessage(session, chatId, id);
  if (!message || message.deleted) return session;
  return {
    ...session,
    replies: { ...session.replies, [chatId]: id },
    edits: { ...session.edits, [chatId]: undefined },
  };
}
export function startEdit(
  session: DemoSession,
  chatId: string,
  id: string,
): DemoSession {
  const message = findMessage(session, chatId, id);
  if (!message || !availableActions(message).includes('edit')) return session;
  return {
    ...session,
    edits: {
      ...session.edits,
      [chatId]: { messageId: id, text: message.text },
    },
  };
}
export function changeComposition(
  session: DemoSession,
  chatId: string,
  text: string,
): DemoSession {
  if (!session.chats.some((c) => c.id === chatId)) return session;
  const edit = session.edits?.[chatId];
  return edit
    ? {
        ...session,
        edits: {
          ...session.edits,
          [chatId]: { ...edit, text: text.slice(0, 4000) },
        },
      }
    : {
        ...session,
        drafts: { ...session.drafts, [chatId]: text.slice(0, 4000) },
      };
}
export function cancelComposition(
  session: DemoSession,
  chatId: string,
): DemoSession {
  return session.edits?.[chatId]
    ? { ...session, edits: { ...session.edits, [chatId]: undefined } }
    : { ...session, replies: { ...session.replies, [chatId]: undefined } };
}
export function submitComposition(
  session: DemoSession,
  chatId: string,
  time: string,
): DemoSession {
  const edit = session.edits?.[chatId];
  if (!edit) return sendDemo(session, chatId, time);
  const message = findMessage(session, chatId, edit.messageId);
  if (
    !message ||
    !availableActions(message).includes('edit') ||
    !edit.text.trim() ||
    session.scenario === 'identityChanged'
  )
    return session;
  return {
    ...session,
    edits: { ...session.edits, [chatId]: undefined },
    chats: session.chats.map((c) =>
      c.id === chatId
        ? {
            ...c,
            messages: c.messages.map((m) =>
              m.id === edit.messageId
                ? {
                    ...m,
                    text: edit.text,
                    edited: m.edited || edit.text !== m.text,
                  }
                : m,
            ),
          }
        : c,
    ),
  };
}
/** Local fixture tombstone: retain IDs/quotes/anchors but remove the original text. */
export function deleteMessage(
  session: DemoSession,
  chatId: string,
  id: string,
): DemoSession {
  const message = findMessage(session, chatId, id);
  if (!message || !availableActions(message).includes('delete')) return session;
  return {
    ...session,
    edits:
      session.edits?.[chatId]?.messageId === id
        ? { ...session.edits, [chatId]: undefined }
        : session.edits,
    chats: session.chats.map((c) =>
      c.id === chatId
        ? {
            ...c,
            messages: c.messages.map((m) =>
              m.id === id
                ? { ...m, text: '', deleted: true, replyTo: undefined }
                : m,
            ),
          }
        : c,
    ),
  };
}
