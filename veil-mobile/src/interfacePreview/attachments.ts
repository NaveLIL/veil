import type { DemoSession } from './model';

import type { Attachment } from './attachmentContract';
export type { Attachment, Transfer } from './attachmentContract';

/** ASCII fixture body: bytes/metadata are reproducible, not guessed provider data. */
export const designFileText =
  '# Veil mobile design\n\nLocal attachment fixture.\n'.padEnd(2048, '.');
export const designAttachments: readonly Attachment[] = [
  {
    kind: 'image',
    name: 'Тихий берег · иллюстрация',
    fixture: 'landscape',
    width: 960,
    height: 640,
  },
  {
    kind: 'file',
    name: 'Заметки о дизайне.md',
    mediaType: 'text/markdown',
    bytes: designFileText.length,
  },
];
export function chooseAttachment(
  s: DemoSession,
  chatId: string,
  asset?: Attachment,
): DemoSession {
  if (!s.chats.some((c) => c.id === chatId) || s.edits?.[chatId]) return s;
  return { ...s, attachments: { ...s.attachments, [chatId]: asset } };
}
export function sendAttachment(
  s: DemoSession,
  chatId: string,
  time: string,
): DemoSession {
  const asset = s.attachments?.[chatId];
  if (
    !asset ||
    s.scenario === 'identityChanged' ||
    s.edits?.[chatId] ||
    !s.chats.some((c) => c.id === chatId)
  )
    return s;
  const message = {
    id: `demo-local-${s.nextId}`,
    own: true,
    text: s.drafts[chatId] ?? '',
    time,
    replyTo: s.replies?.[chatId],
    attachment: asset,
    delivery:
      s.scenario === 'unknown' ? ('unknown' as const) : ('queued' as const),
    transfer: {
      phase:
        s.scenario === 'unknown'
          ? ('unknown' as const)
          : s.scenario === 'offline'
            ? ('waiting' as const)
            : ('sending' as const),
      progress: 0,
      attempt: 1,
      fail: s.scenario === 'failure',
    },
  };
  return {
    ...s,
    nextId: s.nextId + 1,
    drafts: { ...s.drafts, [chatId]: '' },
    replies: { ...s.replies, [chatId]: undefined },
    attachments: { ...s.attachments, [chatId]: undefined },
    chats: s.chats.map((c) =>
      c.id === chatId ? { ...c, messages: [...c.messages, message] } : c,
    ),
  };
}
export function advanceTransfer(
  s: DemoSession,
  chatId: string,
  id: string,
  attempt: number,
): DemoSession {
  const message = s.chats
    .find((c) => c.id === chatId)
    ?.messages.find((m) => m.id === id);
  const t = message?.transfer;
  if (!t || t.phase !== 'sending' || t.attempt !== attempt || message?.deleted)
    return s;
  const progress = Math.min(100, t.progress + 25);
  const phase =
    t.fail && progress >= 50
      ? 'failed'
      : progress === 100
        ? 'complete'
        : 'sending';
  return {
    ...s,
    chats: s.chats.map((c) =>
      c.id !== chatId
        ? c
        : {
            ...c,
            messages: c.messages.map((m) =>
              m.id !== id
                ? m
                : {
                    ...m,
                    transfer: { ...t, phase, progress },
                    delivery:
                      phase === 'complete'
                        ? 'accepted'
                        : phase === 'failed'
                          ? 'failed'
                          : 'queued',
                  },
            ),
          },
    ),
  };
}
export function cancelTransfer(
  s: DemoSession,
  chatId: string,
  id: string,
): DemoSession {
  return {
    ...s,
    chats: s.chats.map((c) =>
      c.id !== chatId
        ? c
        : {
            ...c,
            messages: c.messages.map((m) =>
              m.id !== id || m.transfer?.phase !== 'sending'
                ? m
                : {
                    ...m,
                    transfer: { ...m.transfer, phase: 'cancelled' },
                    delivery: 'failed',
                  },
            ),
          },
    ),
  };
}
export function retryTransfer(
  s: DemoSession,
  chatId: string,
  id: string,
): DemoSession {
  if (s.scenario === 'identityChanged' || s.scenario === 'offline') return s;
  return {
    ...s,
    chats: s.chats.map((c) =>
      c.id !== chatId
        ? c
        : {
            ...c,
            messages: c.messages.map((m) =>
              m.id !== id ||
              m.deleted ||
              !m.transfer ||
              !['failed', 'cancelled', 'waiting'].includes(m.transfer.phase)
                ? m
                : {
                    ...m,
                    delivery: s.scenario === 'unknown' ? 'unknown' : 'queued',
                    transfer: {
                      phase: s.scenario === 'unknown' ? 'unknown' : 'sending',
                      progress: 0,
                      attempt: m.transfer.attempt + 1,
                      fail: s.scenario === 'failure',
                    },
                  },
            ),
          },
    ),
  };
}
