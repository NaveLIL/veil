import { Dispatch, SetStateAction, useEffect } from 'react';
import { DemoSession } from './model';
import { advanceTransfer } from './attachments';
/** Controlled fixture adapter; transport never belongs to presentation. */
export function useAttachmentTransfers(
  session: DemoSession,
  update: Dispatch<SetStateAction<DemoSession>>,
) {
  useEffect(() => {
    const pending = session.chats.flatMap((c) =>
      c.messages
        .filter((m) => !m.deleted && m.transfer?.phase === 'sending')
        .map((m) => ({ chatId: c.id, id: m.id, attempt: m.transfer!.attempt })),
    );
    if (!pending.length) return;
    const timer = setTimeout(
      () =>
        update((s) =>
          pending.reduce(
            (value, p) => advanceTransfer(value, p.chatId, p.id, p.attempt),
            s,
          ),
        ),
      650,
    );
    return () => clearTimeout(timer);
  }, [session.chats, update]);
}
