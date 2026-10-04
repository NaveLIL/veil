/** Offline, in-memory presentation fixtures. These IDs are never Veil account IDs. */
export type Delivery = 'accepted' | 'queued' | 'failed' | 'unknown';
export type Scenario = 'normal' | 'offline' | 'failure' | 'unknown' | 'identityChanged';
export type DemoMessage = { id: string; text: string; own: boolean; time: string; delivery?: Delivery };
export type DemoChat = { id: string; name: string; initials: string; color: string; username: string; unread: number; pinned?: boolean; messages: DemoMessage[] };
export type DemoSession = { chats: DemoChat[]; drafts: Record<string, string>; scenario: Scenario; nextId: number };

export function createDemoSession(): DemoSession {
  return {
    scenario: 'normal', nextId: 1, drafts: {},
    chats: [
      { id: 'demo-anna', name: 'Анна Морозова', initials: 'АМ', color: '#7866AB', username: 'anna.demo', unread: 2, pinned: true,
        messages: [
          { id: 'fixture-a1', own: false, text: 'Хочу, чтобы в чате было спокойно. Только человек и разговор.', time: '14:32' },
          { id: 'fixture-a2', own: true, text: 'Согласен. Сначала доведём личные чаты до мелочей.', time: '14:34', delivery: 'accepted' },
          { id: 'fixture-a3', own: false, text: 'А группы и пространства оставим рядом, чтобы потом не перестраивать всё приложение.', time: '14:35' },
          { id: 'fixture-a4', own: false, text: 'Как тебе такой первый вариант?', time: '14:36' },
        ] },
      { id: 'demo-max', name: 'Максим', initials: 'МК', color: '#3E7D85', username: 'max.demo', unread: 0, pinned: true,
        messages: [{ id: 'fixture-m1', own: false, text: 'Встретимся завтра в десять?', time: '13:18' }, { id: 'fixture-m2', own: true, text: 'Да, до завтра 👋', time: '13:20', delivery: 'accepted' }] },
      { id: 'demo-sofia', name: 'София', initials: 'С', color: '#AB745D', username: 'sofia.demo', unread: 1,
        messages: [{ id: 'fixture-s1', own: false, text: 'Нашла очень красивое место для прогулки.', time: '12:05' }] },
      { id: 'demo-daniel', name: 'Даниил', initials: 'Д', color: '#59749B', username: 'daniel.demo', unread: 0,
        messages: [{ id: 'fixture-d1', own: true, text: 'Спасибо, посмотрю вечером.', time: 'Вчера', delivery: 'accepted' }] },
      { id: 'demo-lena', name: 'Елена', initials: 'Е', color: '#94708D', username: 'lena.demo', unread: 0,
        messages: [{ id: 'fixture-e1', own: false, text: 'Хороших выходных!', time: 'Вчера' }] },
      { id: 'demo-new', name: 'Никита', initials: 'Н', color: '#657B5D', username: 'nikita.demo', unread: 0, messages: [] },
    ],
  };
}

export function visibleChats(session: DemoSession, query: string, unreadOnly: boolean) {
  const needle = query.trim().toLocaleLowerCase('ru');
  return session.chats.filter(c => (!unreadOnly || c.unread > 0) && (!needle || `${c.name} ${c.username}`.toLocaleLowerCase('ru').includes(needle)))
    .slice().sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned));
}
export function setDraft(session: DemoSession, chatId: string, text: string): DemoSession {
  if (!session.chats.some(c => c.id === chatId)) return session;
  return { ...session, drafts: { ...session.drafts, [chatId]: text } };
}
export function openChat(session: DemoSession, chatId: string): DemoSession {
  return { ...session, chats: session.chats.map(c => c.id === chatId ? { ...c, unread: 0 } : c) };
}
export function sendDemo(session: DemoSession, chatId: string, time: string): DemoSession {
  const text = session.drafts[chatId] ?? '';
  if (!text.trim() || session.scenario === 'identityChanged' || !session.chats.some(c => c.id === chatId)) return session;
  const delivery: Delivery = session.scenario === 'offline' ? 'queued' : session.scenario === 'failure' ? 'failed' : session.scenario === 'unknown' ? 'unknown' : 'accepted';
  const message: DemoMessage = { id: `demo-local-${session.nextId}`, own: true, text, time, delivery };
  return { ...session, nextId: session.nextId + 1, drafts: { ...session.drafts, [chatId]: '' },
    chats: session.chats.map(c => c.id === chatId ? { ...c, messages: [...c.messages, message] } : c) };
}
export function retryDemo(session: DemoSession, chatId: string, messageId: string): DemoSession {
  if (session.scenario === 'identityChanged') return session;
  const delivery: Delivery = session.scenario === 'normal' ? 'accepted' : session.scenario === 'offline' ? 'queued' : session.scenario === 'unknown' ? 'unknown' : 'failed';
  return { ...session, chats: session.chats.map(c => c.id !== chatId ? c : { ...c, messages: c.messages.map(m => m.id === messageId && m.delivery === 'failed' ? { ...m, delivery } : m) }) };
}
