/** Offline, in-memory presentation fixtures. These IDs are never Veil account IDs. */
export type Delivery = 'accepted' | 'queued' | 'failed' | 'unknown';
export type Scenario =
  | 'normal'
  | 'offline'
  | 'failure'
  | 'unknown'
  | 'identityChanged';
export const demoToday = '2026-10-04';
export type DemoMessage = {
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
};
export type DemoChat = {
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
  messages: DemoMessage[];
};
export type DemoSession = {
  chats: DemoChat[];
  drafts: Record<string, string>;
  scenario: Scenario;
  nextId: number;
  replies?: Record<string, string | undefined>;
  edits?: Record<string, { messageId: string; text: string } | undefined>;
};
export const demoSpaces = [
  {
    id: 'demo-studio',
    name: 'Студия',
    initials: 'С',
    color: '#7866AB',
    description: 'Место для идей · 8 участников',
  },
  {
    id: 'demo-friends',
    name: 'Наш круг',
    initials: 'К',
    color: '#3E7D85',
    description: 'Свои люди · 12 участников',
  },
];
export function canGroup(
  previous: DemoMessage | undefined,
  current: DemoMessage,
) {
  if (
    !previous ||
    previous.own !== current.own ||
    previous.author !== current.author ||
    (previous.day ?? demoToday) !== (current.day ?? demoToday)
  )
    return false;
  const minutes = (time: string) =>
    /^([01]\d|2[0-3]):[0-5]\d$/.test(time)
      ? Number(time.slice(0, 2)) * 60 + Number(time.slice(3))
      : null;
  const a = minutes(previous.time),
    b = minutes(current.time);
  return a !== null && b !== null && b >= a && b - a <= 5;
}

/** Varied deterministic history; its demonstration links are never opened. */
function olderHistory(chatId: string, count: number): DemoMessage[] {
  const texts = [
    'Доброе утро! Как продвигается наш проект?',
    'Сегодня хочу спокойно разобрать детали и ничего не потерять по дороге.',
    'Да, записал. Вернёмся к этому после обеда.',
    'Небольшой список:\n• проверить основные сценарии\n• сравнить варианты\n• оставить время на исправления',
    'Ссылка для обсуждения: https://example.invalid/veil/design/long-conversation?view=mobile&section=history\nЭто демонстрационный адрес.',
    'Отлично 🙂 Приятно, когда всё складывается. 👨‍👩‍👧‍👦 ✨',
    'Длинное сообщение тоже должно оставаться удобным для чтения. '.repeat(7) +
      '\n\nВторой абзац: открываем другой чат, возвращаемся обратно и продолжаем с того же места.',
    'Договорились. Спасибо!',
    'Проверка длинного слова: ' + 'оченьдлиннаястрокабезпробелов'.repeat(8),
    'Ещё одна мысль — сначала доведём личную переписку до удобного состояния.',
  ];
  return Array.from({ length: count }, (_, index) => ({
    id: `fixture-history-${chatId}-${index}`,
    own: Math.floor(index / 3) % 2 === 1,
    day: new Date(Date.UTC(2026, 8, 27 + Math.floor(index / 45)))
      .toISOString()
      .slice(0, 10),
    time: `${String(9 + Math.floor((index % 45) / 30)).padStart(2, '0')}:${String(index % 30).padStart(2, '0')}`,
    text: texts[index % texts.length],
    ...(Math.floor(index / 3) % 2 === 1
      ? { delivery: 'accepted' as const }
      : {}),
  }));
}
export function createDemoSession(): DemoSession {
  return {
    scenario: 'normal',
    nextId: 1,
    drafts: {},
    chats: [
      {
        id: 'demo-anna',
        name: 'Анна Морозова',
        initials: 'АМ',
        color: '#7866AB',
        username: 'anna.demo',
        unread: 2,
        pinned: true,
        messages: [
          ...olderHistory('anna', 316),
          {
            id: 'fixture-a1',
            own: false,
            text: 'Хочу, чтобы в чате было спокойно. Только человек и разговор.',
            time: '14:32',
          },
          {
            id: 'fixture-a2',
            own: true,
            text: 'Согласен. Сначала доведём личные чаты до мелочей.',
            time: '14:34',
            delivery: 'accepted',
          },
          {
            id: 'fixture-a3',
            own: false,
            text: 'А группы и пространства оставим рядом, чтобы потом не перестраивать всё приложение.',
            time: '14:35',
          },
          {
            id: 'fixture-a4',
            own: false,
            text: 'Как тебе такой первый вариант?',
            time: '14:36',
          },
        ],
      },
      {
        id: 'demo-max',
        name: 'Максим',
        initials: 'МК',
        color: '#3E7D85',
        username: 'max.demo',
        unread: 0,
        pinned: true,
        messages: [
          ...olderHistory('max', 158),
          {
            id: 'fixture-m1',
            own: false,
            text: 'Встретимся завтра в десять?',
            time: '13:18',
          },
          {
            id: 'fixture-m2',
            own: true,
            text: 'Да, до завтра 👋',
            time: '13:20',
            delivery: 'accepted',
          },
        ],
      },
      {
        id: 'demo-sofia',
        name: 'София',
        initials: 'С',
        color: '#AB745D',
        username: 'sofia.demo',
        unread: 1,
        messages: [
          {
            id: 'fixture-s1',
            own: false,
            text: 'Нашла очень красивое место для прогулки.',
            time: '12:05',
          },
        ],
      },
      {
        id: 'demo-daniel',
        name: 'Даниил',
        initials: 'Д',
        color: '#59749B',
        username: 'daniel.demo',
        unread: 0,
        messages: [
          {
            id: 'fixture-d1',
            own: true,
            text: 'Спасибо, посмотрю вечером.',
            time: '11:48',
            delivery: 'accepted',
          },
        ],
      },
      {
        id: 'demo-lena',
        name: 'Елена',
        initials: 'Е',
        color: '#94708D',
        username: 'lena.demo',
        unread: 0,
        messages: [
          {
            id: 'fixture-e1',
            own: false,
            text: 'Хороших выходных!',
            time: '10:15',
          },
        ],
      },
      {
        id: 'demo-new',
        name: 'Никита',
        initials: 'Н',
        color: '#657B5D',
        username: 'nikita.demo',
        unread: 0,
        messages: [],
      },
      {
        id: 'demo-group',
        kind: 'group',
        name: 'Дизайн Veil',
        initials: 'DV',
        color: '#70599B',
        username: 'design.demo',
        unread: 3,
        messages: [
          {
            id: 'fixture-g1',
            own: false,
            author: 'Максим',
            text: 'Давайте сохраним острова и на телефоне.',
            time: '14:40',
          },
          {
            id: 'fixture-g2',
            own: false,
            author: 'Анна',
            text: 'И общий фон между ними. Это очень узнаваемо.',
            time: '14:42',
          },
        ],
      },
      {
        id: 'demo-studio-general',
        kind: 'channel',
        space: 'demo-studio',
        category: 'ОБЩЕНИЕ',
        name: 'общий',
        initials: '#',
        color: '#7866AB',
        username: '',
        unread: 2,
        messages: [
          {
            id: 'fixture-c1',
            own: false,
            author: 'Анна',
            text: 'Добро пожаловать в студию. Здесь собираем идеи.',
            time: '14:20',
          },
          {
            id: 'fixture-c2',
            own: true,
            text: 'Хочу, чтобы мобильный Veil ощущался частью того же приложения.',
            time: '14:22',
            delivery: 'accepted',
          },
        ],
      },
      {
        id: 'demo-studio-design',
        kind: 'channel',
        space: 'demo-studio',
        category: 'ПРОЕКТЫ',
        name: 'дизайн',
        initials: '#',
        color: '#7866AB',
        username: '',
        unread: 0,
        messages: [
          {
            id: 'fixture-c3',
            own: false,
            author: 'Максим',
            text: 'Меньше панелей сверху. Больше места для переписки.',
            time: '13:45',
          },
        ],
      },
      {
        id: 'demo-friends-general',
        kind: 'channel',
        space: 'demo-friends',
        category: 'ОБЩЕНИЕ',
        name: 'гостиная',
        initials: '#',
        color: '#3E7D85',
        username: '',
        unread: 0,
        messages: [
          {
            id: 'fixture-c4',
            own: false,
            author: 'София',
            text: 'Кто сегодня на прогулку?',
            time: '12:10',
          },
        ],
      },
    ],
  };
}

export function visibleChats(
  session: DemoSession,
  query: string,
  unreadOnly: boolean,
) {
  const needle = query.trim().toLocaleLowerCase('ru');
  return session.chats
    .filter(
      (c) =>
        c.kind !== 'channel' &&
        (!unreadOnly || c.unread > 0) &&
        (!needle ||
          `${c.name} ${c.username}`.toLocaleLowerCase('ru').includes(needle)),
    )
    .slice()
    .sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned));
}
export function setDraft(
  session: DemoSession,
  chatId: string,
  text: string,
): DemoSession {
  if (!session.chats.some((c) => c.id === chatId)) return session;
  return { ...session, drafts: { ...session.drafts, [chatId]: text } };
}
export function openChat(session: DemoSession, chatId: string): DemoSession {
  if (!session.chats.some((c) => c.id === chatId && c.unread > 0))
    return session;
  return {
    ...session,
    chats: session.chats.map((c) =>
      c.id === chatId ? { ...c, unread: 0 } : c,
    ),
  };
}
/** Explicit local incoming events for testing reading and keyboard behavior. */
export function receiveDemo(
  session: DemoSession,
  chatId: string,
  count: number,
  time: string,
): DemoSession {
  if (!session.chats.some((c) => c.id === chatId) || ![1, 3].includes(count))
    return session;
  const messages: DemoMessage[] = Array.from({ length: count }, (_, index) => ({
    id: `demo-incoming-${session.nextId + index}`,
    own: false,
    day: demoToday,
    time,
    text: `Новое демо-сообщение ${session.nextId + index}. Продолжайте читать — история сохранит ваше место.`,
  }));
  return {
    ...session,
    nextId: session.nextId + count,
    chats: session.chats.map((c) =>
      c.id === chatId
        ? {
            ...c,
            unread: c.unread + count,
            messages: [...c.messages, ...messages],
          }
        : c,
    ),
  };
}
export function sendDemo(
  session: DemoSession,
  chatId: string,
  time: string,
): DemoSession {
  const text = session.drafts[chatId] ?? '';
  if (
    !text.trim() ||
    session.scenario === 'identityChanged' ||
    !session.chats.some((c) => c.id === chatId)
  )
    return session;
  const delivery: Delivery =
    session.scenario === 'offline'
      ? 'queued'
      : session.scenario === 'failure'
        ? 'failed'
        : session.scenario === 'unknown'
          ? 'unknown'
          : 'accepted';
  const message: DemoMessage = {
    id: `demo-local-${session.nextId}`,
    own: true,
    text,
    time,
    delivery,
    replyTo: session.replies?.[chatId],
  };
  return {
    ...session,
    nextId: session.nextId + 1,
    drafts: { ...session.drafts, [chatId]: '' },
    replies: { ...session.replies, [chatId]: undefined },
    chats: session.chats.map((c) =>
      c.id === chatId ? { ...c, messages: [...c.messages, message] } : c,
    ),
  };
}
export function retryDemo(
  session: DemoSession,
  chatId: string,
  messageId: string,
): DemoSession {
  if (session.scenario === 'identityChanged') return session;
  const delivery: Delivery =
    session.scenario === 'normal'
      ? 'accepted'
      : session.scenario === 'offline'
        ? 'queued'
        : session.scenario === 'unknown'
          ? 'unknown'
          : 'failed';
  return {
    ...session,
    chats: session.chats.map((c) =>
      c.id !== chatId
        ? c
        : {
            ...c,
            messages: c.messages.map((m) =>
              m.id === messageId && m.delivery === 'failed'
                ? { ...m, delivery }
                : m,
            ),
          },
    ),
  };
}
