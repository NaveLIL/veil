import type { TimelineMessage } from './conversationContract';
import { designAttachments } from './attachments';

/** Varied deterministic history; its demonstration links are never opened. */
export function olderHistory(chatId: string, count: number): TimelineMessage[] {
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
  const messages: TimelineMessage[] = Array.from(
    { length: count },
    (_, index) => ({
      id: `fixture-history-${chatId}-${index}`,
      own: Math.floor(index / 3) % 2 === 1,
      day: new Date(
        Date.UTC(2026, 9, 3 - Math.ceil(count / 45) + Math.floor(index / 45)),
      )
        .toISOString()
        .slice(0, 10),
      time: `${String(9 + Math.floor((index % 45) / 30)).padStart(2, '0')}:${String(index % 30).padStart(2, '0')}`,
      text: texts[index % texts.length],
      ...(Math.floor(index / 3) % 2 === 1
        ? { delivery: 'accepted' as const }
        : {}),
    }),
  );
  // A A A A B B A; then twenty short messages and attention/media extremes.
  if (count >= 40) {
    const start = count - 40;
    for (let i = 0; i < 36; i++) {
      const row = messages[start + i];
      row.day = i < 7 ? '2026-10-02' : '2026-10-03';
      row.time = '10:' + String(i).padStart(2, '0');
      row.own = i < 4 || i === 6 || (i >= 7 && i <= 29) || i === 31 || i >= 33;
      row.delivery = row.own ? 'accepted' : undefined;
      row.text = i === 7 ? '🙂' : i === 8 ? 'Я' : 'Короткая реплика ' + i;
    }
    messages[start + 27].delivery = 'unknown';
    messages[start + 28].delivery = 'queued';
    messages[start + 29].delivery = 'failed';
    messages[start + 30].author =
      'Очень длинное имя собеседника, которое должно оставаться читаемым';
    messages[start + 30].text =
      'https://example.invalid/' + 'longsegment'.repeat(70);
    messages[start + 31].text =
      'Очень длинное сообщение, которое полностью доступно при прокрутке. '.repeat(
        80,
      );
    messages[start + 32].text = 'Длинный оригинал для цитирования. '.repeat(30);
    messages[start + 33].replyTo = messages[start + 32].id;
    messages[start + 34].replyTo = messages[start + 32].id;
    messages[start + 34].attachment = designAttachments[0];
    messages[start + 35].replyTo = messages[start + 32].id;
    messages[start + 35].attachment = designAttachments[1];
  }
  return messages;
}
