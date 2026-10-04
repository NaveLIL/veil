import { DemoMessage, demoToday } from './model';

export const historyPageSize = 40;
export const latestThreshold = 48;
export function isAtLatest(
  offset: number,
  contentHeight: number,
  viewportHeight: number,
) {
  return (
    Math.max(0, contentHeight - viewportHeight - Math.max(0, offset)) <=
    latestThreshold
  );
}
/** Only newly appended incoming messages count; retries are not arrivals. */
export function incomingAfter(
  messages: DemoMessage[],
  lastId: string | undefined,
) {
  if (!lastId) return [];
  const previous = messages.findIndex((message) => message.id === lastId);
  return previous < 0
    ? []
    : messages.slice(previous + 1).filter((message) => !message.own);
}
export function dayLabel(day: string | undefined) {
  const value = day ?? demoToday;
  if (value === demoToday) return 'Сегодня';
  if (value === '2026-10-03') return 'Вчера';
  const date = new Date(`${value}T12:00:00Z`);
  return Number.isNaN(date.getTime())
    ? value
    : `${date.getUTCDate()} ${['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'][date.getUTCMonth()]}`;
}
