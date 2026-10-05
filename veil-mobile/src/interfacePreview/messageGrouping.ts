import type { TimelineMessage } from './conversationContract';

export function canGroup(
  previous: TimelineMessage | undefined,
  current: TimelineMessage,
) {
  if (
    !previous ||
    previous.own !== current.own ||
    previous.author !== current.author ||
    previous.day !== current.day
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
