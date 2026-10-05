/** Product copy for the exact native contact flow; never formats raw exceptions. */
export const contactsCopy = {
  title: 'Новый личный чат', subtitle: 'Найти пользователя на текущем Node', username: 'Точное имя пользователя', submit: 'Найти пользователя',
  hint: 'Введите точный username. Имя не подтверждает личность — ключи проверяются отдельно.',
  empty: 'Кого найдём?', emptyDetail: 'Введите username собеседника на этом сервере.',
  missing: 'Пользователь не найден', missingDetail: 'Проверьте точное написание username и повторите поиск.',
  loading: 'Ищем пользователя', loadingDetail: 'Проверяем результат через защищённую сессию.',
  creating: 'Открываем личный чат', creatingDetail: 'Ожидаем подтверждение native runtime.',
  unavailable: 'Поиск сейчас недоступен', unavailableDetail: 'Для поиска нужна открытая сессия текущего аккаунта.',
  error: 'Не удалось завершить действие', errorDetail: 'Результат операции не подтверждён. Проверьте соединение и повторите поиск.',
  retry: 'Повторить поиск', open: (username: string) => `Открыть личный чат с ${username}`,
};
