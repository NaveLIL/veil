import appConfig from '../../../app.json';
import { Bell, Database, Info, KeyRound, Palette, Server, ShieldCheck, Smartphone, type LucideIcon } from 'lucide-react-native';
import type { SettingsSectionKey } from '../account/routes';
import type { VeilMobileRuntimeSnapshot } from '../../native/runtime';
import { ROCKET_CHAT_MIT_NOTICE } from '../rocketChat/notice';
type Tone = 'normal' | 'positive' | 'warning' | 'muted';

/** Existing native-backed settings facts, with centralized Russian product copy. */
const BUILD_CHANNEL = __DEV__ ? "Сборка для разработки" : "Закрытый тестовый клиент";

export const SETTINGS_SECTIONS: {
  key: SettingsSectionKey;
  icon: LucideIcon;
  title: string;
  summary: string;
}[] = [
  { key: "account", icon: KeyRound, title: "Аккаунт и восстановление", summary: "Идентичность и защищённое восстановление" },
  { key: "devices", icon: Smartphone, title: "Устройства", summary: "Этот телефон и доступ других устройств" },
  { key: "privacy", icon: ShieldCheck, title: "Конфиденциальность и безопасность", summary: "Блокировка, защита экрана и доверие" },
  { key: "notifications", icon: Bell, title: "Уведомления", summary: "Доступные настройки уведомлений" },
  { key: "appearance", icon: Palette, title: "Внешний вид", summary: "Тема, подложка и движение" },
  { key: "node", icon: Server, title: "Node и соединение", summary: "Адрес сервера и состояние связи" },
  { key: "storage", icon: Database, title: "Хранилище", summary: "Локальные зашифрованные данные" },
  { key: "about", icon: Info, title: "О Veil и диагностика", summary: "Версия, лицензии и состояние клиента" },
];

export interface DetailDefinition {
  title: string;
  subtitle: string;
  groups: {
    title: string;
    rows: DetailRowProps[];
    note?: string;
  }[];
}

export interface DetailRowProps {
  label: string;
  value?: string;
  detail?: string;
  tone?: Tone;
  mono?: boolean;
  selectable?: boolean;
  onPress?: () => void;
  switchValue?: boolean;
  onSwitchChange?: (value: boolean) => void;
  switchDisabled?: boolean;
}

export interface SettingsActions {
  allowReadyScreenshots: boolean;
  setAllowReadyScreenshots: (allowed: boolean) => void;
  openAndroidSettings: () => void;
  openProjectWebsite: () => void;
}

export function settingsDefinition(
  section: SettingsSectionKey,
  snapshot: VeilMobileRuntimeSnapshot | null,
  actions: SettingsActions,
): DetailDefinition {
  const connected = snapshot?.connectionState === "connected";
  const origin = snapshot?.binding?.canonicalServerOrigin ?? "Недоступно";

  switch (section) {
    case "account":
      return {
        title: "Аккаунт и восстановление",
        subtitle: "Секреты остаются в защищённом native-слое",
        groups: [
          {
            title: "Аккаунт на устройстве",
            rows: [
              { label: "Идентичность", value: snapshot?.identityExists ? "Доступна" : "Недоступно", tone: snapshot?.identityExists ? "positive" : "warning" },
              { label: "Сессия", value: snapshot?.sessionState === "open" ? "Открыта на этом устройстве" : "Заблокирована", tone: snapshot?.sessionState === "open" ? "positive" : "muted" },
              { label: "Восстановление", value: "Защищённый native-экран", detail: "Слова восстановления не передаются в React Native.", tone: "positive" },
            ],
            note: "Просмотр, замена и экспорт материалов восстановления требуют отдельной защищённой native-церемонии.",
          },
          {
            title: "Доверие к личности",
            rows: [
              { label: "Сравнение отпечатков", value: "В профиле собеседника", detail: "Сравнение safety number и QR выполняется отдельно от отображаемого имени.", tone: "warning" },
              { label: "Смена ключей", value: "Доступ закрывается", detail: "Смена ключа собеседника не принимается молча.", tone: "positive" },
            ],
          },
        ],
      };
    case "devices":
      return {
        title: "Устройства",
        subtitle: "Доступ устройств определяется явно",
        groups: [
          {
            title: "Это устройство",
            rows: [
              { label: "Телефон Android", value: connected ? "Активен" : "Только локально", tone: connected ? "positive" : "muted" },
              { label: "Перезапуск приложения", value: "Повторное открытие аккаунта", detail: "После перезапуска Veil откройте защищённую сессию снова.", tone: "muted" },
            ],
          },
          {
            title: "Управление устройствами",
            rows: [
              { label: "Добавить устройство", value: "Пока недоступно", detail: "Для привязки потребуется отдельный защищённый native-контракт.", tone: "warning" },
              { label: "Просмотр и отзыв доступа", value: "Пока недоступно", tone: "muted" },
            ],
            note: "Привязка устройства не должна передавать recovery-фразу или корневую идентичность через QR.",
          },
        ],
      };
    case "privacy":
      return {
        title: "Конфиденциальность и безопасность",
        subtitle: "Защита экрана и доступа",
        groups: [
          {
            title: "Защита экрана",
            rows: [
              { label: "Превью последних приложений", value: "Всегда скрыто", tone: "positive" },
              {
                label: "Снимки экрана для тестирования",
                detail: __DEV__
                  ? "Только в текущей сессии разработки. Снимки и запись разрешены для готового интерфейса; восстановление, регистрация, фон и последние приложения защищены."
                  : "В release-сборке возможность отключена существующей политикой защиты экрана.",
                switchValue: __DEV__ && actions.allowReadyScreenshots,
                onSwitchChange: actions.setAllowReadyScreenshots,
                switchDisabled: !__DEV__,
              },
              { label: "Восстановление и регистрация", value: "Всегда защищены", tone: "positive" },
            ],
            note: "Veil восстанавливает защиту экрана при уходе в фон, блокировке и восстановлении соединения.",
          },
          {
            title: "Доступ к приложению",
            rows: [
              { label: "Блокировка в фоне", value: "Немедленная", tone: "positive" },
              { label: "PIN и биометрия", value: "Пока недоступно", tone: "warning" },
              { label: "Защита от наложений", value: "Восстановление и настройка", tone: "positive" },
            ],
          },
        ],
      };
    case "notifications":
      return {
        title: "Уведомления",
        subtitle: "Содержание сообщений не раскрывается",
        groups: [
          {
            title: "Доставка",
            rows: [
              { label: "Push", value: "Пока недоступно", tone: "muted" },
              { label: "Синхронизация на открытом экране", value: connected ? "Подключено" : "Недоступно", tone: connected ? "positive" : "muted" },
              { label: "Содержание на экране блокировки", value: "Push пока не подключён", tone: "muted" },
              { label: "Настройки приложения в Android", value: "Открыть", detail: "Разрешения, уведомления и расход батареи в системных настройках.", onPress: actions.openAndroidSettings },
            ],
            note: "Содержимое сообщений не передаётся через push. Управление push недоступно в текущем native-контракте.",
          },
          {
            title: "Состояния внимания",
            rows: [
              { label: "Непрочитанные", value: "Контракт пока недоступен", tone: "muted" },
              { label: "Упоминания и ответы", value: "Контракт пока недоступен", tone: "muted" },
              { label: "Настройки отдельных чатов", value: "Пока недоступно", tone: "muted" },
            ],
          },
        ],
      };
    case "appearance":
      return {
        title: "Внешний вид",
        subtitle: "Локальное оформление этого устройства",
        groups: [
          {
            title: "Оформление",
            rows: [
              { label: "Тема", value: "Пять тем Veil" },
              { label: "Поверхности", value: "Острова Veil" },
              { label: "Подложка", value: "Локальное изображение" },
            ],
          },
          {
            title: "Доступность",
            rows: [
              { label: "Уменьшение движения", value: "Учитывает настройки Android", tone: "positive" },
              { label: "Размер текста", value: "Учитывает настройки Android" },
              { label: "Высокая контрастность", value: "Требует проверки на устройстве", tone: "warning" },
            ],
            note: "Мобильный и настольный Veil используют общую визуальную систему.",
          },
        ],
      };
    case "node":
      return {
        title: "Node и соединение",
        subtitle: "Сервер и область доверия",
        groups: [
          {
            title: "Текущий Node",
            rows: [
              { label: "Соединение", value: connected ? "Подключено" : "Недоступно", tone: connected ? "positive" : "warning" },
              { label: "Канонический адрес", value: origin, mono: true, selectable: true },
              { label: "Защищённая синхронизация", value: snapshot?.secureSyncState === "history_synchronized" ? "Готова" : "Не готова", tone: snapshot?.secureSyncState === "history_synchronized" ? "positive" : "warning" },
            ],
            note: "Node — сервер подключения. Смена адреса может изменить область аккаунта и доверия; она всегда требует явного действия.",
          },
          {
            title: "Управление соединением",
            rows: [
              { label: "Восстановление соединения", value: "Управляется native runtime", tone: "positive" },
              { label: "Частный центр сертификации", value: "Контракт пока недоступен", tone: "muted" },
              { label: "Забыть Node / остаться офлайн", value: "Пока недоступно", tone: "muted" },
            ],
          },
        ],
      };
    case "storage":
      return {
        title: "Хранилище",
        subtitle: "Зашифрованные данные на этом устройстве",
        groups: [
          {
            title: "Локальные данные",
            rows: [
              { label: "База данных", value: "SQLCipher", tone: "positive" },
              { label: "Резервная копия Android", value: "Отключена", tone: "positive" },
              { label: "Открытая переписка в интерфейсе", value: "Очищается при блокировке", tone: "positive" },
            ],
          },
          {
            title: "Медиа и поиск",
            rows: [
              { label: "Кэш вложений", value: "Контракт пока недоступен", tone: "muted" },
              { label: "Лимит локальных медиа", value: "Пока недоступно", tone: "muted" },
              { label: "Локальный поисковый индекс", value: "Пока недоступен", tone: "muted" },
            ],
            note: "Очистка медиа не должна удалять состояние шифрования или очередь отправки.",
          },
        ],
      };
    case "about":
      return {
        title: "О Veil и диагностика",
        subtitle: "Версия и состояние без раскрытия секретов",
        groups: [
          {
            title: "Сборка",
            rows: [
              { label: "Версия", value: appConfig.expo.version, mono: true },
              { label: "Канал", value: BUILD_CHANNEL },
              { label: "Независимый аудит криптографии", value: "Не завершён", tone: "warning" },
            ],
          },
          {
            title: "Поддержка",
            rows: [
              {
                label: "Публичные коды ошибок",
                value: "Реестр v1 · настройка и runtime",
                detail: "Коды не заменяют проверку реального обмена и доставки.",
                tone: "warning",
              },
              { label: "Копирование безопасной диагностики", value: "Пока недоступно", tone: "muted" },
              { label: "Сайт проекта", value: "Открыть", onPress: actions.openProjectWebsite },
              { label: "Лицензия", value: "AGPL-3.0-or-later" },
            ],
            note: "Диагностика не должна содержать recovery-слова, билеты, ключи, текст переписки, приватные URL и идентификаторы аккаунтов, устройств или сообщений.",
          },
          {
            title: "Открытые компоненты",
            rows: [{ label: "Rocket.Chat React Native", value: "4.77.0 · MIT", detail: "Адаптированные компоненты интерфейса; native runtime принадлежит Veil." }],
            note: ROCKET_CHAT_MIT_NOTICE,
          },
        ],
      };
  }
}
