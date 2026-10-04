import React from 'react';
import { Modal, Pressable, ScrollView, StyleSheet, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Check, Shield, X } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { DemoChat, Scenario } from './model';
import { ROCKET_CHAT_MIT_NOTICE } from '../presentation/rocketChat/notice';
import { Avatar, Button, IconButton, Label } from './Primitives';
export type Sheet = 'profile' | 'scenarios' | 'about' | null;
type Props = {
  sheet: Sheet;
  chat?: DemoChat;
  scenario: Scenario;
  c: Palette;
  reduceMotion: boolean;
  onClose: () => void;
  onScenario: (scenario: Scenario) => void;
  addIncoming: (count: number) => void;
};
const scenarioNames: Record<Scenario, string> = {
  normal: 'Обычный чат',
  offline: 'Нет сети',
  failure: 'Ошибка отправки',
  unknown: 'Статус неизвестен',
  identityChanged: 'Ключ изменился',
};
export function PreviewSheet({
  sheet,
  chat,
  scenario,
  c,
  reduceMotion,
  onClose,
  onScenario,
  addIncoming,
}: Props) {
  return (
    <Modal
      visible={sheet !== null}
      transparent
      animationType={reduceMotion ? 'none' : 'slide'}
      onRequestClose={onClose}
      statusBarTranslucent
    >
      <View style={styles.modalRoot}>
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Закрыть панель"
          onPress={onClose}
          style={styles.scrim}
        />
        <SafeAreaView
          edges={['bottom']}
          style={[styles.sheet, { backgroundColor: c.surface }]}
        >
          <View style={styles.sheetHeading}>
            <Label color={c.text} style={[styles.cardTitle, styles.flex]}>
              {sheet === 'profile'
                ? 'О разговоре'
                : sheet === 'scenarios'
                  ? 'Сценарии сообщений'
                  : 'Veil Design'}
            </Label>
            <IconButton
              icon={X}
              label="Закрыть"
              color={c.muted}
              onPress={onClose}
            />
          </View>
          <ScrollView contentContainerStyle={styles.sheetContent}>
            {sheet === 'scenarios' ? (
              <>
                <ScenarioPicker value={scenario} onChange={onScenario} c={c} />
                {chat && (
                  <>
                    <Label color={c.muted} style={styles.sectionLabel}>
                      ПРОВЕРКА ИСТОРИИ
                    </Label>
                    <Button
                      label="Добавить входящее демо-сообщение"
                      onPress={() => addIncoming(1)}
                      c={c}
                    />
                    <Button
                      label="Добавить 3 входящих сообщения"
                      onPress={() => addIncoming(3)}
                      c={c}
                    />
                    <Label color={c.muted} style={styles.caption}>
                      Прокрутите историю вверх и добавьте сообщения: ваше место
                      сохранится, а внизу появится счётчик.
                    </Label>
                  </>
                )}
              </>
            ) : sheet === 'profile' && chat ? (
              <>
                <View style={styles.empty}>
                  <Avatar chat={chat} />
                  <Label color={c.text} style={styles.cardTitle}>
                    {chat.name}
                  </Label>
                </View>
                {!chat.kind || chat.kind === 'direct' ? (
                  <>
                    <Shield size={24} color={c.accent} />
                    <Label color={c.text} style={styles.cardTitle}>
                      Личность не подтверждена
                    </Label>
                    <Label color={c.muted} style={styles.body}>
                      В настоящем Veil доверие подтверждается сравнением ключей.
                      Имя и аватар не являются доказательством личности.
                    </Label>
                  </>
                ) : (
                  <Label color={c.muted} style={styles.body}>
                    Демо{' '}
                    {chat.kind === 'group'
                      ? 'группового чата'
                      : 'канала пространства'}
                    . Проверяем навигацию и внешний вид. Подключение к серверу и
                    групповое шифрование не используются.
                  </Label>
                )}
              </>
            ) : (
              <>
                <Label color={c.text} style={styles.cardTitle}>
                  Veil на маленьком экране
                </Label>
                <Label color={c.muted} style={styles.body}>
                  Отдельный дизайн-макет с вымышленными разговорами. Без
                  регистрации, Access Pass и подключения к мессенджеру.
                  Скриншоты разрешены.
                </Label>
                <Label color={c.muted} style={styles.body}>
                  Демо-сообщения и настройки живут в памяти до перезапуска.
                  Выбранная картинка обрабатывается локально.
                </Label>
                <Label color={c.muted} style={styles.body}>
                  Veil © NaveLIL · AGPL-3.0-or-later. Composer pattern adapted
                  from Rocket.Chat.ReactNative 4.77.0.
                </Label>
                <Label color={c.muted} style={styles.license}>
                  {ROCKET_CHAT_MIT_NOTICE}
                </Label>
              </>
            )}
          </ScrollView>
        </SafeAreaView>
      </View>
    </Modal>
  );
}
function ScenarioPicker({
  value,
  onChange,
  c,
}: {
  value: Scenario;
  onChange: (scenario: Scenario) => void;
  c: Palette;
}) {
  return (
    <View>
      {(Object.keys(scenarioNames) as Scenario[]).map((scenario) => (
        <Pressable
          key={scenario}
          onPress={() => onChange(scenario)}
          accessibilityRole="radio"
          accessibilityLabel={scenarioNames[scenario]}
          accessibilityState={{ checked: value === scenario }}
          style={[styles.settingRow, { borderBottomColor: c.line }]}
        >
          <Label color={c.text} style={styles.flex}>
            {scenarioNames[scenario]}
          </Label>
          {value === scenario && <Check size={20} color={c.accent} />}
        </Pressable>
      ))}
      <Label color={c.muted} style={styles.body}>
        Это состояния вымышленной переписки. Сетевые ошибки не создаются.
      </Label>
    </View>
  );
}

const styles = StyleSheet.create({
  modalRoot: { flex: 1, justifyContent: 'flex-end' },
  scrim: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0,0,0,0.65)',
  },
  sheet: {
    borderTopLeftRadius: geometry.radius,
    borderTopRightRadius: geometry.radius,
    maxHeight: '88%',
  },
  sheetHeading: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingLeft: 20,
    paddingRight: 10,
    paddingTop: 12,
  },
  cardTitle: { fontSize: 18, lineHeight: 26, fontWeight: '600' },
  flex: { flex: 1, minWidth: 0 },
  sheetContent: { paddingHorizontal: 20, paddingBottom: 24 },
  sectionLabel: {
    ...typography.micro,
    fontWeight: '600',
    letterSpacing: 1.2,
    marginTop: 24,
    marginBottom: 12,
  },
  caption: { ...typography.caption },
  empty: { alignItems: 'center', paddingVertical: 28, gap: 12 },
  body: { fontSize: 14, lineHeight: 23, marginVertical: 10 },
  license: { fontSize: 11, lineHeight: 17, marginTop: 20 },
  settingRow: {
    minHeight: 60,
    paddingVertical: 8,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
});
