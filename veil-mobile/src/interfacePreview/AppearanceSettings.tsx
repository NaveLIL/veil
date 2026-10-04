import React from 'react';
import { Image, Pressable, ScrollView, StyleSheet, View } from 'react-native';
import { Check } from 'lucide-react-native';
import {
  geometry,
  Palette,
  palettes,
  ThemeName,
  typography,
} from './appearance';
import { Button, Label, SettingSwitch, Stepper } from './Primitives';
type Setter<T> = React.Dispatch<React.SetStateAction<T>>;
type Props = {
  c: Palette;
  theme: ThemeName;
  setTheme: Setter<ThemeName>;
  wallpaper: string | null;
  setWallpaper: Setter<string | null>;
  showWallpaper: boolean;
  setShowWallpaper: Setter<boolean>;
  dim: number;
  setDim: Setter<number>;
  blur: number;
  setBlur: Setter<number>;
  reduceMotion: boolean;
  setReduceMotion: Setter<boolean>;
  systemReduceMotion: boolean;
  picking: boolean;
  pickerError: string;
  chooseWallpaper: () => Promise<void>;
  onLock: () => void;
  onScenarios: () => void;
  onAbout: () => void;
};
export function AppearanceSettings({
  c,
  theme,
  setTheme,
  wallpaper,
  setWallpaper,
  showWallpaper,
  setShowWallpaper,
  dim,
  setDim,
  blur,
  setBlur,
  reduceMotion,
  setReduceMotion,
  systemReduceMotion,
  picking,
  pickerError,
  chooseWallpaper,
  onLock,
  onScenarios,
  onAbout,
}: Props) {
  return (
    <ScrollView contentContainerStyle={styles.settingsContent}>
      <Label color={c.text} style={styles.heading}>
        Внешний вид
      </Label>
      <Label color={c.muted} style={styles.caption}>
        Настройки этого макета
      </Label>
      <Label color={c.muted} style={styles.sectionLabel}>
        ЦВЕТОВАЯ СХЕМА
      </Label>
      {(Object.keys(palettes) as ThemeName[]).map((name) => (
        <Pressable
          key={name}
          accessibilityRole="radio"
          accessibilityLabel={`Тема ${name}`}
          accessibilityState={{ checked: theme === name }}
          onPress={() => setTheme(name)}
          style={[
            styles.themeRow,
            {
              borderColor: theme === name ? c.accent : c.line,
              backgroundColor: theme === name ? c.tint : c.surface,
            },
          ]}
        >
          <View style={styles.swatches}>
            {[
              palettes[name].bg,
              palettes[name].raised,
              palettes[name].accent,
            ].map((color) => (
              <View
                key={color}
                style={[styles.swatch, { backgroundColor: color }]}
              />
            ))}
          </View>
          <Label color={c.text} style={styles.flex}>
            {name}
          </Label>
          {theme === name && <Check size={18} color={c.accent} />}
        </Pressable>
      ))}
      <Label color={c.muted} style={styles.sectionLabel}>
        ПОДЛОЖКА
      </Label>
      <View style={[styles.wallpaperSample, { backgroundColor: c.tint }]}>
        {wallpaper && (
          <Image
            source={{ uri: wallpaper }}
            blurRadius={blur}
            style={StyleSheet.absoluteFillObject}
          />
        )}
        <View
          style={[
            StyleSheet.absoluteFillObject,
            { backgroundColor: `rgba(0,0,0,${dim / 100})` },
          ]}
        />
        <View style={[styles.sampleDock, { backgroundColor: c.bg }]} />
        <View style={[styles.sampleIsland, { backgroundColor: c.bg }]}>
          <View
            style={[styles.sampleComposer, { backgroundColor: c.raised }]}
          />
        </View>
      </View>
      <Button
        label={picking ? 'Открываем выбор…' : 'Выбрать изображение'}
        onPress={() => {
          void chooseWallpaper();
        }}
        c={c}
      />
      {!!pickerError && (
        <Label accessibilityRole="alert" color={c.muted} style={styles.caption}>
          {pickerError}
        </Label>
      )}
      <Button
        label="Вернуть стандартный фон"
        onPress={() => {
          setWallpaper(null);
          setShowWallpaper(true);
          setDim(20);
          setBlur(4);
        }}
        c={c}
      />
      <SettingSwitch
        label="Показывать подложку"
        value={showWallpaper}
        onChange={setShowWallpaper}
        c={c}
      />
      <Stepper
        label="Затемнение"
        value={`${dim}%`}
        onMinus={() => setDim((v) => Math.max(0, v - 10))}
        onPlus={() => setDim((v) => Math.min(90, v + 10))}
        c={c}
      />
      <Stepper
        label="Размытие фото"
        value={`${blur} px`}
        onMinus={() => setBlur((v) => Math.max(0, v - 2))}
        onPlus={() => setBlur((v) => Math.min(24, v + 2))}
        c={c}
      />
      <Label color={c.muted} style={styles.caption}>
        Картинка выбирается на устройстве. Острова сохраняют контраст при любом
        фоне. Настройки пока живут в памяти макета.
      </Label>
      <Label color={c.muted} style={styles.sectionLabel}>
        ДВИЖЕНИЕ
      </Label>
      <SettingSwitch
        label="Уменьшить анимации"
        value={reduceMotion}
        onChange={setReduceMotion}
        c={c}
      />
      {systemReduceMotion && (
        <Label color={c.muted} style={styles.caption}>
          Анимации уже уменьшены настройкой Android.
        </Label>
      )}
      <Button label="Посмотреть экран блокировки" onPress={onLock} c={c} />
      <Button label="Сценарии сообщений" onPress={onScenarios} c={c} />
      <Button label="О дизайн-макете" onPress={onAbout} c={c} />
    </ScrollView>
  );
}
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  heading: {
    ...typography.heading,
    fontWeight: '600',
    letterSpacing: -0.4,
  },
  caption: { ...typography.caption },
  sectionLabel: {
    ...typography.micro,
    fontWeight: '600',
    letterSpacing: 1.2,
    marginTop: 24,
    marginBottom: 12,
  },
  settingsContent: { padding: 14, paddingTop: 20, paddingBottom: 30 },
  themeRow: {
    minHeight: 56,
    borderRadius: geometry.radius,
    borderWidth: 1,
    marginBottom: 8,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    paddingHorizontal: 12,
  },
  swatches: { flexDirection: 'row', gap: 3 },
  swatch: { width: 13, height: 18, borderRadius: 4 },
  wallpaperSample: {
    height: 105,
    borderRadius: geometry.radius,
    padding: 8,
    gap: 6,
    flexDirection: 'row',
    overflow: 'hidden',
    marginBottom: 8,
  },
  sampleDock: { width: 22, borderRadius: geometry.radius * 0.4 },
  sampleIsland: {
    flex: 1,
    borderRadius: geometry.radius * 0.4,
    justifyContent: 'flex-end',
    padding: 6,
  },
  sampleComposer: { height: 12, borderRadius: geometry.radius * 0.25 },
});
