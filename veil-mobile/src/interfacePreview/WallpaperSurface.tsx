import React from 'react';
import { Image, StyleSheet, View } from 'react-native';
import { Palette } from './appearance';
export function WallpaperSurface({c, wallpaper, showWallpaper, blur, dim}: {c:Palette; wallpaper:string|null; showWallpaper:boolean; blur:number; dim:number}) {
  return showWallpaper ? (
      <View
        pointerEvents="none"
        importantForAccessibility="no-hide-descendants"
        style={StyleSheet.absoluteFillObject}
      >
        {wallpaper ? (
          <Image
            source={{ uri: wallpaper }}
            resizeMode="cover"
            blurRadius={blur}
            style={StyleSheet.absoluteFillObject}
          />
        ) : (
          <View style={styles.defaultWallpaper}>
            <View
              style={[styles.glow, styles.one, { backgroundColor: c.accent }]}
            />
            <View
              style={[styles.glow, styles.two, { backgroundColor: c.accent }]}
            />
            <View
              style={[styles.glow, styles.three, { backgroundColor: c.accent }]}
            />
          </View>
        )}
        <View
          style={[
            StyleSheet.absoluteFillObject,
            { backgroundColor: `rgba(0,0,0,${dim / 100})` },
          ]}
        />
      </View>
    ) : null;
}
const styles = StyleSheet.create({
  defaultWallpaper: { flex: 1, overflow: 'hidden', backgroundColor: '#100A19' },
  glow: {
    position: 'absolute',
    opacity: 0.2,
    borderRadius: 180,
    transform: [{ rotate: '-25deg' }],
  },
  one: { width: 320, height: 170, top: -30, left: -150 },
  two: { width: 350, height: 150, top: '42%', right: -210 },
  three: { width: 340, height: 160, bottom: -50, left: -120 },
});
