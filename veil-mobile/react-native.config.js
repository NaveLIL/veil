// Override stale autolinking entry: @react-native-community/cli falls back to
// the legacy `expo.core.ExpoModulesPackage` path for the `expo` package, but
// Expo SDK 53 ships the package at `expo.modules.ExpoModulesPackage`.
module.exports = {
  dependencies: {
    expo: {
      platforms: {
        android: {
          packageImportPath: 'import expo.modules.ExpoModulesPackage;',
          packageInstance: 'new ExpoModulesPackage()',
        },
      },
    },
  },
};
