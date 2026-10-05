import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const allowedSources = [
  'design-preview-index.ts', 'src/interfacePreview/DesignApp.tsx',
  'src/interfacePreview/model.ts', 'src/presentation/rocketChat/notice.ts',
  'src/interfacePreview/appearance.ts', 'src/interfacePreview/appearanceBridge.ts',
  'src/interfacePreview/ChatDeck.tsx', 'src/interfacePreview/UserProfile.tsx', 'src/interfacePreview/navigation.ts',
  'src/interfacePreview/ConversationHistory.tsx', 'src/interfacePreview/Composer.tsx', 'src/interfacePreview/history.ts',
  'src/interfacePreview/Primitives.tsx', 'src/interfacePreview/AppearanceSettings.tsx', 'src/interfacePreview/NavigationPanel.tsx',
  'src/interfacePreview/ConversationScreen.tsx', 'src/interfacePreview/LockPreview.tsx', 'src/interfacePreview/PreviewSheet.tsx',
  'src/interfacePreview/KeyboardFrame.tsx',
  'src/interfacePreview/messageActions.ts', 'src/interfacePreview/MessageActionsPanel.tsx',
  'src/interfacePreview/MessageQuote.tsx', 'src/interfacePreview/MessageRow.tsx',
  'src/interfacePreview/useMessageInteractions.ts', 'src/interfacePreview/useQuoteNavigation.ts',
  'src/interfacePreview/clipboardBridge.ts',
  'src/interfacePreview/deliveryPresentation.ts',
  'src/interfacePreview/attachments.ts', 'src/interfacePreview/useAttachmentTransfers.ts',
  'src/interfacePreview/preferencesBridge.ts', 'src/interfacePreview/useAppearancePreferences.ts',
  'src/interfacePreview/useModalAccessibility.ts',
  'src/interfacePreview/AccessibilityFocusBoundary.tsx',
  'src/interfacePreview/designAccessibilityBridge.ts',
  'src/interfacePreview/conversationContract.ts',
  'src/interfacePreview/attachmentContract.ts', 'src/interfacePreview/messageGrouping.ts',
  'src/interfacePreview/ConversationSurface.tsx',
  'src/interfacePreview/DesignConversation.tsx', 'src/interfacePreview/useDesignAppearance.tsx',
  'src/interfacePreview/historyFixtures.ts',
  'src/interfacePreview/AttachmentVisual.tsx', 'src/interfacePreview/AttachmentCard.tsx', 'src/interfacePreview/AttachmentPanels.tsx',
  'src/interfacePreview/LiveBlur.tsx', 'src/interfacePreview/VeilSheet.tsx',
  'src/interfacePreview/PresentationContext.tsx',
  'src/interfacePreview/useSheetMotion.ts',
  'src/interfacePreview/appearancePreferences.ts', 'src/interfacePreview/useAppearanceState.ts',
  'src/interfacePreview/navigationStyles.ts', 'src/interfacePreview/DockItem.tsx', 'src/interfacePreview/DirectoryRow.tsx',
  'src/interfacePreview/profileStyles.ts', 'src/interfacePreview/ProfileEntry.tsx', 'src/interfacePreview/ProfilePanelFrame.tsx',
  'src/interfacePreview/WallpaperSurface.tsx',
  'src/interfacePreview/messageActionCapabilities.ts',
];
export function verifyPreviewSource() {
  const visited = new Set();
  function visit(relative) {
    if (!allowedSources.includes(relative)) throw Error(`Preview imports account code: ${relative}`);
    if (visited.has(relative)) return;
    visited.add(relative);
    const text = fs.readFileSync(path.join(root, relative), 'utf8');
    const ast = ts.createSourceFile(relative, text, ts.ScriptTarget.Latest, true);
    function check(node) {
      if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) throw Error('Preview must use static imports only');
      if (ts.isIdentifier(node) && ['fetch', 'XMLHttpRequest', 'WebSocket', 'TurboModuleRegistry', 'Linking', 'AsyncStorage'].includes(node.text)) throw Error(`Preview capability not allowed: ${node.text}`);
      if (ts.isIdentifier(node) && node.text === 'NativeModules') {
        const capability = relative === 'src/interfacePreview/designAccessibilityBridge.ts' ? 'VeilDesignAccessibility' : relative === 'src/interfacePreview/appearanceBridge.ts' ? 'VeilDesignAppearance' : relative === 'src/interfacePreview/clipboardBridge.ts' ? 'VeilDesignClipboard' : relative === 'src/interfacePreview/preferencesBridge.ts' ? 'VeilDesignPreferences' : null;
        if (!capability) throw Error('NativeModules is restricted to explicit preview bridges');
        const parent = node.parent;
        const imported = ts.isImportSpecifier(parent) && parent.name === node && !parent.propertyName;
        const selected = ts.isPropertyAccessExpression(parent) && parent.expression === node && parent.name.text === capability;
        if (!imported && !selected) throw Error(`Only the explicit ${capability} capability is allowed`);
      }
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        const specifier = node.moduleSpecifier;
        if (specifier) {
          if (!ts.isStringLiteral(specifier)) throw Error('Non-literal preview import');
          const name = specifier.text;
          if (name.startsWith('.')) {
            const base = path.resolve(root, path.dirname(relative), name);
            const candidate = ['.ts', '.tsx'].map(extension => base + extension).find(file => fs.existsSync(file));
            if (!candidate) throw Error(`Unresolved preview import: ${name}`);
            visit(path.relative(root, candidate).replaceAll('\\', '/'));
          } else if (!['react', 'react-native', 'react-native-safe-area-context', 'lucide-react-native', 'react-native-gesture-handler', 'react-native-reanimated', 'react-native-svg'].includes(name)) throw Error(`Unapproved preview dependency: ${name}`);
        }
      }
      ts.forEachChild(node, check);
    }
    check(ast);
  }
  visit('design-preview-index.ts');
  if (visited.size !== allowedSources.length) throw Error('Preview source inventory drift');
  const application = fs.readFileSync(path.join(root, 'android/designPreview/src/main/java/io/veil/mobile/designpreview/DesignApplication.kt'), 'utf8');
  if (/import io\.veil\.(?!mobile\.(?:designpreview|presentation\.VeilPresentationPackage))|VeilMobileRuntime|VeilCrypto|PackageList|ExpoModulesPackage|native\/generated/.test(application)) throw Error('Preview native host must not register account packages');
  if (!application.includes('VeilPresentationPackage(false)')) throw Error('Preview must disable account appearance module registration');
  for (const file of fs.readdirSync(path.join(root, 'android/presentation/src/main/java/io/veil/mobile/presentation'))) {
    const native = fs.readFileSync(path.join(root, 'android/presentation/src/main/java/io/veil/mobile/presentation', file), 'utf8');
    if (/uniffi|veil_ffi|VeilMobileRuntime|VeilCrypto|FLAG_SECURE|clearFlags|consumeEnrollment|RecoveryActivity|HttpURLConnection|okhttp|java\.net/.test(native)) throw Error('Shared presentation acquired an account/network capability');
  }
  const activity = fs.readFileSync(path.join(root, 'android/designPreview/src/main/java/io/veil/mobile/designpreview/DesignActivity.kt'), 'utf8');
  if (/FLAG_SECURE|clearFlags|consumeEnrollment|RecoveryActivity/.test(activity)) throw Error('Preview must use its own default capture policy, never modify an account window');
  if (!application.includes('DesignAppearancePackage()')) throw Error('Local wallpaper picker package missing');
  if (!application.includes('DesignClipboardPackage()')) throw Error('Preview clipboard package missing');
  if (!application.includes('DesignPreferencesPackage()')) throw Error('Preview appearance preferences package missing');
  // JavaModuleWrapper inspects getDeclaredMethods(); inherited bridge methods
  // silently disappear from JS even though direct Java reflection still works.
  for (const [file, methods] of [
    ['DesignPreferencesModule.kt', ['loadPreferences', 'savePreferences']],
    ['DesignAppearanceModule.kt', ['pickWallpaper']],
  ]) {
    const bridge = fs.readFileSync(path.join(root, 'android/designPreview/src/main/java/io/veil/mobile/designpreview', file), 'utf8');
    for (const method of methods) {
      if (!bridge.includes(`@ReactMethod override fun ${method}(`)) throw Error(`Preview bridge does not declare JS method: ${method}`);
    }
  }
  return [...visited];
}
/** Type-only contracts are audited above but do not exist in the JS bundle. */
export function runtimePreviewSources() {
  const visited = new Set();
  function visit(relative) {
    if (visited.has(relative)) return;
    if (!allowedSources.includes(relative)) throw Error(`Unapproved runtime source: ${relative}`);
    visited.add(relative);
    const emitted = ts.transpileModule(fs.readFileSync(path.join(root, relative), 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.Preserve },
    }).outputText;
    const ast = ts.createSourceFile(relative, emitted, ts.ScriptTarget.Latest, true);
    for (const node of ast.statements) {
      if (!(ts.isImportDeclaration(node) || ts.isExportDeclaration(node))) continue;
      const name = node.moduleSpecifier?.text;
      if (!name?.startsWith('.')) continue;
      const base = path.resolve(root, path.dirname(relative), name);
      const candidate = ['.ts', '.tsx'].map(extension => base + extension).find(file => fs.existsSync(file));
      if (!candidate) throw Error(`Unresolved runtime source: ${name}`);
      visit(path.relative(root, candidate).replaceAll('\\', '/'));
    }
  }
  visit('design-preview-index.ts');
  return [...visited];
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify({ verified: true, applicationSources: verifyPreviewSource() }));
}
