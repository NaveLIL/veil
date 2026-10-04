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
        if (relative !== 'src/interfacePreview/appearanceBridge.ts') throw Error('NativeModules is restricted to the local wallpaper bridge');
        const parent = node.parent;
        const imported = ts.isImportSpecifier(parent) && parent.name === node && !parent.propertyName;
        const selected = ts.isPropertyAccessExpression(parent) && parent.expression === node && parent.name.text === 'VeilDesignAppearance';
        if (!imported && !selected) throw Error('Only the explicit VeilDesignAppearance capability is allowed');
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
          } else if (!['react', 'react-native', 'react-native-safe-area-context', 'lucide-react-native', 'react-native-gesture-handler', 'react-native-reanimated'].includes(name)) throw Error(`Unapproved preview dependency: ${name}`);
        }
      }
      ts.forEachChild(node, check);
    }
    check(ast);
  }
  visit('design-preview-index.ts');
  if (visited.size !== allowedSources.length) throw Error('Preview source inventory drift');
  const application = fs.readFileSync(path.join(root, 'android/designPreview/src/main/java/io/veil/mobile/designpreview/DesignApplication.kt'), 'utf8');
  if (/import io\.veil\.(?!mobile\.designpreview)|VeilMobileRuntime|VeilCrypto|PackageList|ExpoModulesPackage|native\/generated/.test(application)) throw Error('Preview native host must not register account packages');
  const activity = fs.readFileSync(path.join(root, 'android/designPreview/src/main/java/io/veil/mobile/designpreview/DesignActivity.kt'), 'utf8');
  if (/FLAG_SECURE|clearFlags|consumeEnrollment|RecoveryActivity/.test(activity)) throw Error('Preview must use its own default capture policy, never modify an account window');
  if (!application.includes('DesignAppearancePackage()')) throw Error('Local wallpaper picker package missing');
  return [...visited];
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify({ verified: true, applicationSources: verifyPreviewSource() }));
}
