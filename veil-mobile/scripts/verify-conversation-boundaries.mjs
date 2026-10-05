import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { fileURLToPath } from 'node:url';
import { root, verifyPreviewSource } from './verify-design-preview-source.mjs';

const edges = new Map();
function dependencies(relative) {
  if (edges.has(relative)) return edges.get(relative);
  const text = fs.readFileSync(path.join(root, relative), 'utf8');
  if (relative.endsWith('.json')) { JSON.parse(text); edges.set(relative, []); return []; }
  const emitted = ts.transpileModule(text, { compilerOptions: { module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.Preserve } }).outputText;
  const ast = ts.createSourceFile(relative, emitted, ts.ScriptTarget.Latest, true);
  const dependencies = [];
  for (const node of ast.statements) {
    if (!(ts.isImportDeclaration(node) || ts.isExportDeclaration(node))) continue;
    const name = node.moduleSpecifier?.text;
    if (!name?.startsWith('.')) continue;
    const base = path.resolve(root, path.dirname(relative), name);
    const file = ['.ts', '.tsx', ''].map(ext => base + ext).find(file => fs.existsSync(file) && fs.statSync(file).isFile());
    if (!file) throw Error(`Unresolved source ${relative}: ${name}`);
    dependencies.push(path.relative(root, file).replaceAll('\\', '/'));
  }
  edges.set(relative, dependencies);
  return dependencies;
}
function closure(entry, forbid = () => false) {
  const visited = new Set();
  function walk(file, stack = []) {
    if (forbid(file)) throw Error(`Implementation crosses UI boundary: ${[...stack, file].join(' -> ')}`);
    if (stack.includes(file)) throw Error(`Runtime dependency cycle: ${[...stack, file].join(' -> ')}`);
    if (visited.has(file)) return;
    visited.add(file);
    for (const next of dependencies(file)) walk(next, [...stack, file]);
  }
  walk(entry);
  return [...visited];
}
verifyPreviewSource();
const presentation = ['useVeilStyles.ts', 'RouteSurface.tsx', 'KeyboardFrame.tsx', 'ConversationSurface.tsx', 'MessageRow.tsx', 'MessageActionsPanel.tsx', 'ChatDeck.tsx', 'DockItem.tsx', 'DirectoryRow.tsx', 'ProfileEntry.tsx', 'ProfilePanelFrame.tsx', 'WallpaperSurface.tsx', 'AppearanceSettings.tsx', 'PresentationContext.tsx', 'VeilState.tsx', 'useAppearanceState.ts'].flatMap(file => closure(`src/interfacePreview/${file}`, file =>
  /\/(native|stores|presenters)\//.test(file) || /\/(model|attachments|useAttachmentTransfers|DesignConversation|.*Bridge|useAppearancePreferences)\.tsx?$/.test(file)));
const demo = closure('design-preview-index.ts');
const native = closure('src/components/layout/NativeDesignTimeline.tsx', file =>
  /\/interfacePreview\/(model|historyFixtures|attachments|DesignApp|DesignConversation|NavigationPanel|useAttachmentTransfers|.*Bridge)\.tsx?$/.test(file));
closure('src/screens/HomeScreen.tsx', file => /\/interfacePreview\/(model|historyFixtures|DesignApp|DesignConversation|NavigationPanel|UserProfile|.*Bridge)\.tsx?$/.test(file));
// User routes share Veil presentation; legal attribution is deliberately allowed.
for (const route of ['HomeScreen', 'ContactSearchScreen', 'DirectConversationScreen', 'SettingsScreen', 'OnboardingScreen']) {
  closure(`src/screens/${route}.tsx`, file =>
    /\/presentation\/rocketChat\/(?!notice\.)/.test(file) || /\/components\/layout\/MobileHeader\.tsx?$/.test(file)
    || /\/interfacePreview\/(model|historyFixtures|DesignApp|DesignConversation|NavigationPanel|UserProfile|.*Bridge)\.tsx?$/.test(file));
}
const coordinator = fs.readFileSync(path.join(root, 'src/interfacePreview/DesignApp.tsx'), 'utf8');
if (/from ['"].*\/(ConversationHistory|MessageRow|useMessageInteractions|attachments|useAttachmentTransfers|preferencesBridge|appearanceBridge)['"]/.test(coordinator)) throw Error('DesignApp owns feature implementation details again');
// The canonical contract also exports the real capability flags used by the native adapter.
export const allowedProductionPresentation = [...new Set([...presentation, 'src/interfacePreview/conversationContract.ts'])];
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  console.log(JSON.stringify({ verified: true, runtimeCycles: false, sharedPresentation: allowedProductionPresentation, demoSources: demo.length, nativeSources: native.length, coordinatorLines: coordinator.split('\n').length }));
