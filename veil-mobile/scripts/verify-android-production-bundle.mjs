import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { allowedProductionPresentation } from './verify-conversation-boundaries.mjs';

const require = createRequire(import.meta.url);
const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const expoPackage = require.resolve("expo/package.json", { paths: [projectDirectory] });
const expoCli = require.resolve("@expo/cli", { paths: [dirname(expoPackage)] });
const outputDirectory = await mkdtemp(join(tmpdir(), "veil-android-production-bundle-"));
const bundlePath = join(outputDirectory, "index.android.bundle");
const sourceMapPath = `${bundlePath}.map`;

const forbiddenLiterals = [
  "DESIGN PREVIEW",
  "Local-only",
  "Design Circle",
];

const forbiddenSourceFragments = [
  "/src/designPreview/",
  "/src/components/navigation/RootDock.tsx",
  "/src/screens/DesignPreviewScreens.tsx",
  "/src/presentation/rocketChat/ContactItem.tsx",
  "/src/presentation/rocketChat/theme.ts",
  "/node_modules/@rocket.chat/",
  "/node_modules/rocketchat-sdk/",
  "/node_modules/@nozbe/watermelondb/",
];

const requiredSourcePaths = [
  "/src/screens/HomeScreen.tsx",
  "/src/screens/ContactSearchScreen.tsx",
  "/src/components/layout/ChatIsland.tsx",
  "/src/components/runtime/SecureRuntimeGate.tsx",
  "/src/hooks/useVeilRuntimeLifecycle.ts",
  "/src/presenters/directTimeline.ts",
  "/src/presenters/contacts.ts",
  "/src/presentation/account/AccountDirectory.tsx",
  "/src/presentation/account/AccountFrame.tsx",
  "/src/presentation/account/AccountProfile.tsx",
  "/src/presentation/settings/SettingsContent.tsx",
  "/src/presentation/settings/definitions.ts",
  "/src/presentation/account/AccountRouteSurface.tsx",
  "/src/components/layout/NativeDesignTimeline.tsx",
  "/src/presenters/directDesignAdapter.ts",
  "/src/interfacePreview/ConversationSurface.tsx",
  "/src/interfacePreview/MessageRow.tsx",
  "/src/interfacePreview/Composer.tsx",
  "/src/presentation/rocketChat/notice.ts",
];

function runExpoExport() {
  const args = [
    expoCli,
    "export:embed",
    "--platform", "android",
    "--dev", "false",
    "--minify", "false",
    "--entry-file", "index.ts",
    "--bundle-output", bundlePath,
    "--sourcemap-output", sourceMapPath,
    "--assets-dest", join(outputDirectory, "assets"),
    "--reset-cache",
  ];

  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, args, {
      cwd: projectDirectory,
      env: { ...process.env, NODE_ENV: "production" },
      stdio: "inherit",
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolveRun();
        return;
      }
      rejectRun(new Error(
        `Expo production bundle failed (${signal ? `signal ${signal}` : `exit ${code}`})`,
      ));
    });
  });
}

try {
  await runExpoExport();

  const [bundle, sourceMapText, licenseText] = await Promise.all([
    readFile(bundlePath, "utf8"),
    readFile(sourceMapPath, "utf8"),
    readFile(join(projectDirectory, "third-party/rocket-chat-reactnative/LICENSE"), "utf8"),
  ]);
  const sourceMap = JSON.parse(sourceMapText);
  const sources = Array.isArray(sourceMap.sources) ? sourceMap.sources : [];
  const normalizedSources = sources.map((source) => String(source).replaceAll("\\", "/"));

  const literalMatches = forbiddenLiterals.filter((literal) => bundle.includes(literal));
  const sourceMatches = normalizedSources.filter((source) =>
    forbiddenSourceFragments.some((fragment) => source.includes(fragment)) ||
    (source.includes('/src/interfacePreview/') && !allowedProductionPresentation.some(allowed => source.endsWith('/'+allowed))),
  );
  const missingSources = requiredSourcePaths.filter((required) =>
    !normalizedSources.some((source) => source.endsWith(required)),
  );
  // Inspect the actual exported JS, not inventory text or an unreferenced source file.
  // --minify false preserves a literal; tolerate Babel's supported quote styles.
  const notice = licenseText.replaceAll("\r\n", "\n").trim();
  const noticeLiterals = [
    JSON.stringify(notice),
    `\`${notice}\``,
    `'${notice.replaceAll("\\", "\\\\").replaceAll("'", "\\'").replaceAll("\n", "\\n")}'`,
  ];
  const hasShippedNotice = noticeLiterals.some((literal) => bundle.includes(literal));

  if (literalMatches.length > 0 || sourceMatches.length > 0 || missingSources.length > 0 || !hasShippedNotice) {
    if (literalMatches.length > 0) {
      console.error(`Forbidden preview literals in production bundle: ${literalMatches.join(", ")}`);
    }
    if (sourceMatches.length > 0) {
      console.error("Forbidden preview or upstream SDK/database modules in production source map:");
      for (const source of sourceMatches) console.error(`- ${source}`);
    }
    if (missingSources.length > 0) {
      console.error("Required shared Veil routes absent from production source map:");
      for (const source of missingSources) console.error(`- ${source}`);
    }
    if (!hasShippedNotice) console.error("Full Rocket.Chat MIT notice is absent from the exported production JS.");
    process.exitCode = 1;
  } else {
    console.log(`Android production JS boundary, source-port modules and shipped MIT notice verified across ${normalizedSources.length} sources. This does not verify a native APK or device behavior.`);
  }
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}
