import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

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

  const [bundle, sourceMapText] = await Promise.all([
    readFile(bundlePath, "utf8"),
    readFile(sourceMapPath, "utf8"),
  ]);
  const sourceMap = JSON.parse(sourceMapText);
  const sources = Array.isArray(sourceMap.sources) ? sourceMap.sources : [];
  const normalizedSources = sources.map((source) => String(source).replaceAll("\\", "/"));

  const literalMatches = forbiddenLiterals.filter((literal) => bundle.includes(literal));
  const sourceMatches = normalizedSources.filter((source) =>
    forbiddenSourceFragments.some((fragment) => source.includes(fragment)),
  );

  if (literalMatches.length > 0 || sourceMatches.length > 0) {
    if (literalMatches.length > 0) {
      console.error(`Forbidden preview literals in production bundle: ${literalMatches.join(", ")}`);
    }
    if (sourceMatches.length > 0) {
      console.error("Forbidden preview modules in production source map:");
      for (const source of sourceMatches) console.error(`- ${source}`);
    }
    process.exitCode = 1;
  } else {
    console.log(`Android production bundle boundary verified across ${normalizedSources.length} sources.`);
  }
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}
