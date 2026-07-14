#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRepositoryRoot = resolve(scriptDirectory, "..");
const LICENSE_FILE_PATTERN = /^(?:licen[cs]e|copying|copyright|notice)(?:[._-].*)?$/i;
const MAX_NOTICE_FILE_BYTES = 2 * 1024 * 1024;
const APPROVED_NPM_LICENSES = new Set([
  "0BSD",
  "Apache-2.0",
  "Apache-2.0 OR MIT",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "MIT OR Apache-2.0",
  "MPL-2.0",
]);

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error(
    "Usage: node scripts/generate-third-party-notices.mjs " +
      "--component <desktop|gateway> --output <path> [--repo-root <path>]",
  );
  process.exit(2);
}

function parseArguments(argv) {
  const options = { repoRoot: defaultRepositoryRoot };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    const value = argv[index + 1];
    if (name === "--component" && value) {
      options.component = value;
      index += 1;
    } else if (name === "--output" && value) {
      options.output = value;
      index += 1;
    } else if (name === "--repo-root" && value) {
      options.repoRoot = resolve(value);
      index += 1;
    } else {
      usage(`Unknown or incomplete argument: ${name}`);
    }
  }

  if (!new Set(["desktop", "gateway"]).has(options.component)) {
    usage("--component must be desktop or gateway");
  }
  if (!options.output) {
    usage("--output is required");
  }
  options.output = resolve(options.output);
  return options;
}

function run(command, args, cwd) {
  const isWindowsPnpm = process.platform === "win32" && command === "pnpm";
  const executable = isWindowsPnpm ? process.env.ComSpec || "cmd.exe" : command;
  const executableArguments = isWindowsPnpm ? ["/d", "/s", "/c", "pnpm.cmd", ...args] : args;
  try {
    return execFileSync(executable, executableArguments, {
      cwd,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    if (error.stderr) {
      process.stderr.write(error.stderr);
    }
    throw error;
  }
}

function normalizeText(value) {
  return value.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").trimEnd() + "\n";
}

function readNoticeFile(path) {
  const size = statSync(path).size;
  if (size === 0 || size > MAX_NOTICE_FILE_BYTES) {
    throw new Error(`Unexpected upstream notice size (${size} bytes): ${path}`);
  }
  return normalizeText(readFileSync(path, "utf8"));
}

function findNoticeFiles(directory, explicitPaths = []) {
  const candidates = new Map();
  for (const explicitPath of explicitPaths) {
    if (!explicitPath) continue;
    const path = isAbsolute(explicitPath) ? explicitPath : resolve(directory, explicitPath);
    if (existsSync(path) && statSync(path).isFile()) {
      candidates.set(realpathSync(path), path);
    }
  }

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isFile() && LICENSE_FILE_PATTERN.test(entry.name)) {
      const path = join(directory, entry.name);
      candidates.set(realpathSync(path), path);
    }
  }

  return [...candidates.values()]
    .sort((left, right) => left.localeCompare(right, "en"))
    .map((path) => ({ name: relative(directory, path).replaceAll("\\", "/"), text: readNoticeFile(path) }));
}

function packageRepository(packageJson) {
  if (typeof packageJson.repository === "string") return packageJson.repository;
  if (packageJson.repository && typeof packageJson.repository.url === "string") {
    return packageJson.repository.url;
  }
  return packageJson.homepage || "(not declared by upstream package metadata)";
}

function normalizedRepository(value) {
  return String(value)
    .toLowerCase()
    .replace(/^git\+/, "")
    .replace(/\.git(?:#.*)?$/, "")
    .replace(/\/$/, "");
}

function collectNpmComponents(repositoryRoot) {
  const desktopDirectory = join(repositoryRoot, "veil-desktop");
  const groups = JSON.parse(run("pnpm", ["licenses", "list", "--prod", "--json"], desktopDirectory));
  const components = new Map();

  for (const entries of Object.values(groups)) {
    for (const entry of entries) {
      for (const packageDirectory of entry.paths || []) {
        const packageJsonPath = join(packageDirectory, "package.json");
        if (!existsSync(packageJsonPath)) {
          throw new Error(`pnpm reported a package without package.json: ${packageDirectory}`);
        }
        const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
        const name = packageJson.name || entry.name;
        const version = packageJson.version;
        const key = `npm:${name}@${version}`;
        if (!name || !version) {
          throw new Error(`Incomplete npm package metadata: ${packageJsonPath}`);
        }
        if (components.has(key)) continue;

        const declaredLicense = packageJson.license || entry.license;
        if (!APPROVED_NPM_LICENSES.has(declaredLicense)) {
          throw new Error(`Unreviewed npm license expression for ${key}: ${declaredLicense || "missing"}`);
        }
        const files = findNoticeFiles(packageDirectory, [packageJson.licenseFile]);
        components.set(key, {
          ecosystem: "npm",
          name,
          version,
          license: declaredLicense,
          source: packageRepository(packageJson),
          files,
        });
      }
    }
  }

  // npm commonly publishes platform-specific binary subpackages without a
  // duplicate LICENSE file. Reuse a license only from the exact same upstream
  // repository, version, and declared license (for example esbuild/esbuild's
  // @esbuild/* package). This copies upstream material; it does not synthesize
  // copyright data or infer a license from package names.
  for (const [key, component] of components) {
    if (component.files.length > 0) continue;
    const source = normalizedRepository(component.source);
    if (source.startsWith("(")) {
      throw new Error(`No upstream LICENSE/NOTICE file or repository found for ${key}`);
    }
    const candidates = [...components.values()].filter(
      (candidate) =>
        candidate.files.length > 0 &&
        candidate.version === component.version &&
        candidate.license === component.license &&
        normalizedRepository(candidate.source) === source,
    );
    if (candidates.length === 0) {
      throw new Error(`No upstream LICENSE/NOTICE file found for ${key}`);
    }
    candidates.sort((left, right) => left.name.localeCompare(right.name, "en"));
    component.files = candidates[0].files.map((file) => ({
      name: `${candidates[0].name}/${file.name}`,
      text: file.text,
    }));
  }

  return [...components.values()];
}

function collectCargoComponents(repositoryRoot) {
  const manifestPath = join(repositoryRoot, "veil-desktop", "src-tauri", "Cargo.toml");
  const reportPath = join(tmpdir(), `veil-cargo-about-${process.pid}.json`);
  let report;
  try {
    run(
      "cargo",
      [
        "about",
        "generate",
        "--locked",
        "--fail",
        "--format",
        "json",
        "--manifest-path",
        manifestPath,
        "--output-file",
        reportPath,
      ],
      repositoryRoot,
    );
    report = JSON.parse(readFileSync(reportPath, "utf8"));
  } finally {
    if (existsSync(reportPath)) unlinkSync(reportPath);
  }

  const components = new Map();
  for (const entry of report.crates || []) {
    const item = entry.package;
    if (!item?.source) continue;
    components.set(item.id, {
      ecosystem: "Cargo",
      name: item.name,
      version: item.version,
      license: entry.license || item.license || "(not declared)",
      source: item.repository || item.homepage || item.source,
      files: [],
    });
  }

  for (const license of report.licenses || []) {
    if (!license.text?.trim()) {
      throw new Error(`cargo-about produced an empty license text for ${license.id}`);
    }
    for (const use of license.used_by || []) {
      const component = components.get(use.crate?.id);
      if (!component) continue;
      component.files.push({
        name: license.source_path ? basename(license.source_path) : `SPDX-${license.id}.txt`,
        text: normalizeText(license.text),
      });
    }
  }

  for (const component of components.values()) {
    if (component.files.length === 0) {
      throw new Error(
        `cargo-about did not resolve license material for Cargo:${component.name}@${component.version}`,
      );
    }
  }
  return [...components.values()];
}

function parseJsonStream(value) {
  const results = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
    } else if (character === "{") {
      if (depth === 0) start = index;
      depth += 1;
    } else if (character === "}") {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        results.push(JSON.parse(value.slice(start, index + 1)));
        start = -1;
      }
      if (depth < 0) throw new Error("Invalid JSON object stream");
    }
  }
  if (depth !== 0 || inString) throw new Error("Truncated JSON object stream");
  return results;
}

function collectGoComponents(repositoryRoot) {
  const serverDirectory = join(repositoryRoot, "veil-server");
  const packages = parseJsonStream(
    run("go", ["list", "-mod=readonly", "-deps", "-json", "./cmd/gateway"], serverDirectory),
  );
  const components = new Map();

  for (const item of packages) {
    if (!item.Module || item.Module.Main) continue;
    const effectiveModule = item.Module.Replace || item.Module;
    if (!effectiveModule.Dir) {
      throw new Error(`Go module has no resolved directory: ${item.Module.Path}`);
    }
    const version = item.Module.Version || effectiveModule.Version || "(local replacement)";
    const key = `Go:${item.Module.Path}@${version}`;
    if (components.has(key)) continue;
    const files = findNoticeFiles(effectiveModule.Dir);
    if (files.length === 0) {
      throw new Error(`No upstream LICENSE/NOTICE file found for ${key}`);
    }
    components.set(key, {
      ecosystem: "Go",
      name: item.Module.Path,
      version,
      license: "See included upstream license file(s)",
      source: effectiveModule.Path,
      files,
    });
  }

  const goos = run("go", ["env", "GOOS"], serverDirectory).trim();
  const policyPath = join(repositoryRoot, "third_party", "go-modules.allow");
  if (!existsSync(policyPath)) {
    throw new Error(`Go module notice policy is missing: ${policyPath}`);
  }
  const approvedModules = new Set();
  for (const [index, rawLine] of readFileSync(policyPath, "utf8").split(/\r?\n/).entries()) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(/\s+/);
    if (fields.length !== 3 || !new Set(["all", "linux", "windows", "darwin"]).has(fields[0])) {
      throw new Error(`Invalid ${policyPath}:${index + 1}; expected <goos|all> <module> <version>`);
    }
    if (fields[0] !== "all" && fields[0] !== goos) continue;
    approvedModules.add(`${fields[1]} ${fields[2]}`);
  }
  const linkedModules = new Set(
    [...components.values()].map((component) => `${component.name} ${component.version}`),
  );
  const unexpectedModules = [...linkedModules].filter((item) => !approvedModules.has(item));
  const staleApprovals = [...approvedModules].filter((item) => !linkedModules.has(item));
  if (unexpectedModules.length > 0 || staleApprovals.length > 0) {
    throw new Error(
      [
        `Go module notice policy does not match the ${goos} gateway dependency graph.`,
        unexpectedModules.length > 0 ? `Unreviewed: ${unexpectedModules.join(", ")}` : "",
        staleApprovals.length > 0 ? `Not linked: ${staleApprovals.join(", ")}` : "",
      ]
        .filter(Boolean)
        .join(" "),
    );
  }

  const goRoot = run("go", ["env", "GOROOT"], serverDirectory).trim();
  const goVersion = run("go", ["env", "GOVERSION"], serverDirectory).trim();
  const standardLibraryFiles = findNoticeFiles(goRoot, [join(goRoot, "PATENTS")]);
  if (standardLibraryFiles.length === 0) {
    throw new Error(`Go toolchain at ${goRoot} has no LICENSE/PATENTS files`);
  }
  components.set(`Go standard library and runtime@${goVersion}`, {
    ecosystem: "Go",
    name: "Go standard library and runtime",
    version: goVersion,
    license: "See included upstream license and patent files",
    source: "https://go.dev/",
    files: standardLibraryFiles,
  });

  return [...components.values()];
}

function render(componentName, components) {
  const sorted = [...components].sort((left, right) =>
    `${left.ecosystem}:${left.name}@${left.version}`.localeCompare(
      `${right.ecosystem}:${right.name}@${right.version}`,
      "en",
    ),
  );
  const materialByHash = new Map();

  for (const component of sorted) {
    component.materials = component.files.map((file) => {
      const hash = createHash("sha256").update(file.text).digest("hex");
      if (!materialByHash.has(hash)) {
        materialByHash.set(hash, { hash, text: file.text, uses: [] });
      }
      materialByHash.get(hash).uses.push({ component, filename: file.name });
      return { filename: file.name, hash };
    });
  }

  const lines = [
    "VEIL THIRD-PARTY SOFTWARE NOTICES",
    "=================================",
    "",
    `Artifact component: ${componentName}`,
    "",
    "This file is generated from locked dependency metadata and license/notice",
    "material resolved from upstream package files and declared SPDX terms. Do not",
    "edit it manually. Veil itself is",
    "licensed separately under AGPL-3.0-or-later; see LICENSE and NOTICE.",
    "",
    `Inventory entries: ${sorted.length}`,
    `Distinct upstream notice texts: ${materialByHash.size}`,
    "",
    "COMPONENT INVENTORY",
    "===================",
    "",
  ];

  for (const component of sorted) {
    lines.push(`${component.ecosystem}: ${component.name} ${component.version}`);
    lines.push(`Declared license: ${component.license}`);
    lines.push(`Source: ${component.source}`);
    lines.push(
      `Included files: ${component.materials
        .map((item) => `${item.filename} (sha256:${item.hash})`)
        .join(", ")}`,
    );
    lines.push("");
  }

  lines.push("UPSTREAM LICENSE AND NOTICE MATERIALS", "=====================================", "");
  for (const material of [...materialByHash.values()].sort((left, right) =>
    left.hash.localeCompare(right.hash, "en"),
  )) {
    const uses = material.uses
      .map((item) => `${item.component.ecosystem}:${item.component.name}@${item.component.version} [${item.filename}]`)
      .sort((left, right) => left.localeCompare(right, "en"));
    lines.push("-".repeat(80));
    lines.push(`SHA-256: ${material.hash}`);
    lines.push("Used by:");
    for (const use of uses) lines.push(`  - ${use}`);
    lines.push("-".repeat(80), "", material.text.trimEnd(), "");
  }

  return lines.join("\n").trimEnd() + "\n";
}

const options = parseArguments(process.argv.slice(2));
let components;
if (options.component === "desktop") {
  components = [
    ...collectCargoComponents(options.repoRoot),
    ...collectNpmComponents(options.repoRoot),
  ];
} else {
  components = collectGoComponents(options.repoRoot);
}

if (components.length === 0) {
  throw new Error(`No third-party components found for ${options.component}`);
}
writeFileSync(options.output, render(options.component, components), "utf8");
console.log(`Generated ${options.output} with ${components.length} component entries.`);
