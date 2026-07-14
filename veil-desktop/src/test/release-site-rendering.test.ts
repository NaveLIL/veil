import { describe, expect, it } from "vitest";
import siteHtml from "../../../veil-server/cmd/gateway/web/index.html?raw";

const scripts = [...siteHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)];
const releaseScript = scripts[scripts.length - 1]?.[1] ?? "";
const sha256 = "a".repeat(64);

function releaseFile(
  platform: string,
  kind: string,
  filename: string,
  signature?: "authenticode" | "unsigned",
) {
  return { platform, kind, filename, size: 10, sha256, ...(signature ? { signature } : {}) };
}

async function renderReleaseSite(files: ReturnType<typeof releaseFile>[]) {
  const siteDocument = new DOMParser().parseFromString(siteHtml, "text/html");
  const manifest = {
    version: "0.1.1",
    published_at: "2026-07-15T00:00:00Z",
    commit: "b".repeat(40),
    license: "AGPL-3.0-or-later",
    source: {
      filename: "Veil-0.1.1-source.tar.gz",
      url: "/downloads/Veil-0.1.1-source.tar.gz",
      size: 10,
      sha256,
    },
    files,
  };
  const runReleaseScript = new Function("document", "navigator", "fetch", releaseScript);
  runReleaseScript(
    siteDocument,
    { platform: "Win32", userAgent: "Windows" },
    async () => ({ ok: true, json: async () => manifest }),
  );
  await new Promise<void>((resolveRender) => setTimeout(resolveRender, 0));
  return siteDocument;
}

describe("release download site", () => {
  it("renders every installer and clearly labels an unsigned Windows Preview", async () => {
    expect(releaseScript).toBeTruthy();
    const siteDocument = await renderReleaseSite([
      releaseFile("linux", "deb", "Veil-linux-amd64.deb"),
      releaseFile("linux", "appimage", "Veil-linux-x86_64.AppImage"),
      releaseFile("windows", "exe", "Veil-windows-x64-setup.exe", "unsigned"),
      releaseFile("windows", "msi", "Veil-windows-x64.msi", "unsigned"),
    ]);

    expect(siteDocument.querySelectorAll("#release-grid a")).toHaveLength(4);
    expect(siteDocument.querySelector("#release-grid")?.textContent).toContain("БЕЗ ПОДПИСИ");
    expect(siteDocument.querySelector("#release-grid")?.textContent).not.toContain("БЕЗ ПОДПИСИ · рекомендуется");
    expect(siteDocument.querySelector("#package-release-status")?.textContent).toContain("SmartScreen");
    expect(siteDocument.querySelector("#release-checksums")?.hasAttribute("hidden")).toBe(false);
    expect(siteDocument.querySelector("#release-source")?.hasAttribute("hidden")).toBe(false);
  });

  it("rejects a partial manifest instead of claiming unavailable Windows packages", async () => {
    const siteDocument = await renderReleaseSite([
      releaseFile("linux", "deb", "Veil-linux-amd64.deb"),
      releaseFile("linux", "appimage", "Veil-linux-x86_64.AppImage"),
    ]);

    expect(siteDocument.querySelectorAll("#release-grid a")).toHaveLength(0);
    expect(siteDocument.querySelector("#package-release-status")?.textContent).not.toContain("доступны Linux и Windows");
    expect(siteDocument.querySelector("#release-checksums")?.hasAttribute("hidden")).toBe(true);
  });
});
