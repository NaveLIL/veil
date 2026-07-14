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

type FetchStub = () => Promise<{
  ok: boolean;
  status?: number;
  json: () => Promise<unknown>;
}>;

async function renderReleaseSite(
  files: ReturnType<typeof releaseFile>[],
  fetchStub?: FetchStub,
) {
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
    fetchStub ?? (async () => ({ ok: true, status: 200, json: async () => manifest })),
  );
  await new Promise<void>((resolveRender) => setTimeout(resolveRender, 0));
  return siteDocument;
}

function expectDownloadsHidden(siteDocument: Document) {
  expect(siteDocument.querySelectorAll("#release-grid a")).toHaveLength(0);
  expect(siteDocument.querySelector("#release-checksums")?.hasAttribute("hidden")).toBe(true);
  expect(siteDocument.querySelector("#release-checksums")?.hasAttribute("href")).toBe(false);
  expect(siteDocument.querySelector("#release-source")?.hasAttribute("hidden")).toBe(true);
  expect(siteDocument.querySelector("#release-source")?.hasAttribute("href")).toBe(false);
  expect(siteDocument.querySelector("#release-status")?.getAttribute("aria-live")).toBe("polite");
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

    expectDownloadsHidden(siteDocument);
    expect(siteDocument.querySelector("#release-status")?.textContent).toContain("не прошли проверку");
    expect(siteDocument.querySelector("#package-release-status")?.textContent).not.toContain("доступны Linux и Windows");
  });

  it("keeps the honest no-release fallback for a missing manifest", async () => {
    const siteDocument = await renderReleaseSite([], async () => ({
      ok: false,
      status: 404,
      json: async () => null,
    }));

    expectDownloadsHidden(siteDocument);
    expect(siteDocument.querySelector("#release-status")?.textContent).toContain("Проверенных preview-сборок пока нет");
  });

  it("reports a temporary outage for a non-404 response", async () => {
    const siteDocument = await renderReleaseSite([], async () => ({
      ok: false,
      status: 503,
      json: async () => null,
    }));

    expectDownloadsHidden(siteDocument);
    expect(siteDocument.querySelector("#release-status")?.textContent).toContain("временно недоступен");
  });

  it("reports a temporary outage when the manifest request fails", async () => {
    const siteDocument = await renderReleaseSite([], async () => {
      throw new TypeError("network unavailable");
    });

    expectDownloadsHidden(siteDocument);
    expect(siteDocument.querySelector("#release-status")?.textContent).toContain("временно недоступен");
  });

  it("rejects invalid JSON as untrusted release data", async () => {
    const siteDocument = await renderReleaseSite([], async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError("invalid JSON");
      },
    }));

    expectDownloadsHidden(siteDocument);
    expect(siteDocument.querySelector("#release-status")?.textContent).toContain("не прошли проверку");
  });
});
