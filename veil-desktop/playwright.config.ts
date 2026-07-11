import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

const localChrome = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const executablePath = !process.env.CI && process.platform === "win32" && existsSync(localChrome)
  ? localChrome
  : undefined;

export default defineConfig({
  testDir: "./visual-tests",
  outputDir: "./test-results/playwright",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: {
    timeout: 5_000,
    toHaveScreenshot: {
      animations: "disabled",
      caret: "hide",
      scale: "css",
      threshold: 0.3,
      maxDiffPixelRatio: 0.025,
    },
  },
  reporter: process.env.CI
    ? [["github"], ["html", { open: "never", outputFolder: "playwright-report" }]]
    : [["list"]],
  snapshotPathTemplate: "{testDir}/__screenshots__/{projectName}/{arg}{ext}",
  use: {
    baseURL: "http://127.0.0.1:1421",
    headless: true,
    colorScheme: "dark",
    locale: "en-US",
    timezoneId: "UTC",
    deviceScaleFactor: 1,
    reducedMotion: "reduce",
    launchOptions: executablePath ? { executablePath } : undefined,
  },
  projects: [
    { name: "app-shell-800x600", use: { viewport: { width: 800, height: 600 } } },
    { name: "app-shell-1200x800", use: { viewport: { width: 1200, height: 800 } } },
    { name: "app-shell-1440x900", use: { viewport: { width: 1440, height: 900 } } },
  ],
  webServer: {
    command: "pnpm exec vite --host 127.0.0.1 --port 1421 --strictPort",
    url: "http://127.0.0.1:1421/visual.html",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
