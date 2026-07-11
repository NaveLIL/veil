import { expect, test, type Page } from "@playwright/test";

async function openFixture(page: Page, state: "wallpaper" | "members" | "focus" | "lock") {
  await page.goto(`/visual.html?state=${state}`, { waitUntil: "networkidle" });
  await expect(page.getByTestId("app-shell")).toHaveAttribute("data-visual-state", state);
  await expect(page.locator("#root")).toHaveAttribute("data-fixture-ready", "true");
}

async function enterLockPinWithKeyboard(page: Page) {
  const input = page.getByTestId("lock-pin-input");
  const progress = page.getByRole("progressbar", { name: "PIN length" });
  await input.focus();
  await page.keyboard.type("1234");
  await expect(input).toHaveValue("1234");
  await expect(progress).toHaveAttribute("aria-valuenow", "4");
  await expect(progress).toHaveAttribute("aria-valuemax", "12");
  await expect(progress.locator(":scope > div")).toHaveCount(12);

  await page.keyboard.type("56");
  await page.keyboard.press("Backspace");
  await expect(input).toHaveValue("12345");
  await page.keyboard.type("678901");
  await expect(input).toHaveValue("12345678901");
  await expect(progress).toHaveAttribute("aria-valuenow", "11");
}

async function expectLockScreenGeometry(page: Page, expectedKeySize: number) {
  await expectNoDocumentOverflow(page);
  const screen = page.getByTestId("lock-screen");
  const island = page.getByTestId("lock-island");
  const progress = page.getByTestId("lock-pin-progress");
  const numpad = page.getByTestId("lock-numpad");
  const unlock = page.getByRole("button", { name: "Unlock", exact: true });
  const errorStatus = page.locator("#pin-error-status");
  await expect(island).toHaveCSS("opacity", "1");
  await expect(unlock).toBeVisible();

  const [screenBox, islandBox, progressBox, numpadBox, unlockBox, errorBox, keyBox] = await Promise.all([
    screen.boundingBox(),
    island.boundingBox(),
    progress.boundingBox(),
    numpad.boundingBox(),
    unlock.boundingBox(),
    errorStatus.boundingBox(),
    page.getByRole("button", { name: "Digit 1" }).boundingBox(),
  ]);
  for (const box of [screenBox, islandBox, progressBox, numpadBox, unlockBox, errorBox, keyBox]) {
    expect(box).not.toBeNull();
  }
  if (!screenBox || !islandBox || !progressBox || !numpadBox || !unlockBox || !errorBox || !keyBox) return;

  const screenBottom = screenBox.y + screenBox.height;
  const islandBottom = islandBox.y + islandBox.height;
  expect(islandBox.y).toBeGreaterThanOrEqual(screenBox.y + 7);
  expect(islandBottom).toBeLessThanOrEqual(screenBottom - 7);
  expect(progressBox.y).toBeGreaterThanOrEqual(islandBox.y);
  expect(numpadBox.y).toBeGreaterThan(progressBox.y + progressBox.height - 1);
  expect(unlockBox.y).toBeGreaterThan(numpadBox.y + numpadBox.height - 1);
  expect(errorBox.y + errorBox.height).toBeLessThanOrEqual(islandBottom + 1);
  expect(Math.abs(keyBox.width - expectedKeySize)).toBeLessThanOrEqual(1);
  expect(Math.abs(keyBox.height - expectedKeySize)).toBeLessThanOrEqual(1);

  const overflow = await island.evaluate((element) => ({
    horizontal: element.scrollWidth - element.clientWidth,
    vertical: element.scrollHeight - element.clientHeight,
  }));
  expect(overflow.horizontal).toBeLessThanOrEqual(1);
  expect(overflow.vertical).toBeLessThanOrEqual(1);
}

async function expectNoDocumentOverflow(page: Page) {
  const metrics = await page.evaluate(() => ({
    documentClientWidth: document.documentElement.clientWidth,
    documentScrollWidth: document.documentElement.scrollWidth,
    documentClientHeight: document.documentElement.clientHeight,
    documentScrollHeight: document.documentElement.scrollHeight,
    bodyClientWidth: document.body.clientWidth,
    bodyScrollWidth: document.body.scrollWidth,
    bodyClientHeight: document.body.clientHeight,
    bodyScrollHeight: document.body.scrollHeight,
  }));

  expect(metrics.documentScrollWidth - metrics.documentClientWidth).toBeLessThanOrEqual(1);
  expect(metrics.documentScrollHeight - metrics.documentClientHeight).toBeLessThanOrEqual(1);
  expect(metrics.bodyScrollWidth - metrics.bodyClientWidth).toBeLessThanOrEqual(1);
  expect(metrics.bodyScrollHeight - metrics.bodyClientHeight).toBeLessThanOrEqual(1);
}

async function expectComposerGeometry(page: Page) {
  const composer = page.getByTestId("composer");
  const input = page.getByTestId("composer-input");
  const chat = page.getByTestId("chat-island");
  const [composerBox, inputBox, chatBox] = await Promise.all([
    composer.boundingBox(),
    input.boundingBox(),
    chat.boundingBox(),
  ]);

  expect(composerBox).not.toBeNull();
  expect(inputBox).not.toBeNull();
  expect(chatBox).not.toBeNull();
  if (!composerBox || !inputBox || !chatBox) return;

  const composerRight = composerBox.x + composerBox.width;
  const chatRight = chatBox.x + chatBox.width;
  const composerBottom = composerBox.y + composerBox.height;
  const chatBottom = chatBox.y + chatBox.height;
  const composerCenter = composerBox.y + composerBox.height / 2;
  const inputCenter = inputBox.y + inputBox.height / 2;
  const inputBottom = inputBox.y + inputBox.height;

  expect(composerBox.x - chatBox.x).toBeGreaterThanOrEqual(18);
  expect(chatRight - composerRight).toBeGreaterThanOrEqual(18);
  expect(chatBottom - composerBottom).toBeGreaterThanOrEqual(18);
  expect(chatBottom - composerBottom).toBeLessThanOrEqual(22);
  // The active composer is flex-end aligned: a one-line textarea shares the
  // same lower inset as the 32px action buttons, rather than their center.
  expect(composerBottom - inputBottom).toBeGreaterThanOrEqual(11);
  expect(composerBottom - inputBottom).toBeLessThanOrEqual(13);
  expect(Math.abs(composerCenter - inputCenter)).toBeLessThanOrEqual(6);
  expect(inputBox.y).toBeGreaterThanOrEqual(composerBox.y);
  expect(inputBottom).toBeLessThanOrEqual(composerBottom);
  expect(composerBox.height).toBeGreaterThanOrEqual(44);
  expect(composerBox.width).toBeGreaterThan(260);
}

function parseCssColor(value: string) {
  const hex = value.trim().match(/^#([0-9a-f]{6})$/i)?.[1];
  if (hex) return hex.match(/../g)!.map((channel) => Number.parseInt(channel, 16));
  const rgb = value.match(/rgba?\(\s*([\d.]+)[, ]+\s*([\d.]+)[, ]+\s*([\d.]+)/i);
  if (!rgb) throw new Error(`Unsupported CSS color: ${value}`);
  return rgb.slice(1, 4).map(Number);
}

function contrastRatio(first: string, second: string) {
  const luminance = (color: string) => {
    const [red, green, blue] = parseCssColor(color)
      .map((channel) => channel / 255)
      .map((channel) => channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  };
  const a = luminance(first);
  const b = luminance(second);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

test("local wallpaper covers the AppShell without shifting its islands", async ({ page }) => {
  await openFixture(page, "wallpaper");
  await expectNoDocumentOverflow(page);
  await expectComposerGeometry(page);

  const wallpaper = page.getByTestId("wallpaper-layer");
  const wallpaperStyle = await wallpaper.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      backgroundImage: style.backgroundImage,
      backgroundSize: style.backgroundSize,
      backgroundPosition: style.backgroundPosition,
    };
  });
  expect(wallpaperStyle.backgroundImage).toContain("wallpaper.svg");
  expect(wallpaperStyle.backgroundSize).toBe("cover");
  expect(wallpaperStyle.backgroundPosition).toBe("50% 50%");

  const hostBox = await page.getByTestId("wallpaper-host").boundingBox();
  const viewport = page.viewportSize();
  expect(hostBox).not.toBeNull();
  expect(viewport).not.toBeNull();
  if (hostBox && viewport) {
    expect(Math.abs(hostBox.width - viewport.width)).toBeLessThanOrEqual(1);
    expect(Math.abs(hostBox.height - viewport.height)).toBeLessThanOrEqual(1);
  }

  await expect(page).toHaveScreenshot("app-shell-wallpaper.png");
});

test("sending with a wallpaper scrolls only the message viewport", async ({ page }) => {
  await openFixture(page, "wallpaper");
  const composer = page.getByTestId("composer");
  const input = page.getByTestId("composer-input");
  const chat = page.getByTestId("chat-island");
  const before = await Promise.all([composer.boundingBox(), chat.boundingBox()]);

  await input.fill("Viewport regression message");
  await page.getByRole("button", { name: "Send message" }).click();

  await expect(page.getByText("Viewport regression message")).toBeVisible();
  await expect(input).toHaveValue("");
  await expectNoDocumentOverflow(page);
  await expectComposerGeometry(page);

  const after = await Promise.all([composer.boundingBox(), chat.boundingBox()]);
  expect(after).toEqual(before);
  const scrollState = await page.evaluate(() => ({
    windowX: window.scrollX,
    windowY: window.scrollY,
    documentTop: document.documentElement.scrollTop,
    bodyTop: document.body.scrollTop,
  }));
  expect(scrollState).toEqual({ windowX: 0, windowY: 0, documentTop: 0, bodyTop: 0 });
});

test("theme tokens preserve readable small text and accent labels", async ({ page }) => {
  await openFixture(page, "wallpaper");
  for (const theme of [null, "midnight", "ocean", "forest", "oled"] as const) {
    const tokens = await page.evaluate((selectedTheme) => {
      if (selectedTheme) document.documentElement.dataset.veilTheme = selectedTheme;
      else delete document.documentElement.dataset.veilTheme;
      const style = getComputedStyle(document.documentElement);
      const read = (name: string) => style.getPropertyValue(name).trim();
      return {
        faint: read("--veil-text-faint"),
        muted: read("--veil-text-muted"),
        onAccent: read("--veil-on-accent"),
        accent: read("--veil-accent"),
        surfaces: [
          read("--veil-window"),
          read("--veil-island"),
          read("--veil-surface-raised"),
          read("--veil-composer"),
          read("--veil-control"),
        ],
      };
    }, theme);

    for (const surface of tokens.surfaces) {
      expect(contrastRatio(tokens.faint, surface), `${theme ?? "veil"}: faint`).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(tokens.muted, surface), `${theme ?? "veil"}: muted`).toBeGreaterThanOrEqual(4.5);
    }
    expect(contrastRatio(tokens.onAccent, tokens.accent), `${theme ?? "veil"}: on-accent`).toBeGreaterThanOrEqual(4.5);
  }
});

test("members island overlays only below the four-column breakpoint", async ({ page }) => {
  await openFixture(page, "members");
  await expectNoDocumentOverflow(page);
  await expectComposerGeometry(page);

  const wrapper = page.getByRole("complementary", { name: "Conversation members" });
  await expect(wrapper).toHaveAttribute("aria-hidden", "false");
  const [bodyBox, chatBox, membersBox] = await Promise.all([
    page.getByTestId("app-body").boundingBox(),
    page.getByTestId("chat-island").boundingBox(),
    wrapper.boundingBox(),
  ]);
  expect(bodyBox).not.toBeNull();
  expect(chatBox).not.toBeNull();
  expect(membersBox).not.toBeNull();

  const position = await wrapper.evaluate((element) => getComputedStyle(element).position);
  const viewport = page.viewportSize();
  expect(viewport).not.toBeNull();
  if (viewport && bodyBox && chatBox && membersBox) {
    expect(Math.abs(membersBox.width - 240)).toBeLessThanOrEqual(1);
    if (viewport.width <= 1080) {
      expect(position).toBe("absolute");
      expect(Math.abs(membersBox.x + membersBox.width - (bodyBox.x + bodyBox.width))).toBeLessThanOrEqual(1);
      expect(Math.abs(chatBox.x + chatBox.width - (bodyBox.x + bodyBox.width))).toBeLessThanOrEqual(1);
    } else {
      expect(position).toBe("static");
      expect(membersBox.x - (chatBox.x + chatBox.width)).toBeGreaterThanOrEqual(7);
    }
  }

  await expect(page).toHaveScreenshot("app-shell-members.png");
});

test("composer focus ring follows the full composer geometry", async ({ page }) => {
  await openFixture(page, "focus");
  const input = page.getByTestId("composer-input");
  await input.focus();
  await expect(input).toBeFocused();
  await expectNoDocumentOverflow(page);
  await expectComposerGeometry(page);

  const focusStyle = await page.getByTestId("composer").evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      outlineColor: style.outlineColor,
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth,
    };
  });
  expect(focusStyle.outlineStyle).toBe("solid");
  expect(Number.parseFloat(focusStyle.outlineWidth)).toBeGreaterThanOrEqual(2);
  expect(focusStyle.outlineColor).not.toBe("rgba(0, 0, 0, 0)");

  await expect(page).toHaveScreenshot("app-shell-composer-focus.png");
});

test.describe("LockScreen minimum-window geometry", () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(
      testInfo.project.name !== "app-shell-800x600",
      "The two explicit LockScreen viewports run once in the minimum-window project.",
    );
  });

  test("fits the 800x600 native minimum after the titlebar", async ({ page }) => {
    await openFixture(page, "lock");
    await enterLockPinWithKeyboard(page);
    await expectLockScreenGeometry(page, 48);
    await expect(page).toHaveScreenshot("lock-screen-800x600.png");
  });

  test("fits the 125-percent equivalent viewport without internal scrolling", async ({ page }) => {
    await page.setViewportSize({ width: 640, height: 480 });
    await openFixture(page, "lock");
    await enterLockPinWithKeyboard(page);
    await expectLockScreenGeometry(page, 38);
    await expect(page).toHaveScreenshot("lock-screen-125-percent.png");
  });
});
