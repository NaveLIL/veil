import { expect, test, type Page } from "@playwright/test";

async function openFixture(page: Page, state: "wallpaper" | "members" | "focus") {
  await page.goto(`/visual.html?state=${state}`, { waitUntil: "networkidle" });
  await expect(page.getByTestId("app-shell")).toHaveAttribute("data-visual-state", state);
  await expect(page.locator("#root")).toHaveAttribute("data-fixture-ready", "true");
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
