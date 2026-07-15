import { describe, expect, it } from "vitest";

import capability from "../../src-tauri/capabilities/default.json";

describe("desktop application metadata capability", () => {
  it("allows the main window to read the packaged application version", () => {
    expect(capability.windows).toContain("main");
    expect(capability.permissions).toContain("core:app:allow-version");
  });
});
