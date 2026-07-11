import { render } from "@solidjs/testing-library";
import axe from "axe-core";
import { createSignal } from "solid-js";
import { describe, expect, it } from "vitest";
import { VeilMark } from "@/components/brand/VeilMark";
import { Switch } from "@/components/ui/switch";

describe("desktop accessibility smoke", () => {
  it("has no structural axe violations in the shared settings controls", async () => {
    const Fixture = () => {
      const [enabled, setEnabled] = createSignal(false);
      return (
        <main aria-labelledby="appearance-title">
          <h1 id="appearance-title">Appearance</h1>
          <VeilMark label="Veil" />
          <Switch
            checked={enabled()}
            onChange={setEnabled}
            label="Reduce motion"
            description="Minimizes decorative movement."
          />
          <div id="island-portal" />
        </main>
      );
    };

    const { container } = render(() => <Fixture />);
    const result = await axe.run(container, {
      rules: {
        // jsdom does not perform layout or resolve CSS custom properties.
        "color-contrast": { enabled: false },
      },
    });

    expect(result.violations).toEqual([]);
  });
});
