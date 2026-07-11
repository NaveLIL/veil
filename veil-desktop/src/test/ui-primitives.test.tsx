import { render, screen } from "@solidjs/testing-library";
import userEvent from "@testing-library/user-event";
import { createSignal } from "solid-js";
import { describe, expect, it } from "vitest";
import { VeilMark } from "@/components/brand/VeilMark";
import { IslandSelect } from "@/components/ui/IslandSelect";
import { Switch } from "@/components/ui/switch";

describe("shared UI primitives", () => {
  it("keeps decorative and labelled Phase Shift marks semantically distinct", () => {
    const { container } = render(() => (
      <>
        <VeilMark />
        <VeilMark label="Veil" />
      </>
    ));

    expect(screen.getByRole("img", { name: "Veil" })).toBeInTheDocument();
    expect(container.querySelector("svg[aria-hidden='true']")).toBeInTheDocument();
  });

  it("exposes switch state and supports keyboard activation", async () => {
    const Harness = () => {
      const [checked, setChecked] = createSignal(false);
      return <Switch checked={checked()} onChange={setChecked} label="Reduce motion" />;
    };

    render(() => <Harness />);
    const user = userEvent.setup();
    const control = screen.getByRole("switch", { name: "Reduce motion" });
    expect(control).toHaveAttribute("aria-checked", "false");

    await user.tab();
    expect(control).toHaveFocus();
    await user.keyboard("[Space]");
    expect(control).toHaveAttribute("aria-checked", "true");
  });

  it("opens the shared select and commits a keyboard choice", async () => {
    const Harness = () => {
      const [minutes, setMinutes] = createSignal(5);
      return (
        <IslandSelect
          value={minutes()}
          options={[
            { value: 1, label: "1 minute" },
            { value: 5, label: "5 minutes" },
            { value: 15, label: "15 minutes" },
          ]}
          onChange={setMinutes}
          ariaLabel="Lock after inactivity"
        />
      );
    };

    render(() => <Harness />);
    const user = userEvent.setup();
    const select = screen.getByRole("button", { name: /Lock after inactivity/ });
    expect(select).toHaveTextContent("5 minutes");

    await user.click(select);
    await user.keyboard("{ArrowDown}{Enter}");
    expect(select).toHaveTextContent("15 minutes");
  });
});
