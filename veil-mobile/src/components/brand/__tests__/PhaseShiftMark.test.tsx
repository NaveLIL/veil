import React from "react";
import { describe, expect, it } from "@jest/globals";
import { render } from "@testing-library/react-native";
import { Path, Rect } from "react-native-svg";

import { PhaseShiftMark } from "../PhaseShiftMark";

const MASTER_PATH =
  "M4 4H8V11.8L4 13ZM4 16L8 14.8V20H4ZM10 2H14V10.5L10 11.7ZM10 14.7L14 13.5V22H10ZM16 5H20V8.2L16 9.4ZM16 12.4L20 11.2V19H16Z";

describe("PhaseShiftMark", () => {
  it("keeps the canonical mobile mark synchronized with the master asset", () => {
    const view = render(
      <PhaseShiftMark size={56} label="Veil Phase Shift mark" testID="phase-shift-mark" />,
    );

    const rendered = JSON.stringify(view.toJSON());
    const path = view.UNSAFE_getByType(Path);
    const tile = view.UNSAFE_getByType(Rect);
    expect(view.getByTestId("phase-shift-mark")).toBeTruthy();
    expect(path.props.d).toBe(MASTER_PATH);
    expect(path.props.fill).toBe("#a78bfa");
    expect(tile.props.fill).toBe("#0d0e14");
    expect(tile.props.stroke).toBe("#2e2e50");
    expect(rendered).not.toContain('"children":["V"]');
  });

  it("is decorative unless the caller supplies a label", () => {
    const view = render(<PhaseShiftMark testID="decorative-phase-shift-mark" />);

    expect(
      view.getByTestId("decorative-phase-shift-mark", { includeHiddenElements: true }).props
        .accessible,
    ).toBe(false);
  });
});
