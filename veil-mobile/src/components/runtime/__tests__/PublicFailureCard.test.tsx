import React from "react";
import { describe, expect, it } from "@jest/globals";
import { render } from "@testing-library/react-native";

import {
  PUBLIC_FAILURE_CODES_V1,
  publicFailurePresentationV1,
} from "../../../contracts/publicFailureCodesV1";
import { PublicFailureCard } from "../PublicFailureCard";

describe("PublicFailureCard v1", () => {
  it("renders reviewed title, description, action and a selectable ASCII code", () => {
    const view = render(<PublicFailureCard code="VEIL-SYNC-001" />);

    expect(view.getByText("Secure Direct sync did not complete")).toBeTruthy();
    expect(view.getByText(/account authenticated and remains saved/i)).toBeTruthy();
    expect(view.getByText(/Reconnect with this same account/i)).toBeTruthy();
    expect(view.getByText("NEXT ACTION")).toBeTruthy();
    expect(view.getByTestId("public-failure-code-v1").props).toMatchObject({
      children: "VEIL-SYNC-001",
      selectable: true,
      accessibilityLabel: "Public failure code VEIL-SYNC-001",
    });
  });

  it.each(PUBLIC_FAILURE_CODES_V1)("renders every required field for %s", (code) => {
    const presentation = publicFailurePresentationV1(code);
    const view = render(<PublicFailureCard code={code} />);

    expect(view.getByText(presentation.title)).toBeTruthy();
    expect(view.getByText(presentation.description)).toBeTruthy();
    expect(view.getByText(presentation.nextAction)).toBeTruthy();
    expect(view.getByText("NEXT ACTION")).toBeTruthy();
    expect(view.getByTestId("public-failure-card-v1").props).toMatchObject({
      accessibilityRole: "alert",
      accessibilityLiveRegion: "assertive",
    });
    expect(view.getByTestId("public-failure-code-v1").props).toMatchObject({
      children: code,
      selectable: true,
      accessibilityLabel: `Public failure code ${code}`,
    });
  });

  it("can join a larger assertive recovery announcement without a nested alert", () => {
    const view = render(<PublicFailureCard code="VEIL-SETUP-002" announce={false} />);

    expect(view.getByTestId("public-failure-card-v1").props).toMatchObject({
      accessibilityLiveRegion: "none",
    });
    expect(view.getByTestId("public-failure-card-v1").props.accessibilityRole).toBeUndefined();
  });
});
