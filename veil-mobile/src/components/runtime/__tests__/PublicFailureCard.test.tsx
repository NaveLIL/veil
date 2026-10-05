import React from "react";
import { publicFailureCopy as publicFailurePresentationV1 } from "../../../presentation/copy/publicFailures";
import { describe, expect, it } from "@jest/globals";
import { render } from "@testing-library/react-native";

import {
  PUBLIC_FAILURE_CODES_V1,

} from "../../../contracts/publicFailureCodesV1";
import { PublicFailureCard } from "../PublicFailureCard";

describe("PublicFailureCard v1", () => {
  it("renders reviewed title, description, action and a selectable ASCII code", () => {
    const view = render(<PublicFailureCard code="VEIL-SYNC-001" />);

    expect(view.getByText("Синхронизация Direct не завершилась")).toBeTruthy();
    expect(view.getByText(/Аккаунт аутентифицирован и сохранён/i)).toBeTruthy();
    expect(view.getByText(/Подключитесь снова с тем же аккаунтом/i)).toBeTruthy();
    expect(view.getByText("Что делать")).toBeTruthy();
    expect(view.getByTestId("public-failure-code-v1").props).toMatchObject({
      children: "VEIL-SYNC-001",
      selectable: true,
      accessibilityLabel: "Публичный код ошибки VEIL-SYNC-001",
    });
  });

  it.each(PUBLIC_FAILURE_CODES_V1)("renders every required field for %s", (code) => {
    const presentation = publicFailurePresentationV1(code);
    const view = render(<PublicFailureCard code={code} />);

    expect(view.getByText(presentation.title)).toBeTruthy();
    expect(view.getByText(presentation.description)).toBeTruthy();
    expect(view.getByText(presentation.nextAction)).toBeTruthy();
    expect(view.getByText("Что делать")).toBeTruthy();
    expect(view.getByTestId("public-failure-card-v1").props).toMatchObject({
      accessibilityRole: "alert",
      accessibilityLiveRegion: "assertive",
    });
    expect(view.getByTestId("public-failure-code-v1").props).toMatchObject({
      children: code,
      selectable: true,
      accessibilityLabel: `Публичный код ошибки ${code}`,
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
