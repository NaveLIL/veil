import { afterEach, describe, expect, it } from "vitest";
import {
  confirmDecision,
  decisionDialog,
  promptDecision,
  resetDecisionDialogsForTests,
} from "@/lib/decisionDialog";

describe("decision dialog queue", () => {
  afterEach(() => resetDecisionDialogsForTests());

  it("serializes decisions without overwriting an active security prompt", async () => {
    const first = confirmDecision({ title: "First", message: "one" });
    const second = promptDecision({ title: "Second", message: "two" });

    expect(decisionDialog.active()?.title).toBe("First");
    decisionDialog.complete(true);
    await expect(first).resolves.toBe(true);
    await new Promise<void>((resolve) => queueMicrotask(resolve));

    expect(decisionDialog.active()?.title).toBe("Second");
    decisionDialog.complete("verified");
    await expect(second).resolves.toBe("verified");
  });

  it("returns an explicit cancellation value for every interactive kind", async () => {
    const confirmation = confirmDecision({ title: "Confirm", message: "question" });
    decisionDialog.cancel();
    await expect(confirmation).resolves.toBe(false);

    await new Promise<void>((resolve) => queueMicrotask(resolve));
    const prompt = promptDecision({ title: "Prompt", message: "question" });
    decisionDialog.cancel();
    await expect(prompt).resolves.toBeNull();
  });
});
