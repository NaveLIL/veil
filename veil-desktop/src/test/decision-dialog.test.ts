import { afterEach, describe, expect, it } from "vitest";
import {
  alertDecision,
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

  it("cancels the active dialog and every queued dialog with kind-safe values", async () => {
    const confirmation = confirmDecision({ title: "Confirm", message: "one" });
    const prompt = promptDecision({ title: "Prompt", message: "two" });
    const alert = alertDecision({ title: "Alert", message: "three" });

    expect(decisionDialog.active()?.title).toBe("Confirm");
    decisionDialog.cancelAll();

    expect(decisionDialog.active()).toBeNull();
    await expect(confirmation).resolves.toBe(false);
    await expect(prompt).resolves.toBeNull();
    await expect(alert).resolves.toBeUndefined();
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(decisionDialog.active()).toBeNull();
  });

  it("does not drain a replacement enqueued by a cancellation callback", async () => {
    const active = confirmDecision({ title: "Old active", message: "one" });
    const queued = promptDecision({ title: "Old queued", message: "two" });
    let replacement!: Promise<boolean>;
    const enqueueReplacement = active.then((accepted) => {
      expect(accepted).toBe(false);
      replacement = confirmDecision({ title: "Replacement", message: "three" });
    });

    decisionDialog.cancelAll();
    await enqueueReplacement;

    expect(decisionDialog.active()?.title).toBe("Replacement");
    decisionDialog.complete(true);
    await expect(replacement).resolves.toBe(true);
    await expect(queued).resolves.toBeNull();
  });
});
