import { createSignal } from "solid-js";

export type DecisionDialogKind = "alert" | "confirm" | "prompt";

export interface DecisionDialogOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  placeholder?: string;
  initialValue?: string;
  requiredValue?: string;
}

export interface ActiveDecisionDialog extends DecisionDialogOptions {
  id: number;
  kind: DecisionDialogKind;
}

type DecisionResult = boolean | string | null | undefined;

interface QueuedDecision {
  request: ActiveDecisionDialog;
  resolve: (value: DecisionResult) => void;
}

let nextId = 1;
let activeItem: QueuedDecision | null = null;
const queue: QueuedDecision[] = [];
const [activeDecisionDialog, setActiveDecisionDialog] =
  createSignal<ActiveDecisionDialog | null>(null);

const cancellationValue = (kind: DecisionDialogKind): DecisionResult => {
  if (kind === "confirm") return false;
  if (kind === "prompt") return null;
  return undefined;
};

const pumpQueue = () => {
  if (activeItem || queue.length === 0) return;
  activeItem = queue.shift() ?? null;
  setActiveDecisionDialog(activeItem?.request ?? null);
};

const enqueue = <T extends DecisionResult>(
  kind: DecisionDialogKind,
  options: DecisionDialogOptions,
): Promise<T> => new Promise<T>((resolve) => {
  queue.push({
    request: { ...options, id: nextId++, kind },
    resolve: (value) => resolve(value as T),
  });
  pumpQueue();
});

export const alertDecision = async (options: DecisionDialogOptions): Promise<void> => {
  await enqueue<undefined>("alert", options);
};

export const confirmDecision = (options: DecisionDialogOptions): Promise<boolean> =>
  enqueue<boolean>("confirm", options);

export const promptDecision = (options: DecisionDialogOptions): Promise<string | null> =>
  enqueue<string | null>("prompt", options);

export const decisionDialog = {
  active: activeDecisionDialog,
  complete(value: DecisionResult) {
    const item = activeItem;
    if (!item) return;
    activeItem = null;
    setActiveDecisionDialog(null);
    item.resolve(value);
    queueMicrotask(pumpQueue);
  },
  cancel() {
    const request = activeItem?.request;
    if (!request) return;
    this.complete(cancellationValue(request.kind));
  },
  cancelAll() {
    // Detach the complete queue before resolving anything. Promise callbacks
    // are then free to enqueue a new dialog without being consumed by this
    // cancellation pass or by a previously scheduled pumpQueue microtask.
    const cancelled = activeItem ? [activeItem, ...queue.splice(0)] : queue.splice(0);
    activeItem = null;
    setActiveDecisionDialog(null);
    for (const item of cancelled) {
      item.resolve(cancellationValue(item.request.kind));
    }
  },
};

/** Test-only reset so a failed assertion cannot strand later dialog tests. */
export const resetDecisionDialogsForTests = () => {
  decisionDialog.cancelAll();
  nextId = 1;
};
