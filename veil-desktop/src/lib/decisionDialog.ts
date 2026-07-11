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
    this.complete(request.kind === "confirm" ? false : request.kind === "prompt" ? null : undefined);
  },
};

/** Test-only reset so a failed assertion cannot strand later dialog tests. */
export const resetDecisionDialogsForTests = () => {
  activeItem?.resolve(activeItem.request.kind === "confirm" ? false : null);
  activeItem = null;
  while (queue.length > 0) {
    const item = queue.shift();
    item?.resolve(item.request.kind === "confirm" ? false : null);
  }
  setActiveDecisionDialog(null);
};
