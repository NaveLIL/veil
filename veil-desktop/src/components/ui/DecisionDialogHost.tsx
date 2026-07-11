import { Component, Show, createEffect, createMemo, createSignal } from "solid-js";
import { AlertTriangle, HelpCircle, Info } from "lucide-solid";
import { decisionDialog } from "@/lib/decisionDialog";
import { IslandDialog, dlgStyles } from "@/components/ui/IslandDialog";

export const DecisionDialogHost: Component = () => {
  const [value, setValue] = createSignal("");
  let inputRef: HTMLInputElement | undefined;
  const active = decisionDialog.active;

  createEffect(() => {
    const request = active();
    setValue(request?.initialValue ?? "");
    if (request?.kind === "prompt") {
      requestAnimationFrame(() => {
        inputRef?.focus();
        inputRef?.select();
      });
    }
  });

  const valid = createMemo(() => {
    const request = active();
    if (!request || request.kind !== "prompt" || request.requiredValue === undefined) return true;
    return value() === request.requiredValue;
  });

  const submit = () => {
    const request = active();
    if (!request) return;
    if (request.kind === "prompt") {
      if (!valid()) return;
      decisionDialog.complete(value());
      return;
    }
    decisionDialog.complete(request.kind === "confirm" ? true : undefined);
  };

  const icon = () => {
    const request = active();
    if (request?.danger) return <AlertTriangle size={16} aria-hidden="true" />;
    if (request?.kind === "alert") return <Info size={16} aria-hidden="true" />;
    return <HelpCircle size={16} aria-hidden="true" />;
  };

  return (
    <Show when={active()}>
      {(request) => (
        <IslandDialog
          open
          onClose={() => decisionDialog.cancel()}
          title={request().title}
          icon={icon()}
          accent={request().danger ? "var(--veil-danger)" : "var(--veil-accent)"}
          width={460}
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              submit();
            }}
          >
            <p
              style={{
                margin: "0",
                color: "var(--veil-text-muted)",
                "font-size": "13px",
                "line-height": "1.55",
                "white-space": "pre-line",
              }}
            >
              {request().message}
            </p>

            <Show when={request().kind === "prompt"}>
              <label style={{ display: "block", "margin-top": "14px" }}>
                <span style={dlgStyles.label}>
                  {request().requiredValue === undefined ? "Response" : `Type ${request().requiredValue} to confirm`}
                </span>
                <input
                  ref={inputRef}
                  value={value()}
                  placeholder={request().placeholder}
                  autocomplete="off"
                  spellcheck={false}
                  style={dlgStyles.input(!valid() && value().length > 0)}
                  onInput={(event) => setValue(event.currentTarget.value)}
                />
              </label>
            </Show>

            <div
              style={{
                display: "flex",
                "justify-content": "flex-end",
                gap: "9px",
                "margin-top": "18px",
              }}
            >
              <Show when={request().kind !== "alert"}>
                <button
                  type="button"
                  style={{ ...dlgStyles.secondaryBtn(true), width: "auto", padding: "0 16px" }}
                  onClick={() => decisionDialog.cancel()}
                >
                  {request().cancelLabel ?? "Cancel"}
                </button>
              </Show>
              <button
                type="submit"
                disabled={!valid()}
                style={{
                  ...dlgStyles.primaryBtn(valid(), request().danger ? "var(--veil-danger)" : "var(--veil-accent)"),
                  width: "auto",
                  padding: "0 16px",
                }}
              >
                {request().confirmLabel ?? (request().kind === "alert" ? "OK" : "Continue")}
              </button>
            </div>
          </form>
        </IslandDialog>
      )}
    </Show>
  );
};
