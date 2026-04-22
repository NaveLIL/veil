import { Component, createSignal, Show } from "solid-js";
import { Plus, ArrowRight, Loader2 } from "lucide-solid";
import { appStore } from "@/stores/app";
import { IslandDialog, dlgStyles as ds } from "@/components/ui/IslandDialog";

interface Props {
  open: boolean;
  onClose: () => void;
}

export const CreateServerDialog: Component<Props> = (props) => {
  const [name, setName] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");

  const reset = () => { setName(""); setError(""); };
  const close = () => { if (loading()) return; reset(); props.onClose(); };

  const handleCreate = async () => {
    const n = name().trim();
    if (!n) return;
    setLoading(true); setError("");
    try {
      const created = await appStore.createServer(n);
      if (created) {
        appStore.selectServer(created.id);
        reset();
        props.onClose();
      } else setError("Failed to create server");
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && name().trim() && !loading()) { e.preventDefault(); handleCreate(); }
  };

  const enabled = () => name().trim().length > 0 && !loading();

  return (
    <IslandDialog
      open={props.open}
      onClose={close}
      title="Create Server"
      icon={<Plus size={15} />}
      accent="#34d399"
      closeDisabled={loading()}
    >
      <div style={ds.fieldGroup}>
        <div>
          <label style={ds.label}>Server name</label>
          <input
            style={ds.input(!!error())}
            placeholder="My Awesome Server"
            value={name()}
            onInput={(e) => { setName(e.currentTarget.value); setError(""); }}
            onKeyDown={onKey}
            maxLength={80}
            autofocus
          />
        </div>

        <Show when={error()}>
          <div style={ds.errorBox}>{error()}</div>
        </Show>

        <button
          style={ds.primaryBtn(enabled(), "#34d399")}
          onClick={handleCreate}
          disabled={!enabled()}
        >
          <Show when={loading()} fallback={<>Create Server <ArrowRight size={14} /></>}>
            <Loader2 size={14} class="animate-spin" /> Creating…
          </Show>
        </button>
      </div>
    </IslandDialog>
  );
};
