import { createSignal, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

type Screen = "onboarding" | "chat";

function App() {
  const [screen, setScreen] = createSignal<Screen>("onboarding");
  const [mnemonic, setMnemonic] = createSignal("");
  const [identity, setIdentity] = createSignal<string | null>(null);

  const generateMnemonic = async () => {
    const m = await invoke<string>("generate_mnemonic");
    setMnemonic(m);
  };

  const initIdentity = async () => {
    const phrase = mnemonic();
    if (!phrase) return;
    try {
      const key = await invoke<string>("init_identity", { mnemonic: phrase });
      setIdentity(key);
      setScreen("chat");
    } finally {
      setMnemonic("");
    }
  };

  return (
    <div style={{ height: "100%", display: "flex", "flex-direction": "column" }}>
      <Show when={screen() === "onboarding"}>
        <div style={{
          display: "flex",
          "flex-direction": "column",
          "align-items": "center",
          "justify-content": "center",
          height: "100%",
          gap: "20px",
          padding: "40px",
        }}>
          <h1 style={{ "font-size": "2em", "font-weight": "300", "letter-spacing": "0.3em" }}>
            VEIL
          </h1>
          <p style={{ color: "#888", "max-width": "400px", "text-align": "center" }}>
            Native end-to-end encrypted messenger. Your keys never leave this device.
          </p>

          <Show when={!mnemonic()} fallback={
            <div style={{ display: "flex", "flex-direction": "column", gap: "16px", width: "100%", "max-width": "500px" }}>
              <div style={{
                background: "#16161e",
                padding: "20px",
                "border-radius": "12px",
                "font-family": "monospace",
                "font-size": "1.1em",
                "line-height": "1.8",
                "text-align": "center",
                "word-spacing": "4px",
                border: "1px solid #2a2a35",
              }}>
                {mnemonic()}
              </div>
              <p style={{ color: "#f59e0b", "font-size": "0.85em", "text-align": "center" }}>
                Write down these words. They are your only way to recover this account.
              </p>
              <button
                onClick={initIdentity}
                style={{
                  padding: "12px 24px",
                  background: "#6366f1",
                  color: "white",
                  border: "none",
                  "border-radius": "8px",
                  "font-size": "1em",
                  cursor: "pointer",
                }}
              >
                I've saved my recovery phrase
              </button>
            </div>
          }>
            <button
              onClick={generateMnemonic}
              style={{
                padding: "12px 24px",
                background: "#6366f1",
                color: "white",
                border: "none",
                "border-radius": "8px",
                "font-size": "1em",
                cursor: "pointer",
              }}
            >
              Create New Identity
            </button>
          </Show>
        </div>
      </Show>

      <Show when={screen() === "chat"}>
        <div style={{ display: "flex", height: "100%" }}>
          {/* Sidebar */}
          <div style={{
            width: "280px",
            background: "#0e0e16",
            "border-right": "1px solid #1a1a25",
            display: "flex",
            "flex-direction": "column",
          }}>
            <div style={{ padding: "16px", "border-bottom": "1px solid #1a1a25" }}>
              <span style={{ "font-size": "0.75em", color: "#6366f1", "letter-spacing": "0.2em" }}>VEIL</span>
            </div>
            <div style={{ flex: 1, padding: "8px", color: "#666" }}>
              No conversations yet
            </div>
            <div style={{ padding: "12px", "border-top": "1px solid #1a1a25", "font-size": "0.8em", color: "#555" }}>
              {identity()?.slice(0, 16)}...
            </div>
          </div>

          {/* Main area */}
          <div style={{
            flex: 1,
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
            color: "#444",
          }}>
            Select a conversation to start messaging
          </div>
        </div>
      </Show>
    </div>
  );
}

export default App;
