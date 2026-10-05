import { useEffect, useRef, useState } from "react";
import VeilRuntime, { type NativeContactSearchResult } from "../native/runtime";
import { useChatStore } from "../stores/chat";

// UI correlation only. This counter grants no native identity or selection authority.
let actionSerial = 0;
type Flow = { scope: string; generation: number; actionId: string; phase: "searching" | "selected" | "creating" };
type Status = "idle" | "searching" | "creating" | "not_found" | "error";
interface ContactState { scope: string | null; query: string; result: NativeContactSearchResult | null; status: Status }

function currentScope(): string | null {
  const s = useChatStore.getState();
  return s.runtimeBinding && s.directGeneration !== null
    ? `${s.runtimeBinding.canonicalServerOrigin}\u0000${s.runtimeBinding.userId}\u0000${s.directGeneration}` : null;
}

/** Native contact commands own HTTP, signing, bounds and verified peer selection. */
export function useContactsPresenter(onCreated: (conversationId: string) => void) {
  const binding = useChatStore((s) => s.runtimeBinding);
  const generation = useChatStore((s) => s.directGeneration);
  const scope = binding && generation !== null
    ? `${binding.canonicalServerOrigin}\u0000${binding.userId}\u0000${generation}` : null;
  const [state, setState] = useState<ContactState>({ scope, query: "", result: null, status: "idle" });
  const flow = useRef<Flow | null>(null);
  const mounted = useRef(true);
  const visible = state.scope === scope ? state : { scope, query: "", result: null, status: "idle" as const };
  const isCurrent = (candidate: Flow) => mounted.current && flow.current === candidate && currentScope() === candidate.scope;
  const cancelFlow = () => {
    const previous = flow.current;
    flow.current = null;
    if (previous) void VeilRuntime.cancelContacts(previous.generation, previous.actionId).catch(() => undefined);
  };

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      const previous = flow.current;
      flow.current = null;
      if (previous) void VeilRuntime.cancelContacts(previous.generation, previous.actionId).catch(() => undefined);
    };
  }, []);

  useEffect(() => {
    const previous = flow.current;
    flow.current = null;
    if (previous) void VeilRuntime.cancelContacts(previous.generation, previous.actionId).catch(() => undefined);
    setState({ scope, query: "", result: null, status: "idle" });
  }, [scope]);

  const setQuery = (query: string) => {
    cancelFlow();
    setState({ scope, query, result: null, status: "idle" });
  };

  const search = async () => {
    if (!scope || generation === null || !visible.query.trim()
      || flow.current?.phase === "searching" || flow.current?.phase === "creating") return;
    cancelFlow();
    const candidate: Flow = { scope, generation, actionId: `veil-contact-${++actionSerial}`, phase: "searching" };
    flow.current = candidate;
    const query = visible.query.trim();
    setState({ scope, query: visible.query, result: null, status: "searching" });
    try {
      const result = await VeilRuntime.searchContact(query, generation, candidate.actionId);
      if (!isCurrent(candidate)) return;
      if (result) candidate.phase = "selected";
      else cancelFlow();
      setState({ scope, query: visible.query, result, status: result ? "idle" : "not_found" });
    } catch {
      if (isCurrent(candidate)) {
        cancelFlow();
        setState({ scope, query: visible.query, result: null, status: "error" });
      }
    }
  };

  const create = async () => {
    const candidate = flow.current;
    const result = visible.result;
    if (!candidate || candidate.phase !== "selected" || !result || !isCurrent(candidate)) return;
    candidate.phase = "creating";
    setState((s) => ({ ...s, status: "creating" }));
    try {
      const created = await VeilRuntime.createDirect(result.userId, candidate.generation, candidate.actionId);
      if (!isCurrent(candidate)) return;
      const snapshot = await VeilRuntime.getSnapshot();
      if (!isCurrent(candidate)) return;
      if (snapshot.directGeneration !== candidate.generation
        || snapshot.binding?.canonicalServerOrigin !== binding?.canonicalServerOrigin
        || snapshot.binding?.userId !== binding?.userId
        || !snapshot.directConversations.some((c) => c.conversationId === created.conversationId && c.peerUserId === result.userId)) throw new Error("Unavailable");
      // Hydrate authoritative metadata before selection/navigation; never insert a JS conversation.
      const store = useChatStore.getState();
      store.hydrateRuntimeDirectory(snapshot);
      if (!isCurrent(candidate)) return;
      useChatStore.getState().selectDm(created.conversationId);
      if (useChatStore.getState().selectedDmId !== created.conversationId) throw new Error("Unavailable");
      flow.current = null;
      setState((s) => ({ ...s, status: "idle" }));
      onCreated(created.conversationId);
    } catch {
      if (isCurrent(candidate)) {
        cancelFlow();
        setState((s) => ({ ...s, result: null, status: "error" }));
      }
    }
  };

  return { ...visible, binding, available: scope !== null, setQuery, search, create };
}
