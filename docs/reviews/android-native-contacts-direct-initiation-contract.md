# Android native contacts and Direct initiation contract

Status: design and implementation gate, not implemented and not activated.

## Why this contract exists

The Android Direct runtime can safely receive, project, establish a session for,
and send in a Direct conversation already present in the authenticated native
directory. It cannot yet search for an account, display/act on friend requests,
or create a new Direct. Desktop has all of those product flows.

Adding a renderer-only contacts screen would be misleading and would make
JavaScript the authority for account selection, request signing, and a peer's
cryptographic identity. This contract defines the minimum native-first slice
needed before Android may claim that it can start a Direct conversation.

## User-visible flow

For two people on the same Veil Node:

1. A user searches the exact technical username on the currently authenticated
   canonical origin.
2. The application shows the returned account and identity material as an
   unverified first-contact identity; a nearby user can compare the identity
   fingerprint out of band.
3. The user may send a friend request, or begin a Direct from a reviewed
   identity surface when that product policy permits it. Friendship and Direct
   creation are distinct server operations; accepting a request does not
   silently create a conversation.
4. A recipient sees an incoming request, explicitly accepts or rejects it, and
   may remove a friendship later.
5. Creating a Direct returns the canonical conversation ID and the peer's
   identity and signing keys. Native code validates and installs that result;
   the renderer only observes the subsequently authenticated directory.

The flow never uses a recovery phrase, Node Access Pass, raw account ID copied
from another screen, or a long identity key as a search term. There is no
cross-origin/global account directory.

## Required authority boundary

- Rust owns every signed REST/WS mutation, request target, body, replay/freshness
  metadata, and response installation. Kotlin may carry an opaque native
  capability and JS may render only bounded public projections.
- Every contact operation is scoped to one `MobileAuthenticatedEpoch`: canonical
  origin, authenticated user ID, and Direct generation. Lock, background
  invalidation, reconnect, origin change, or generation replacement revokes all
  outstanding contact capabilities and clears their projections.
- A search response is accepted only when its canonical user ID, bounded
  technical username, identity key, and origin parse exactly. It is an
  observation, not proof that the Node showed the same identity to another
  client. The UI must retain that distinction until a key-transparency design
  exists.
- The native create-Direct request may name only the selected canonical peer
  ID. The response must bind the same peer ID and validate the returned
  identity/signing keys before a conversation can become visible or obtain a
  peer-prekey capability.
- Friend events are authenticated transport metadata, not plaintext Direct
  content. They must share the bounded FIFO/lifecycle discipline with Direct
  events. The current Direct replay path intentionally ignores friend events;
  this must be replaced by an explicit multiplexed native event state machine,
  never by a second competing queue or a renderer subscription.
- Native code maps malformed, stale, conflicting, or uncertain results to the
  restrictive runtime state or a reviewed public action. It never renders
  server diagnostic text, guesses a previous result, retries a mutation from
  UI state, or falls back to a weaker transport protocol.

## Transport/versioning requirements

The currently live managed ingress remains WS v2 plus the exact transitional
REST v1 authority policy. The new mobile contacts slice must name the selected
transport contract explicitly and must not silently switch between REST v1 and
the future REST v2 boundary. REST v2 is not usable for this work until its
route, raw-HTTP, client, and gateway activation gates are complete.

Its native request/response grammar must be versioned, bounded, and covered by
Rust, Kotlin, and TypeScript structural tests. JavaScript must not construct
arbitrary signed URLs, headers, or JSON bodies. A future protocol cutover is a
single explicit version selection with no downgrade fallback.

## Required evidence before enabling the UI

1. Host tests for exact-origin selection, stale epoch rejection, bounded
   username/identity parsing, and no private key/Pass/request capability across
   FFI or React Native.
2. Deterministic tests proving the shared event pipeline cannot lose, reorder,
   or apply contact events to a new epoch while Direct history/live replay is
   active.
3. Tests for search-result to create-Direct identity binding, changed-key
   rejection, duplicate request/accept/remove handling, and no automatic Direct
   creation on friendship acceptance.
4. Cross-client desktop-to-Android and Android-to-desktop tests using the same
   canonical origin and public failure/action semantics.
5. The existing signed tester artifact and physical-device gates remain
   separate. This contract authorizes neither a phone mutation nor a release
   claim.

## Non-claims

This is not key transparency, contact discovery across Nodes, a global social
graph, multi-device linking, or a production release. Until implementation and
all evidence above exist, Android exposes only existing authenticated Direct
conversations and must say so plainly.
