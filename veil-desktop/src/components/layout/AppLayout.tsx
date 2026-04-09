import { Component, JSX } from "solid-js";

export interface AppLayoutProps {
  children: JSX.Element;
}

/**
 * Root shell for the island layout.
 *
 * Provides the dark window background, outer padding, and gap
 * between island columns. All child islands are laid out in a
 * horizontal flex row.
 *
 * The drag region spans the full top of the window so the user
 * can drag from any gap between islands.
 */
export const AppLayout: Component<AppLayoutProps> = (props) => {
  return (
    <div
      data-tauri-drag-region
      class="flex h-full w-full p-3 gap-2 bg-window overflow-hidden"
    >
      {props.children}
    </div>
  );
};
