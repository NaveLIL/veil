import { ContextMenu as KContextMenu } from "@kobalte/core/context-menu";
import { type Component, type JSX, type ParentComponent, splitProps } from "solid-js";
import { cn } from "@/lib/utils";

/* ═══════════════════════════════════════════════════════
   CONTEXT MENU — Veil standard
   Thin wrappers over Kobalte ContextMenu primitives.
   Styling via .veil-ctx-* classes in app.css.

   Usage:
     <ContextMenu>
       <ContextMenuTrigger>
         <div>Right-click me</div>
       </ContextMenuTrigger>
       <ContextMenuContent>
         <ContextMenuItem onSelect={fn}>Copy</ContextMenuItem>
         <ContextMenuSeparator />
         <ContextMenuSub>
           <ContextMenuSubTrigger>More</ContextMenuSubTrigger>
           <ContextMenuSubContent>
             <ContextMenuItem onSelect={fn}>Option A</ContextMenuItem>
           </ContextMenuSubContent>
         </ContextMenuSub>
         <ContextMenuSeparator />
         <ContextMenuItem variant="danger" onSelect={fn}>Delete</ContextMenuItem>
       </ContextMenuContent>
     </ContextMenu>
   ═══════════════════════════════════════════════════════ */

// ─── Root ─────────────────────────────────────────────

export const ContextMenu = KContextMenu;

// ─── Trigger ──────────────────────────────────────────

interface TriggerProps {
  class?: string;
  disabled?: boolean;
  children: JSX.Element;
}

export const ContextMenuTrigger: Component<TriggerProps> = (props) => {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.Trigger class={cn("outline-none", local.class)} {...rest}>
      {local.children}
    </KContextMenu.Trigger>
  );
};

// ─── Content (portaled) ───────────────────────────────

interface ContentProps {
  class?: string;
  children: JSX.Element;
}

export const ContextMenuContent: Component<ContentProps> = (props) => {
  const [local] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.Portal>
      <KContextMenu.Content
        class={cn("veil-ctx-content", local.class)}
        onContextMenu={(e: MouseEvent) => e.preventDefault()}
      >
        {local.children}
      </KContextMenu.Content>
    </KContextMenu.Portal>
  );
};

// ─── Item ─────────────────────────────────────────────

interface ItemProps {
  class?: string;
  variant?: "default" | "danger";
  disabled?: boolean;
  closeOnSelect?: boolean;
  onSelect?: () => void;
  children: JSX.Element;
}

export const ContextMenuItem: Component<ItemProps> = (props) => {
  const [local, rest] = splitProps(props, ["class", "variant", "children"]);
  return (
    <KContextMenu.Item
      class={cn(
        "veil-ctx-item",
        local.variant === "danger" && "veil-ctx-item--danger",
        local.class,
      )}
      {...rest}
    >
      {local.children}
    </KContextMenu.Item>
  );
};

// ─── Item helpers: Label, Description, Icon slot ──────

export const ContextMenuItemLabel = KContextMenu.ItemLabel;

interface ItemDescProps {
  class?: string;
  children: JSX.Element;
}

export const ContextMenuItemDescription: Component<ItemDescProps> = (props) => {
  const [local] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.ItemDescription class={cn("veil-ctx-item-desc", local.class)}>
      {local.children}
    </KContextMenu.ItemDescription>
  );
};

/** Right-aligned slot for keyboard shortcuts */
export const ContextMenuShortcut: ParentComponent<{ class?: string }> = (props) => (
  <span class={cn("veil-ctx-shortcut", props.class)}>{props.children}</span>
);

/** Left-aligned icon slot (16×16 recommended) */
export const ContextMenuIcon: ParentComponent<{ class?: string }> = (props) => (
  <span class={cn("veil-ctx-icon", props.class)}>{props.children}</span>
);

// ─── Separator ────────────────────────────────────────

export const ContextMenuSeparator: Component<{ class?: string }> = (props) => (
  <KContextMenu.Separator class={cn("veil-ctx-separator", props.class)} />
);

// ─── Group + Label ────────────────────────────────────

export const ContextMenuGroup = KContextMenu.Group;

export const ContextMenuGroupLabel: Component<{ class?: string; children: JSX.Element }> = (props) => {
  const [local] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.GroupLabel class={cn("veil-ctx-group-label", local.class)}>
      {local.children}
    </KContextMenu.GroupLabel>
  );
};

// ─── Sub-menu ─────────────────────────────────────────

export const ContextMenuSub = KContextMenu.Sub;

interface SubTriggerProps {
  class?: string;
  disabled?: boolean;
  children: JSX.Element;
}

export const ContextMenuSubTrigger: Component<SubTriggerProps> = (props) => {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.SubTrigger class={cn("veil-ctx-item veil-ctx-sub-trigger", local.class)} {...rest}>
      {local.children}
      <span class="veil-ctx-chevron" aria-hidden="true">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="9 18 15 12 9 6" />
        </svg>
      </span>
    </KContextMenu.SubTrigger>
  );
};

interface SubContentProps {
  class?: string;
  children: JSX.Element;
}

export const ContextMenuSubContent: Component<SubContentProps> = (props) => {
  const [local] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.Portal>
      <KContextMenu.SubContent class={cn("veil-ctx-content veil-ctx-sub-content", local.class)}>
        {local.children}
      </KContextMenu.SubContent>
    </KContextMenu.Portal>
  );
};

// ─── Checkbox Item ────────────────────────────────────

interface CheckboxItemProps {
  class?: string;
  checked?: boolean;
  defaultChecked?: boolean;
  onChange?: (checked: boolean) => void;
  disabled?: boolean;
  closeOnSelect?: boolean;
  onSelect?: () => void;
  children: JSX.Element;
}

export const ContextMenuCheckboxItem: Component<CheckboxItemProps> = (props) => {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.CheckboxItem class={cn("veil-ctx-item veil-ctx-checkbox-item", local.class)} {...rest}>
      <KContextMenu.ItemIndicator class="veil-ctx-indicator" forceMount>
        <svg class="veil-ctx-check-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </KContextMenu.ItemIndicator>
      {local.children}
    </KContextMenu.CheckboxItem>
  );
};

// ─── Radio Group + Radio Item ─────────────────────────

export const ContextMenuRadioGroup = KContextMenu.RadioGroup;

interface RadioItemProps {
  class?: string;
  value: string;
  disabled?: boolean;
  closeOnSelect?: boolean;
  onSelect?: () => void;
  children: JSX.Element;
}

export const ContextMenuRadioItem: Component<RadioItemProps> = (props) => {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <KContextMenu.RadioItem class={cn("veil-ctx-item veil-ctx-radio-item", local.class)} {...rest}>
      <KContextMenu.ItemIndicator class="veil-ctx-indicator" forceMount>
        <svg class="veil-ctx-dot-icon" width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
          <circle cx="12" cy="12" r="5" />
        </svg>
      </KContextMenu.ItemIndicator>
      {local.children}
    </KContextMenu.RadioItem>
  );
};
