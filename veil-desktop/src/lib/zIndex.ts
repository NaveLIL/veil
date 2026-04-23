/**
 * Centralised z-index layers for all overlay UI.
 *
 * Banishes raw `z-50`/`60`/`70`/`9999` magic numbers across components.
 * If you need a new layer, add it here and document why.
 *
 * Layer ordering (low → high):
 *   BASE      = chat layout, sidebar, header
 *   POPOVER   = dropdowns, tooltips, hover-cards
 *   DIALOG    = modal dialogs (IslandDialog), bottom sheets
 *   DROPDOWN  = select menus opened from inside a dialog
 *   TOAST     = transient notifications
 *   DRAG      = items being dragged (file drop zone overlay, draggable dialog)
 *
 * Kept as plain numbers (not constants) so inline-styles can reference them.
 */
export const Z = {
  BASE: 1,
  POPOVER: 40,
  DIALOG_BACKDROP: 60,
  DIALOG: 61,
  DROPDOWN: 70,
  TOAST: 80,
  DRAG: 90,
} as const;

export type ZLayer = keyof typeof Z;
