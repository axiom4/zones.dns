/** Moves focus to the element with this id once Angular has drawn it (after an inline edit opens or closes, or a row goes away). */
export function focusSoon(id: string) {
  setTimeout(() => document.getElementById(id)?.focus());
}
