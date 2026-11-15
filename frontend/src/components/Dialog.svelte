<script lang="ts">
  import type { Snippet } from "svelte";

  // A modal dialog on the native <dialog> element: the browser traps focus,
  // makes the rest of the window inert and closes it on Escape. Focus goes
  // back to what had it when the dialog closes.
  let {
    open,
    title,
    onclose,
    children,
    actions,
  }: { open: boolean; title: string; onclose: () => void; children: Snippet; actions: Snippet } = $props();

  let el: HTMLDialogElement | undefined = $state();
  let returnTo: Element | null = null;
  const id = "dlg-" + Math.random().toString(36).slice(2);

  $effect(() => {
    if (!el) return;
    if (open && !el.open) {
      returnTo = document.activeElement;
      el.showModal();
    } else if (!open && el.open) {
      el.close();
    }
  });
</script>

<dialog
  bind:this={el}
  class="dialog"
  aria-labelledby={id}
  onclose={() => {
    if (returnTo instanceof HTMLElement) returnTo.focus();
    if (open) onclose();
  }}
  oncancel={(e) => {
    e.preventDefault();
    onclose();
  }}
>
  <h2 class="dialog-title" {id}>{title}</h2>
  <div class="dialog-body">{@render children()}</div>
  <div class="dialog-actions">{@render actions()}</div>
</dialog>
