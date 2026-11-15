<script lang="ts">
  import type { Snippet } from "svelte";

  // One sentence and one action (plan section 7).
  let { text, action }: { text: string; action?: Snippet } = $props();
</script>

<div class="empty">
  <p>{text}</p>
  {#if action}{@render action()}{/if}
</div>
