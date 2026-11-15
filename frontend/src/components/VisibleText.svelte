<script lang="ts">
  import { segments } from "../lib/visible";

  // S-34: shows outside text as text. Hidden characters (controls,
  // bidirectional overrides, zero-width) appear as a visible marker such as
  // U+202E instead of acting on the text around them. Svelte text
  // interpolation only: never {@html}, never innerHTML (lint rule).
  let { text, max }: { text: string; max?: number } = $props();
  const parts = $derived(segments(text, max));
</script>

{#each parts as p, i (i)}{#if p.marker}<span class="ctl">{p.text}</span>{:else}{p.text}{/if}{/each}
