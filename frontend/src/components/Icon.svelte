<script lang="ts">
  import { icons, type IconName } from "../lib/icons/icons";

  // Decorative by default: the word next to it carries the meaning.
  let { name, large = false }: { name: IconName; large?: boolean } = $props();
  const data = $derived(icons[name]);
</script>

<svg class="icon" class:icon-large={large} viewBox="0 0 {data.size} {data.size}" aria-hidden="true" focusable="false">
  {#each data.paths as d, i (i)}
    <path {d} />
  {/each}
</svg>
