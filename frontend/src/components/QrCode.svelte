<script lang="ts">
  import type { gui } from "../lib/api";

  // Drawn as SVG rectangles from the matrix the Go side made on this PC
  // (plan section 6): no image request, no HTML from data.
  let { code, label }: { code: gui.QRCode; label: string } = $props();
  const quiet = 4;
  const cells = $derived(
    code.modules.flatMap((row, y) => row.flatMap((dark, x) => (dark ? [{ x: x + quiet, y: y + quiet }] : []))),
  );
</script>

<svg class="qr" viewBox="0 0 {code.size + 2 * quiet} {code.size + 2 * quiet}" role="img" aria-label={label} shape-rendering="crispEdges">
  <rect class="qr-bg" x="0" y="0" width={code.size + 2 * quiet} height={code.size + 2 * quiet} />
  {#each cells as c (c.y * 1000 + c.x)}
    <rect class="qr-dot" x={c.x} y={c.y} width="1" height="1" />
  {/each}
</svg>
