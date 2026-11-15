<script lang="ts">
  import Icon from "./Icon.svelte";
  import type { IconName } from "../lib/icons/icons";
  import type { Tone } from "../lib/status";

  // Status is a word plus a shape plus a colour, never colour alone
  // (plan section 7): check, triangle, exclamation, hollow circle, barred
  // circle.
  let { tone, text, blocked = false }: { tone: Tone; text: string; blocked?: boolean } = $props();
  const shapes: Record<Tone, IconName> = {
    ok: "status-ok",
    warning: "status-warning",
    danger: "status-danger",
    off: "status-off",
  };
</script>

<span class="status status-{tone}"><Icon name={blocked ? "blocked" : shapes[tone]} />{text}</span>
