<script lang="ts">
  import { t } from "../lib/i18n";

  // On/off is state, not the primary action, so the switch is grey, never
  // the accent. The word beside it says the state as well as the knob.
  let {
    checked,
    label,
    disabled = false,
    onchange,
  }: { checked: boolean; label: string; disabled?: boolean; onchange: (next: boolean) => void } = $props();
</script>

<button
  class="switch"
  type="button"
  role="switch"
  aria-checked={checked}
  aria-label={label}
  {disabled}
  onclick={(e) => {
    e.stopPropagation();
    onchange(!checked);
  }}
>
  <span class="switch-track"></span><span class="switch-label">{checked ? t("common.on") : t("common.off")}</span>
</button>
