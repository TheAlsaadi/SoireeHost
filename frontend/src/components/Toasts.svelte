<script lang="ts">
  import Icon from "./Icon.svelte";
  import VisibleText from "./VisibleText.svelte";
  import { t } from "../lib/i18n";
  import { dismissToast, toasts } from "../lib/state.svelte";
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each toasts as toast (toast.id)}
    <div class="toast toast-{toast.kind}">
      <Icon name={toast.kind === "error" ? "status-danger" : "status-ok"} />
      <div class="toast-text">
        <p><VisibleText text={toast.text} /></p>
        {#if toast.detail}
          <p class="small secondary">{t("common.workerSaid")}</p>
          <p class="mono small"><VisibleText text={toast.detail} max={200} /></p>
        {/if}
      </div>
      <button class="button button-subtle button-icon" type="button" aria-label={t("common.close")} onclick={() => dismissToast(toast.id)}>
        <Icon name="dismiss" />
      </button>
    </div>
  {/each}
</div>
