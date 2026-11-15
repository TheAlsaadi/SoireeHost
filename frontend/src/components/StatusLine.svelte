<script lang="ts">
  import StatusMark from "./StatusMark.svelte";
  import { api } from "../lib/api";
  import { t } from "../lib/i18n";
  import { app, applyConfig, refreshStatus, toastError } from "../lib/state.svelte";
  import { statusLine } from "../lib/status";

  // One sentence on every screen, in plain words (plan section 7), and the
  // one switch that takes everything offline (plan section 6).
  const said = $derived(statusLine(app.status, app.config, app.failed));
  const isOnline = $derived(said.key === "statusline.online");
  let busy = $state(false);

  async function flip() {
    if (!app.status) return;
    busy = true;
    try {
      applyConfig(await api().setOffline(!app.status.tunnel.offline));
      await refreshStatus();
    } catch (e) {
      toastError(e, t("error.generic"));
    } finally {
      busy = false;
    }
  }
</script>

<div class="statusline" role="status">
  <p class="statusline-text">
    {#if isOnline}
      <StatusMark tone="ok" text={t("statusline.onlineLead")} />
      <span>{t(said.key, said.params)}</span>
    {:else}
      <StatusMark tone={said.tone} text={t(said.key, said.params)} />
    {/if}
  </p>
  {#if app.status}
    <button class="button" type="button" disabled={busy} onclick={flip}>
      {app.status.tunnel.offline ? t("statusline.bringOnline") : t("statusline.takeOffline")}
    </button>
  {/if}
</div>
