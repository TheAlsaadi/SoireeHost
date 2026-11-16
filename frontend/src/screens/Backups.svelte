<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import EmptyState from "../components/EmptyState.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type config } from "../lib/api";
  import { t } from "../lib/i18n";
  import { app, applyConfig, refreshStatus, toastDone, toastError, withConfirmation } from "../lib/state.svelte";
  import { dateTime, revisionSummary } from "../lib/status";

  function summaryOf(r: config.Record): string {
    const s = revisionSummary(r.summary);
    return s ? t(s.key, s.params) : r.summary;
  }

  let revisions = $state<config.Record[]>([]);
  let busy = $state(false);

  async function load() {
    try {
      const h = await api().history();
      revisions = [...h.revisions].sort((a, b) => b.revision - a.revision);
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  $effect(() => {
    void app.revision;
    void load();
  });

  async function exportSettings() {
    busy = true;
    try {
      const text = await api().exportConfig();
      if (await api().saveExport(text)) toastDone(t("backups.exported"));
    } catch (e) {
      toastError(e, t("error.generic"));
    } finally {
      busy = false;
    }
  }

  // Import is always a weakening change (S-32): the supervisor names what
  // it changes and the user confirms; the file read is what gets confirmed.
  async function importSettings() {
    busy = true;
    try {
      const text = await api().openImport();
      if (!text) return;
      let first = true;
      const res = await withConfirmation((tok) => {
        if (first) {
          first = false;
          return api().importConfig(text);
        }
        return api().confirmImport(tok);
      });
      applyConfig(res);
      await refreshStatus();
      toastDone(t("backups.imported"));
    } catch (e) {
      toastError(e, t("error.generic"));
    } finally {
      busy = false;
    }
  }

  async function restore(rev: number) {
    busy = true;
    try {
      applyConfig(await withConfirmation((tok) => api().rollback(rev, tok)));
      await refreshStatus();
      toastDone(t("backups.restored", { n: rev }));
    } catch (e) {
      toastError(e, t("error.generic"));
    } finally {
      busy = false;
    }
  }
</script>

<main class="screen">
  <div class="screen-head">
    <h1>{t("backups.title")}</h1>
  </div>
  <p class="screen-intro">{t("backups.intro")}</p>
  <div class="actions page-actions">
    <button class="button" type="button" disabled={busy} onclick={exportSettings}><Icon name="copy" />{t("backups.export")}</button>
    <button class="button" type="button" disabled={busy} onclick={importSettings}><Icon name="folder" />{t("backups.import")}</button>
  </div>

  <div class="checklist-scroll">
    <section class="group" aria-labelledby="g-history">
      <h2 id="g-history">{t("backups.history")}</h2>
      {#if revisions.length === 0}
        <EmptyState text={t("backups.historyEmpty")} />
      {:else}
        <ul class="checklist">
          {#each revisions as r (r.revision)}
            <li class="check check-wide">
              <span class="check-name">{t("backups.revision", { n: r.revision })}</span>
              <div>
                <p class="check-what"><VisibleText text={t("backups.by", { summary: summaryOf(r), date: dateTime(r.saved_at) })} /></p>
              </div>
              {#if r.revision === app.revision}
                <span class="secondary">{t("backups.current")}</span>
              {:else}
                <button class="button" type="button" disabled={busy} onclick={() => restore(r.revision)}>{t("backups.restore")}</button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  </div>
</main>
