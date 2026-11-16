<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import StatusMark from "../components/StatusMark.svelte";
  import Switch from "../components/Switch.svelte";
  import EmptyState from "../components/EmptyState.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import SiteDetail from "./SiteDetail.svelte";
  import SiteForm from "./SiteForm.svelte";
  import { api, type config } from "../lib/api";
  import { t } from "../lib/i18n";
  import { app, applyConfig, refreshStatus, toastError, withConfirmation } from "../lib/state.svelte";
  import { siteAddress, siteStatus } from "../lib/status";

  let { droppedFolder = $bindable("") }: { droppedFolder?: string } = $props();

  const sites = $derived(app.config?.sites ?? []);
  let selectedId = $state("");
  let paneOpen = $state(true);
  let formOpen = $state(false);
  let editing: config.Site | undefined = $state();
  let formFolder = $state("");

  const selected = $derived(sites.find((s) => s.id === selectedId) ?? sites[0]);

  $effect(() => {
    if (droppedFolder) {
      editing = undefined;
      formFolder = droppedFolder;
      formOpen = true;
      droppedFolder = "";
    }
  });

  function hostOf(address: string): string {
    return address.replace(/^https:\/\//, "").replace(/\/$/, "");
  }

  async function setEnabled(site: config.Site, on: boolean) {
    try {
      applyConfig(await withConfirmation((tok) => api().setSiteEnabled(site.id, on, tok)));
      await refreshStatus();
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  function openAdd() {
    editing = undefined;
    formFolder = "";
    formOpen = true;
  }

  function openEdit(site: config.Site) {
    editing = site;
    formFolder = "";
    formOpen = true;
  }

  function select(site: config.Site) {
    selectedId = site.id;
    paneOpen = true;
  }

  // The list is one tab stop: arrow keys move between rows, Enter opens the
  // row's details, Escape closes them.
  function onRowKey(e: KeyboardEvent, i: number) {
    const rows = sites;
    let next: number;
    if (e.key === "ArrowDown") next = Math.min(i + 1, rows.length - 1);
    else if (e.key === "ArrowUp") next = Math.max(i - 1, 0);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = rows.length - 1;
    else if (e.key === "Enter") {
      const row = rows[i];
      if (row) select(row);
      return;
    } else if (e.key === "Escape") {
      paneOpen = false;
      return;
    } else return;
    e.preventDefault();
    const target = rows[next];
    if (!target) return;
    selectedId = target.id;
    const tr = (e.currentTarget as HTMLElement).parentElement?.children[next] as HTMLElement | undefined;
    tr?.focus();
  }
</script>

<main class="screen">
  <div class="screen-head">
    <h1>{t("sites.title")}</h1>
    <button class="button button-primary" type="button" onclick={openAdd}><Icon name="add" />{t("sites.add")}</button>
  </div>

  {#if app.config && sites.length === 0}
    <EmptyState text={t("sites.empty")}>
      {#snippet action()}
        <button class="button" type="button" onclick={openAdd}><Icon name="add" />{t("sites.add")}</button>
      {/snippet}
    </EmptyState>
  {:else}
    <div class="split" class:split-single={!paneOpen || !selected}>
      <div class="list-region">
        <table class="table table-fixed" role="grid" aria-label={t("sites.list")}>
          <colgroup><col class="col-name" /><col class="col-address" /><col class="col-type cell-type" /><col class="col-status" /><col class="col-switch" /></colgroup>
          <thead>
            <tr>
              <th scope="col">{t("sites.col.name")}</th>
              <th scope="col" class="cell-address">{t("sites.col.address")}</th>
              <th scope="col" class="cell-type">{t("sites.col.type")}</th>
              <th scope="col">{t("sites.col.status")}</th>
              <th scope="col">{t("sites.col.serving")}</th>
            </tr>
          </thead>
          <tbody>
            {#each sites as site, i (site.id)}
              {@const address = siteAddress(site, app.status)}
              {@const said = siteStatus(site, app.status, app.ports)}
              <tr
                aria-selected={selected?.id === site.id}
                tabindex={selected?.id === site.id ? 0 : -1}
                onclick={() => select(site)}
                onkeydown={(e) => onRowKey(e, i)}
              >
                <td class="site-name"><VisibleText text={site.name} max={60} /></td>
                {#if address}
                  <td class="cell-truncate cell-address mono small" title={address}><VisibleText text={hostOf(address)} /></td>
                {:else}
                  <td class="secondary cell-address">{t("sites.noAddress")}</td>
                {/if}
                <td class="cell-type">{site.type === "static" ? t("site.type.static") : t("site.type.proxy")}</td>
                <td><StatusMark tone={said.tone} text={t(said.key, said.params)} /></td>
                <td>
                  <Switch checked={site.enabled} label={t("sites.serve", { name: site.name })} onchange={(on) => setEnabled(site, on)} />
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="drop-hint small secondary">{t("sites.dropHint")}</p>
      </div>
      {#if paneOpen && selected}
        <SiteDetail site={selected} onedit={() => openEdit(selected)} onclose={() => (paneOpen = false)} />
      {/if}
    </div>
  {/if}
</main>

<SiteForm bind:open={formOpen} site={editing} initialFolder={formFolder} onsaved={(id) => (selectedId = id)} />
