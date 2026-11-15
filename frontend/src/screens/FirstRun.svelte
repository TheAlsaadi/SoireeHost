<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type config } from "../lib/api";
  import { t } from "../lib/i18n";
  import { Declined, app, applyConfig, refreshPorts, refreshStatus, toastError, withConfirmation } from "../lib/state.svelte";
  import { idFromName, proxyTarget } from "../lib/status";
  import { toApiError } from "../lib/errors";

  // First run reaches a live site in three steps: choose a folder or a
  // port, choose quick share or tunnel, go live (plan section 6).
  let { initialFolder = "", ondone }: { initialFolder?: string; ondone: () => void } = $props();

  let step = $state(1);
  let kind = $state<"static" | "proxy">("static");
  // svelte-ignore state_referenced_locally
  let folder = $state(initialFolder);
  let port = $state("");
  let how = $state<"quick" | "tunnel">("quick");
  let problem = $state("");
  let busy = $state(false);
  let heading: HTMLHeadingElement | undefined = $state();

  $effect(() => {
    void refreshPorts();
  });
  $effect(() => {
    void step;
    heading?.focus();
  });

  const name = $derived(kind === "static" ? (folder.split(/[\\/]/).filter(Boolean).pop() ?? "") : t("first.appName", { port }));
  const source = $derived(kind === "static" ? folder : "127.0.0.1:" + port);
  const ready = $derived(kind === "static" ? !!folder : /^\d{4,5}$/.test(port.trim()));

  async function choose() {
    try {
      const p = await api().chooseFolder();
      if (p) folder = p;
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  async function goLive() {
    busy = true;
    problem = "";
    try {
      const root = kind === "static" ? await api().prepareFolder(folder) : "";
      const site: config.Site = {
        id: idFromName(name, []),
        name: name || "Site",
        enabled: true,
        hostnames: [],
        type: kind,
        static: kind === "static" ? { root, directory_listing: false } : null,
        proxy: kind === "proxy" ? { target: proxyTarget(Number(port.trim()), app.ports), allow_lan: false } : null,
        max_body_bytes: 0,
        rate_limit_per_minute: 0,
        allow_well_known: false,
        firewall: { mode: "block", paranoia_level: 1 },
      };
      applyConfig(await withConfirmation((tok) => api().putSite(site, tok)));
      if (how === "quick") applyConfig(await api().startQuickShare(site.id));
      await refreshStatus();
      ondone();
    } catch (e) {
      if (e instanceof Declined) return;
      const err = toApiError(e);
      problem = err.message || t("error.generic");
      if (err.workerDetail) problem += " " + t("common.workerSaid") + " " + err.workerDetail;
    } finally {
      busy = false;
    }
  }
</script>

<main class="screen first-run">
  <div class="screen-head">
    <h1>{t("first.title")}</h1>
  </div>
  <div class="panel first-panel">
    <p class="small secondary">{t("first.step", { n: step })}</p>
    {#if step === 1}
      <h2 tabindex="-1" bind:this={heading}>{t("first.step1")}</h2>
      <fieldset class="form-field">
        <legend class="visually-hidden">{t("form.kind")}</legend>
        <label class="choice"><input type="radio" value="static" bind:group={kind} />{t("form.kind.static")}</label>
        <label class="choice"><input type="radio" value="proxy" bind:group={kind} />{t("form.kind.proxy")}</label>
      </fieldset>
      {#if kind === "static"}
        <div class="form-row">
          <span class="mono small folder-path">{#if folder}<VisibleText text={folder} />{:else}<span class="secondary">{t("form.noFolder")}</span>{/if}</span>
          <button class="button" type="button" onclick={choose}><Icon name="folder" />{t("form.chooseFolder")}</button>
        </div>
      {:else}
        <label for="fr-port">{t("form.port")}</label>
        <select id="fr-port" class="select-native" bind:value={port}>
          <option value="">{t("form.portPick")}</option>
          {#each app.ports ?? [] as p (p.port)}
            <option value={String(p.port)}>{p.process ? t("form.portOption", { port: p.port, process: p.process }) : t("form.portOptionUnknown", { port: p.port })}</option>
          {/each}
        </select>
      {/if}
    {:else if step === 2}
      <h2 tabindex="-1" bind:this={heading}>{t("first.step2")}</h2>
      <fieldset class="form-field">
        <legend class="visually-hidden">{t("first.step2")}</legend>
        <label class="choice choice-block">
          <input type="radio" value="quick" bind:group={how} />
          <span><strong>{t("first.quick")}</strong><br /><span class="secondary small">{t("first.quickHelp")}</span></span>
        </label>
        <label class="choice choice-block">
          <input type="radio" value="tunnel" bind:group={how} disabled={!app.status?.tunnel.token_set} />
          <span><strong>{t("first.tunnel")}</strong><br /><span class="secondary small">{t("first.tunnelHelp")}</span></span>
        </label>
      </fieldset>
    {:else}
      <h2 tabindex="-1" bind:this={heading}>{t("first.step3")}</h2>
      <p>
        <VisibleText
          text={t("first.summary", { name, source, how: how === "quick" ? t("first.quick") : t("first.tunnel") })}
        />
      </p>
      {#if problem}
        <p class="form-problem" role="alert"><Icon name="status-danger" /><span><VisibleText text={problem} /></span></p>
      {/if}
    {/if}

    <div class="actions">
      {#if step > 1}<button class="button" type="button" onclick={() => step--}>{t("first.back")}</button>{/if}
      {#if step < 3}
        <button class="button button-primary" type="button" disabled={!ready} onclick={() => step++}>{t("first.next")}</button>
      {:else}
        <button class="button button-primary" type="button" disabled={busy} onclick={goLive}>{t("first.goLive")}</button>
      {/if}
      <button class="button button-subtle" type="button" onclick={ondone}>{t("first.skip")}</button>
    </div>
  </div>
</main>
