<script lang="ts">
  import Dialog from "../components/Dialog.svelte";
  import Icon from "../components/Icon.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type config } from "../lib/api";
  import { t } from "../lib/i18n";
  import { Declined, app, applyConfig, refreshPorts, refreshStatus, toastDone, toastError, withConfirmation } from "../lib/state.svelte";
  import { idFromName, proxyPort, proxyTarget } from "../lib/status";
  import { toApiError } from "../lib/errors";

  let {
    open = $bindable(false),
    site,
    initialFolder = "",
    onsaved,
  }: { open?: boolean; site?: config.Site; initialFolder?: string; onsaved?: (id: string) => void } = $props();

  let name = $state("");
  let kind = $state<"static" | "proxy">("static");
  let folder = $state("");
  let port = $state("");
  let hostnames = $state("");
  let fwMode = $state("block");
  let listing = $state(false);
  let wellKnown = $state(false);
  let problem = $state("");
  let busy = $state(false);

  // Fill the form each time it opens.
  $effect(() => {
    if (!open) return;
    problem = "";
    if (site) {
      name = site.name;
      kind = site.type === "proxy" ? "proxy" : "static";
      folder = site.static?.root ?? "";
      port = site.proxy ? String(proxyPort(site)) : "";
      hostnames = site.hostnames.join("\n");
      fwMode = site.firewall.mode || "block";
      listing = site.static?.directory_listing ?? false;
      wellKnown = site.allow_well_known;
    } else {
      name = "";
      kind = "static";
      folder = initialFolder;
      port = "";
      hostnames = "";
      fwMode = "block";
      listing = false;
      wellKnown = false;
    }
    void refreshPorts();
  });

  const ports = $derived(app.ports ?? []);
  const chosenPort = $derived(ports.find((p) => String(p.port) === port.trim()));

  async function chooseFolder() {
    try {
      const p = await api().chooseFolder();
      if (p) folder = p;
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  async function save(ev: SubmitEvent) {
    ev.preventDefault();
    problem = "";
    if (!name.trim()) return void (problem = t("form.needName"));
    const n = Number(port.trim());
    if (kind === "proxy" && !(Number.isInteger(n) && n >= 1024 && n <= 65535)) return void (problem = t("form.needPort"));
    if (kind === "static" && !folder) return void (problem = t("form.needFolder"));
    busy = true;
    try {
      let root = folder;
      // The folder is checked (S-11) and opened to the web worker only
      // through one handle that never follows a link (SE-07); an
      // unchanged folder of an existing site is not granted again.
      if (kind === "static" && root !== site?.static?.root) root = await api().prepareFolder(folder);
      const taken = (app.config?.sites ?? []).map((s) => s.id).filter((id) => id !== site?.id);
      const next: config.Site = {
        id: site?.id ?? idFromName(name, taken),
        name: name.trim(),
        enabled: site?.enabled ?? true,
        hostnames: hostnames
          .split(/[\s,]+/)
          .map((h) => h.trim().toLowerCase())
          .filter(Boolean),
        type: kind,
        static: kind === "static" ? { root, directory_listing: listing } : null,
        proxy: kind === "proxy" ? { target: proxyTarget(n, app.ports), allow_lan: false } : null,
        max_body_bytes: site?.max_body_bytes ?? 0,
        rate_limit_per_minute: site?.rate_limit_per_minute ?? 0,
        allow_well_known: kind === "static" && wellKnown,
        response_headers: site?.response_headers,
        remove_headers: site?.remove_headers,
        firewall: { mode: fwMode, paranoia_level: site?.firewall.paranoia_level ?? 1 },
      };
      const res = await withConfirmation((tok) => api().putSite(next, tok));
      applyConfig(res);
      await refreshStatus();
      open = false;
      onsaved?.(next.id);
      toastDone(name.trim());
    } catch (e) {
      if (e instanceof Declined) return;
      const err = toApiError(e);
      if (err.code) problem = err.message || t("error.generic");
      if (err.workerDetail) problem += " " + t("common.workerSaid") + " " + err.workerDetail;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog {open} title={site ? t("form.editTitle", { name: site.name }) : t("form.addTitle")} onclose={() => (open = false)}>
  <form id="site-form" class="form" onsubmit={save} novalidate>
    <div class="form-field">
      <label for="f-name">{t("form.name")}</label>
      <input id="f-name" class="input-text" type="text" maxlength="64" bind:value={name} aria-describedby="f-name-help" />
      <p id="f-name-help" class="small secondary">{t("form.nameHelp")}</p>
    </div>

    {#if !site}
      <fieldset class="form-field">
        <legend>{t("form.kind")}</legend>
        <label class="choice"><input type="radio" name="kind" value="static" bind:group={kind} />{t("form.kind.static")}</label>
        <label class="choice"><input type="radio" name="kind" value="proxy" bind:group={kind} />{t("form.kind.proxy")}</label>
      </fieldset>
    {/if}

    {#if kind === "static"}
      <div class="form-field">
        <span class="form-label" id="f-folder-label">{t("form.folder")}</span>
        <div class="form-row">
          <span class="mono small folder-path" aria-labelledby="f-folder-label">
            {#if folder}<VisibleText text={folder} />{:else}<span class="secondary">{t("form.noFolder")}</span>{/if}
          </span>
          <button class="button" type="button" onclick={chooseFolder}><Icon name="folder" />{t("form.chooseFolder")}</button>
        </div>
      </div>
      <label class="choice"><input type="checkbox" bind:checked={listing} />{t("form.listing")}</label>
      <label class="choice"><input type="checkbox" bind:checked={wellKnown} />{t("form.wellKnown")}</label>
    {:else}
      <div class="form-field">
        <label for="f-port-pick">{t("form.port")}</label>
        <select id="f-port-pick" class="select-native" bind:value={port}>
          <option value="">{t("form.portPick")}</option>
          {#each ports as p (p.port)}
            <option value={String(p.port)}>
              {p.process ? t("form.portOption", { port: p.port, process: p.process }) : t("form.portOptionUnknown", { port: p.port })}
            </option>
          {/each}
        </select>
        <label for="f-port" class="small secondary">{t("form.portManual")}</label>
        <input id="f-port" class="input-text input-short" type="text" inputmode="numeric" maxlength="5" bind:value={port} />
        {#if chosenPort && !chosenPort.loopback}
          <p class="small status-warning-text">{t("form.portNotLoopback", { port: chosenPort.port })}</p>
        {/if}
      </div>
    {/if}

    <div class="form-field">
      <label for="f-hosts">{t("form.hostnames")}</label>
      <textarea id="f-hosts" class="input-text mono" rows="2" bind:value={hostnames} aria-describedby="f-hosts-help"></textarea>
      <p id="f-hosts-help" class="small secondary">{t("form.hostnamesHelp")}</p>
    </div>

    <fieldset class="form-field">
      <legend>{t("form.firewall")}</legend>
      <label class="choice"><input type="radio" name="fw" value="block" bind:group={fwMode} />{t("form.firewall.block")}</label>
      <label class="choice"><input type="radio" name="fw" value="detect" bind:group={fwMode} />{t("form.firewall.detect")}</label>
      <label class="choice"><input type="radio" name="fw" value="off" bind:group={fwMode} />{t("form.firewall.off")}</label>
    </fieldset>

    {#if problem}
      <p class="form-problem" role="alert"><Icon name="status-danger" /><span><VisibleText text={problem} /></span></p>
    {/if}
  </form>
  {#snippet actions()}
    <button class="button button-subtle" type="button" onclick={() => (open = false)}>{t("common.cancel")}</button>
    <button class="button button-primary" type="submit" form="site-form" disabled={busy}>
      {busy && kind === "static" ? t("form.checking") : site ? t("form.saveEdit") : t("form.saveAdd")}
    </button>
  {/snippet}
</Dialog>
