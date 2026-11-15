<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import Dialog from "../components/Dialog.svelte";
  import QrCode from "../components/QrCode.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type config, type gui } from "../lib/api";
  import { t } from "../lib/i18n";
  import { app, applyConfig, refreshStatus, toastDone, toastError, withConfirmation } from "../lib/state.svelte";
  import { megabytes, proxyPort, siteAddress, siteOnline, siteStatus } from "../lib/status";

  let { site, onedit, onclose }: { site: config.Site; onedit: () => void; onclose: () => void } = $props();

  const address = $derived(siteAddress(site, app.status));
  const said = $derived(siteStatus(site, app.status, app.ports));
  const quick = $derived(app.status?.tunnel.tunnels.find((x) => x.kind === "quick" && x.site_id === site.id));
  const fwMode = $derived(site.firewall.mode || "block");
  const level = $derived(site.firewall.paranoia_level || 1);
  const removed = $derived(site.remove_headers ?? []);
  let qr: gui.QRCode | undefined = $state();
  let removing = $state(false);
  let busy = $state(false);

  $effect(() => {
    void site.id;
    qr = undefined;
  });

  const health = $derived.by(() => {
    if (app.status?.tunnel.offline && site.enabled) return t("site.health.offline");
    if (said.key === "site.status.stopped") return t("site.health.stopped");
    if (said.key === "site.status.portDown") return t("site.health.portDown", { port: proxyPort(site) });
    if (siteOnline(site, app.status)) {
      return t("site.health.online", { how: quick?.state === "connected" ? t("site.health.quick") : t("site.health.permanent") });
    }
    return t("site.health.notOnline");
  });

  async function run(fn: () => Promise<unknown>) {
    busy = true;
    try {
      await fn();
      await refreshStatus();
    } catch (e) {
      toastError(e, t("error.generic"));
    } finally {
      busy = false;
    }
  }

  async function copyAddress() {
    if (await api().copyText(address)) toastDone(t("common.copied"));
  }

  async function toggleQr() {
    if (qr) {
      qr = undefined;
      return;
    }
    try {
      qr = await api().qrCode(address);
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }
</script>

<aside class="pane" aria-labelledby="pane-title">
  <div class="pane-head">
    <h2 id="pane-title"><VisibleText text={site.name} /></h2>
    <button class="button button-subtle button-icon" type="button" aria-label={t("common.closeDetails")} onclick={onclose}>
      <Icon name="dismiss" />
    </button>
  </div>
  <p class="health status-{said.tone}">
    <Icon name={said.tone === "ok" ? "status-ok" : said.tone === "warning" ? "status-warning" : said.tone === "danger" ? "status-danger" : "status-off"} />
    <span><span class="visually-hidden">{t(said.key, said.params)}. </span>{health}</span>
  </p>

  {#if address}
    <section class="pane-section" aria-labelledby="h-address">
      <h3 id="h-address">{t("site.address")}</h3>
      <p class="address"><VisibleText text={address} /></p>
      <div class="actions">
        <button class="button" type="button" onclick={copyAddress}><Icon name="copy" />{t("site.copyAddress")}</button>
        <button class="button" type="button" aria-expanded={!!qr} onclick={toggleQr}>
          <Icon name="qr" large />{qr ? t("site.hideQr") : t("site.showQr")}
        </button>
        <button class="button" type="button" onclick={() => run(() => api().openSiteAddress(address))}>
          <Icon name="open" />{t("site.openAddress")}
        </button>
      </div>
      {#if qr}
        <div class="qr-wrap"><QrCode code={qr} label={t("site.qrLabel", { address })} /></div>
      {/if}
      {#if quick?.temporary}
        <p class="note"><Icon name="info" />{t("site.quickLabel")}</p>
      {/if}
    </section>
  {/if}

  <section class="pane-section" aria-labelledby="h-content">
    <h3 id="h-content">{t("site.content")}</h3>
    <dl class="facts">
      <dt>{t("site.fact.type")}</dt>
      <dd>{site.type === "static" ? t("site.fact.static") : t("site.fact.proxy")}</dd>
      {#if site.static}
        <dt>{t("site.fact.folder")}</dt>
        <dd class="mono small"><VisibleText text={site.static.root} /></dd>
        <dt>{t("site.fact.listing")}</dt>
        <dd>{site.static.directory_listing ? t("common.on") : t("common.off")}</dd>
        <dt>{t("site.fact.wellKnown")}</dt>
        <dd>{site.allow_well_known ? t("common.on") : t("common.off")}</dd>
      {/if}
      {#if site.proxy}
        <dt>{t("site.fact.target")}</dt>
        <dd class="mono small"><VisibleText text={site.proxy.target} /></dd>
      {/if}
    </dl>
  </section>

  <section class="pane-section" aria-labelledby="h-online">
    <h3 id="h-online">{t("site.online")}</h3>
    <dl class="facts">
      <dt>{t("site.fact.quick")}</dt>
      <dd>{site.quick_share ? t("common.on") : t("common.off")}</dd>
      <dt>{t("site.fact.permanent")}</dt>
      <dd>
        {#if !app.status?.tunnel.token_set}
          {t("site.permanent.none")}
        {:else if site.hostnames.length === 0}
          {t("site.permanent.noHostnames")}
        {:else}
          <span class="mono small"><VisibleText text={site.hostnames.join(", ")} /></span>
        {/if}
      </dd>
    </dl>
    <div class="actions">
      {#if site.quick_share}
        <button class="button" type="button" disabled={busy} onclick={() => run(async () => applyConfig(await api().stopQuickShare(site.id)))}>
          {t("site.stopShare")}
        </button>
      {:else}
        <button class="button" type="button" disabled={busy || !site.enabled} onclick={() => run(async () => applyConfig(await api().startQuickShare(site.id)))}>
          {t("site.startShare")}
        </button>
      {/if}
    </div>
  </section>

  <section class="pane-section" aria-labelledby="h-protection">
    <h3 id="h-protection">{t("site.protection")}</h3>
    <dl class="facts">
      <dt>{t("site.fact.firewall")}</dt>
      <dd>
        {fwMode === "block" ? t("site.firewall.block", { level }) : fwMode === "detect" ? t("site.firewall.detect", { level }) : t("site.firewall.off")}
      </dd>
      <dt>{t("site.fact.rate")}</dt>
      <dd>{t("site.rate", { n: site.rate_limit_per_minute || 300 })}</dd>
      <dt>{t("site.fact.body")}</dt>
      <dd>{t("site.body", { n: megabytes(site.max_body_bytes || 10 << 20) })}</dd>
      <dt>{t("site.fact.headers")}</dt>
      <dd>{removed.length === 0 ? t("site.headers.all") : t("site.headers.weakened", { names: removed.join(", ") })}</dd>
    </dl>
  </section>

  <div class="pane-foot">
    <button class="button" type="button" onclick={onedit}>{t("site.edit")}</button>
    <button
      class="button"
      type="button"
      disabled={busy}
      onclick={() => run(async () => applyConfig(await withConfirmation((tok) => api().setSiteEnabled(site.id, !site.enabled, tok))))}
    >
      {site.enabled ? t("site.stopServing") : t("site.startServing")}
    </button>
    <button class="button" type="button" onclick={() => (removing = true)}><Icon name="delete" />{t("site.remove")}</button>
  </div>
</aside>

<Dialog open={removing} title={t("site.removeTitle", { name: site.name })} onclose={() => (removing = false)}>
  <p>{t("site.removeBody")}</p>
  {#snippet actions()}
    <button
      class="button"
      type="button"
      onclick={() => {
        removing = false;
        run(async () => {
          applyConfig(await api().removeSite(site.id));
          onclose();
        });
      }}>{t("site.remove")}</button
    >
    <!-- svelte-ignore a11y_autofocus -->
    <button class="button button-primary" type="button" autofocus onclick={() => (removing = false)}>{t("site.removeKeep")}</button>
  {/snippet}
</Dialog>
