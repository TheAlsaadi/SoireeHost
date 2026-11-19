<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import Switch from "../components/Switch.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type ipc } from "../lib/api";
  import { t } from "../lib/i18n";
  import { Declined, app, applyConfig, refreshStatus, toastDone, toastError, withConfirmation } from "../lib/state.svelte";
  import { setupOK, setupProblem, updateLine } from "../lib/setup";
  import { dateTime } from "../lib/status";
  import { licences } from "../lib/licences";
  import { versionLabel } from "../lib/version";

  let secret = $state<ipc.SecretStatus | undefined>();
  let signIn = $state(false);
  let busy = $state(false);
  let tokenInput: HTMLInputElement | undefined = $state();

  $effect(() => {
    api()
      .secretStatus()
      .then((r) => (secret = r.secrets.find((s) => s.name === "tunnel_token")))
      .catch(() => {});
    api()
      .startAtSignIn()
      .then((v) => (signIn = v))
      .catch(() => {});
  });

  // S-35: the token goes straight from the field to the supervisor and the
  // field is cleared. Nothing in the control panel can read it back.
  async function saveToken(ev: SubmitEvent) {
    ev.preventDefault();
    const value = tokenInput?.value ?? "";
    if (!value) return;
    busy = true;
    try {
      const res = await withConfirmation((tok) => api().setTunnelToken(value, tok));
      secret = res.secrets.find((s) => s.name === "tunnel_token");
      toastDone(t("settings.tokenSaved"));
      await refreshStatus();
    } catch (e) {
      toastError(e, t("error.generic"));
    } finally {
      if (tokenInput) tokenInput.value = "";
      busy = false;
    }
  }

  async function setSignIn(on: boolean) {
    try {
      await api().setStartAtSignIn(on);
      signIn = on;
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  async function setOffline(off: boolean) {
    try {
      applyConfig(await api().setOffline(off));
      await refreshStatus();
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  // The update check (ADR-0004). Turning it off is a weakening change: the
  // supervisor asks for confirmation with its own sentence (S-32).
  async function setUpdateCheck(on: boolean) {
    try {
      applyConfig(await withConfirmation((tok) => api().setUpdateCheck(on, tok)));
      await refreshStatus();
    } catch (e) {
      if (!(e instanceof Declined)) toastError(e, t("error.generic"));
    }
  }

  async function checkNow() {
    try {
      await api().checkForUpdates();
      await refreshStatus();
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  // Install update and Repair raise the Windows prompt (S-64, ADR-0010).
  async function runSetup(action: "apply-update" | "repair", success: string) {
    busy = true;
    try {
      const r = await api().runSetup(action);
      if (setupOK(r)) {
        toastDone(success);
        await refreshStatus();
      } else {
        toastError(new Error(setupProblem(r)), setupProblem(r));
      }
    } catch (e) {
      toastError(e, t("setup.code.1"));
    } finally {
      busy = false;
    }
  }

  const update = $derived(app.status?.update);
  const checkOn = $derived(!(app.config?.updates?.off ?? false));

  async function copyServiceUrl() {
    if (app.status && (await api().copyText(app.status.tunnel.service_url))) toastDone(t("common.copied"));
  }
</script>

<main class="screen">
  <div class="screen-head">
    <h1>{t("settings.title")}</h1>
  </div>
  <div class="checklist-scroll">
    <section class="group" aria-labelledby="s-tunnel">
      <h2 id="s-tunnel">{t("settings.tunnel")}</h2>
      <div class="panel">
        <p class="check-what">{t("settings.tunnelIntro")}</p>
        <p>{secret?.set ? t("settings.tokenSet", { date: dateTime(secret.set_at ?? "") }) : t("settings.tokenNotSet")}</p>
        <form class="form-row" onsubmit={saveToken}>
          <label class="visually-hidden" for="s-token">{t("settings.tokenLabel")}</label>
          <input
            id="s-token"
            class="input-text input-token mono"
            type="password"
            autocomplete="off"
            spellcheck="false"
            bind:this={tokenInput}
          />
          <button class="button button-primary" type="submit" disabled={busy}><Icon name="key" />{secret?.set ? t("settings.replaceToken") : t("settings.saveToken")}</button>
        </form>
        <div class="actions">
          <button class="button button-subtle" type="button" onclick={() => api().openKnownLink("tunnel-token-help")}><Icon name="open" />{t("settings.tokenHelp")}</button>
          <button class="button button-subtle" type="button" onclick={() => api().openKnownLink("cloudflare-dashboard")}><Icon name="open" />{t("settings.dashboard")}</button>
        </div>
        {#if app.status?.tunnel.service_url}
          <p class="check-what">{t("settings.serviceUrl")}</p>
          <div class="form-row">
            <code class="code-block"><VisibleText text={app.status.tunnel.service_url} /></code>
            <button class="button" type="button" onclick={copyServiceUrl}><Icon name="copy" />{t("settings.copyServiceUrl")}</button>
          </div>
        {/if}
      </div>
    </section>

    <section class="group" aria-labelledby="s-running">
      <h2 id="s-running" class="visually-hidden">{t("settings.signIn")}</h2>
      <ul class="checklist">
        <li class="check check-setting">
          <div>
            <p class="check-name" id="s-signin">{t("settings.signIn")}</p>
            <p class="check-what">{t("settings.signInHelp")}</p>
          </div>
          <Switch checked={signIn} label={t("settings.signIn")} onchange={setSignIn} />
        </li>
        <li class="check check-setting">
          <div>
            <p class="check-name">{t("settings.offline")}</p>
            <p class="check-what">{t("settings.offlineHelp")}</p>
          </div>
          <Switch checked={app.status?.tunnel.offline ?? false} label={t("settings.offline")} disabled={!app.status} onchange={setOffline} />
        </li>
      </ul>
    </section>

    <section class="group" aria-labelledby="s-updates">
      <h2 id="s-updates">{t("settings.updates")}</h2>
      <div class="panel">
        <p role="status">{updateLine(update)}</p>
        {#if update?.state === "ready"}
          <p class="check-what">{t("settings.installHelp")}</p>
        {/if}
        <div class="actions">
          {#if update?.state === "ready"}
            <button class="button button-primary" type="button" disabled={busy} onclick={() => runSetup("apply-update", t("settings.updateInstalled"))}>{t("settings.installUpdate")}</button>
          {/if}
          <button
            class="button"
            type="button"
            disabled={busy || !checkOn || update?.state === "off" || update?.state === "checking" || update?.state === "downloading"}
            onclick={checkNow}><Icon name="refresh" />{t("settings.checkNow")}</button
          >
        </div>
      </div>
      <ul class="checklist">
        <li class="check check-setting">
          <div>
            <p class="check-name">{t("settings.updatesCheck")}</p>
            <p class="check-what">{t("settings.updatesCheckHelp")}</p>
          </div>
          <Switch checked={checkOn} label={t("settings.updatesCheck")} disabled={!app.config} onchange={setUpdateCheck} />
        </li>
      </ul>
    </section>

    <section class="group" aria-labelledby="s-about">
      <h2 id="s-about">{t("settings.about")}</h2>
      <div class="panel">
        <p>{versionLabel(app.version)}</p>
        {#if app.status?.tunnel.repair_needed}
          <p class="form-problem"><Icon name="status-danger" /><span>{t("settings.repair")}</span></p>
          <div class="actions">
            <button class="button button-primary" type="button" disabled={busy} onclick={() => runSetup("repair", t("settings.repaired"))}><Icon name="refresh" />{t("settings.repairGo")}</button>
          </div>
        {/if}
        <div class="actions">
          <button class="button button-subtle" type="button" onclick={() => api().openKnownLink("project")}><Icon name="open" />{t("settings.project")}</button>
          <button class="button button-subtle" type="button" onclick={() => api().openKnownLink("security-policy")}><Icon name="open" />{t("settings.securityPolicy")}</button>
        </div>
        <h3 class="subhead">{t("settings.outbound")}</h3>
        <ul class="outbound check-what">
          <li>{t("security.outbound.tunnel")}</li>
          <li>{t("security.outbound.updates")}</li>
        </ul>
        <p class="check-what">{t("security.outbound.none")}</p>
        <h3 class="subhead">{t("settings.licences")}</h3>
        <p class="check-what">{t("settings.licencesIntro")}</p>
        <ul class="licences small">
          {#each licences as l (l.name)}
            <li><span>{l.name}</span> <span class="secondary">{l.licence}</span></li>
          {/each}
        </ul>
      </div>
    </section>
  </div>
</main>
