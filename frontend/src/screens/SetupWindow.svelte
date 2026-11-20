<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import { api, type gui } from "../lib/api";
  import { t } from "../lib/i18n";
  import { setupOK, setupProblem } from "../lib/setup";

  // The windows of the setup role (ADR-0010): install from a downloaded copy,
  // upgrade or open the installed copy, and uninstall from Settings > Apps.
  // Every action raises the Windows prompt through Setup.Run with an action
  // from a closed set; nothing here passes a path or a command.
  let { info }: { info: gui.SetupState } = $props();

  let busy = $state(false);
  let problem = $state("");
  let done = $state("");
  let purge = $state(false);
  let heading: HTMLHeadingElement | undefined = $state();

  $effect(() => {
    heading?.focus();
  });

  const changes = [
    "setup.change.program",
    "setup.change.services",
    "setup.change.firewall",
    "setup.change.data",
    "setup.change.apps",
    "setup.change.signIn",
  ] as const;

  async function run(action: "install" | "uninstall" | "uninstall-purge", success: string) {
    busy = true;
    problem = "";
    try {
      const r = await api().runSetup(action);
      if (setupOK(r)) {
        done = success;
      } else {
        problem = setupProblem(r);
        // uninstalled, but the data folder was kept: still done
        if (r.code === 30) done = problem;
      }
    } catch {
      problem = t("setup.code.1");
    } finally {
      busy = false;
    }
  }
</script>

<main class="screen first-run setup-window">
  {#if info.mode === "uninstall"}
    <div class="screen-head">
      <h1 tabindex="-1" bind:this={heading}>{t("setup.uninstall.title")}</h1>
    </div>
    <div class="panel first-panel">
      {#if done}
        <p role="status">{done}</p>
        <div class="actions">
          <button class="button button-primary" type="button" onclick={() => api().closeSetup()}>{t("setup.close")}</button>
        </div>
      {:else}
        <p>{t("setup.uninstall.lead")}</p>
        <label class="choice"><input type="checkbox" bind:checked={purge} disabled={busy} />{t("setup.uninstall.purge")}</label>
        <p class="check-what">{t("setup.uninstall.purgeHelp")}</p>
        <p class="check-what">{t("setup.install.prompt")}</p>
        {#if problem}
          <p class="form-problem" role="alert"><Icon name="status-danger" /><span>{problem}</span></p>
        {/if}
        <div class="actions">
          <button class="button" type="button" disabled={busy} onclick={() => api().closeSetup()}>{t("setup.close")}</button>
          <button class="button button-primary" type="button" disabled={busy} onclick={() => run(purge ? "uninstall-purge" : "uninstall", t("setup.uninstall.done"))}>
            <Icon name="delete" />{busy ? t("setup.uninstall.busy") : t("setup.uninstall.go")}
          </button>
        </div>
      {/if}
    </div>
  {:else if info.mode === "other_copy"}
    <div class="screen-head">
      <h1 tabindex="-1" bind:this={heading}>{t("setup.other.title")}</h1>
    </div>
    <div class="panel first-panel">
      <p>
        {info.installed_version
          ? t("setup.other.versions", { this: info.this_version, installed: info.installed_version })
          : t("setup.other.thisOnly", { this: info.this_version })}
      </p>
      {#if done}
        <p role="status">{done}</p>
      {:else}
        {#if !info.newer}
          <p class="check-what">{t("setup.other.older")}</p>
        {:else}
          <p class="check-what">{t("setup.install.prompt")}</p>
        {/if}
        {#if problem}
          <p class="form-problem" role="alert"><Icon name="status-danger" /><span>{problem}</span></p>
        {/if}
        <div class="actions">
          <button class="button" class:button-primary={!info.newer} type="button" disabled={busy} onclick={() => api().openInstalled()}>
            <Icon name="open" />{t("setup.other.open")}
          </button>
          {#if info.newer}
            <button class="button button-primary" type="button" disabled={busy} onclick={() => run("install", t("setup.install.done"))}>
              <Icon name="refresh" />{busy ? t("setup.install.busy") : t("setup.other.upgrade", { v: info.this_version })}
            </button>
          {/if}
        </div>
      {/if}
    </div>
  {:else}
    <div class="screen-head">
      <h1 tabindex="-1" bind:this={heading}>{t("setup.install.title")}</h1>
    </div>
    <div class="panel first-panel">
      {#if done}
        <p role="status">{done}</p>
      {:else}
        <p>{t("setup.install.lead")}</p>
        <ul class="confirm-list">
          {#each changes as key (key)}
            <li>{t(key)}</li>
          {/each}
        </ul>
        <p class="check-what">{t("setup.install.prompt")}</p>
        {#if problem}
          <p class="form-problem" role="alert"><Icon name="status-danger" /><span>{problem}</span></p>
        {/if}
        <div class="actions">
          <button class="button" type="button" disabled={busy} onclick={() => api().closeSetup()}>{t("setup.close")}</button>
          <button class="button button-primary" type="button" disabled={busy} onclick={() => run("install", t("setup.install.done"))}>
            <Icon name="add" />{busy ? t("setup.install.busy") : t("setup.install.go")}
          </button>
        </div>
      {/if}
    </div>
  {/if}
</main>
