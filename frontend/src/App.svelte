<script lang="ts">
  import { onMount } from "svelte";
  import Rail from "./components/Rail.svelte";
  import StatusLine from "./components/StatusLine.svelte";
  import ConfirmDialog from "./components/ConfirmDialog.svelte";
  import Toasts from "./components/Toasts.svelte";
  import Sites from "./screens/Sites.svelte";
  import Activity from "./screens/Activity.svelte";
  import Security from "./screens/Security.svelte";
  import Backups from "./screens/Backups.svelte";
  import Settings from "./screens/Settings.svelte";
  import FirstRun from "./screens/FirstRun.svelte";
  import SetupWindow from "./screens/SetupWindow.svelte";
  import { api, type gui } from "./lib/api";
  import { app, startPolling } from "./lib/state.svelte";
  import type { Screen } from "./lib/nav";

  let screen = $state<Screen>("sites");
  let firstRunDone = $state(false);
  let dropped = $state("");
  // install, upgrade and uninstall windows (ADR-0010); undefined until known
  let setup = $state<gui.SetupState | undefined>();

  const showFirstRun = $derived(!firstRunDone && !!app.config && app.config.sites.length === 0 && !app.failed);

  onMount(() => {
    let stop = () => {};
    api()
      .setupState()
      .then((s) => {
        setup = s;
        // only the installed control panel talks to the supervisor
        if (s.mode === "installed") stop = startPolling();
      })
      .catch(() => {
        setup = { mode: "installed", installed_version: "", this_version: "", newer: false };
        stop = startPolling();
      });
    api()
      .version()
      .then((v) => (app.version = v))
      .catch(() => {});
    // A folder dropped on the window starts adding a site (plan section 6);
    // the path is checked like a chosen folder before anything changes.
    const off = api().onFolderDropped((path) => {
      screen = "sites";
      dropped = path;
    });
    // Navigation lock, inside the page (S-33): Wails v3.1.0 exposes no way
    // to cancel a WebView2 navigation, so no link may leave the app. The UI
    // has no external links; outside pages open through OpenKnownLink.
    const guard = (e: MouseEvent) => {
      const a = (e.target as Element | null)?.closest?.("a[href]");
      if (a) e.preventDefault();
    };
    document.addEventListener("click", guard, true);
    document.addEventListener("auxclick", guard, true);
    return () => {
      stop();
      off();
      document.removeEventListener("click", guard, true);
      document.removeEventListener("auxclick", guard, true);
    };
  });

  function go(s: Screen) {
    screen = s;
  }
</script>

{#if setup && setup.mode !== "installed"}
  <SetupWindow info={setup} />
{:else if setup}
  <div class="app">
    <Rail current={screen} onselect={go} />
    <div class="main">
      <StatusLine />
      {#if showFirstRun}
        <FirstRun initialFolder={dropped} ondone={() => (firstRunDone = true)} />
      {:else if screen === "sites"}
        <Sites bind:droppedFolder={dropped} />
      {:else if screen === "activity"}
        <Activity />
      {:else if screen === "security"}
        <Security {go} />
      {:else if screen === "backups"}
        <Backups />
      {:else}
        <Settings />
      {/if}
    </div>
  </div>
{/if}
<ConfirmDialog />
<Toasts />
