<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import EmptyState from "../components/EmptyState.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type ipc } from "../lib/api";
  import { t, type MessageKey } from "../lib/i18n";
  import { app, toastError } from "../lib/state.svelte";
  import { clockSeconds, dateTime } from "../lib/status";

  // S-34: every field of every entry is attacker-controlled. All of it is
  // rendered through VisibleText (text interpolation, hidden characters as
  // markers); nothing from an entry is ever put into an attribute except
  // through Svelte's attribute binding, and never into HTML.

  const MAX_ROWS = 1000;
  // Entries are never changed in place, so they are kept raw: each one is
  // the same object for as long as it is listed, and its id stays put when
  // newer requests arrive above it.
  let entries = $state.raw<ipc.AccessEntry[]>([]);
  let siteFilter = $state("");
  let classFilter = $state("");
  let timeFilter = $state("1h");
  let search = $state("");
  let paused = $state(false);
  let more = $state(false);
  let skipped = $state(0);
  let loaded = $state(false);
  let selectedKey = $state("");

  const ids = new WeakMap<ipc.AccessEntry, string>();
  let nextId = 1;
  function keyOf(e: ipc.AccessEntry): string {
    let id = ids.get(e);
    if (!id) {
      id = String(nextId++);
      ids.set(e, id);
    }
    return id;
  }

  function since(): string | undefined {
    const span: Record<string, number> = { "15m": 15, "1h": 60, "24h": 1440 };
    const m = span[timeFilter];
    return m ? new Date(Date.now() - m * 60_000).toISOString() : undefined;
  }

  function params(extra: Partial<ipc.AccessListParams>): ipc.AccessListParams {
    return { site_id: siteFilter, class: classFilter, limit: 200, after: since(), ...extra };
  }

  async function reload() {
    try {
      const res = await api().activity(params({}));
      entries = res.entries;
      more = res.more;
      skipped = res.skipped;
      loaded = true;
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  async function poll() {
    if (paused || document.visibilityState === "hidden") return;
    const newest = entries[0]?.time;
    try {
      const res = await api().activity(params(newest ? { after: newest } : {}));
      if (res.entries.length) entries = [...res.entries, ...entries].slice(0, MAX_ROWS);
      skipped += res.skipped;
      loaded = true;
    } catch {
      // the status line already says when the service is not answering
    }
  }

  async function older() {
    const oldest = entries[entries.length - 1]?.time;
    if (!oldest) return;
    try {
      const res = await api().activity(params({ before: oldest }));
      entries = [...entries, ...res.entries].slice(0, MAX_ROWS);
      more = res.more;
    } catch (e) {
      toastError(e, t("error.generic"));
    }
  }

  $effect(() => {
    void siteFilter;
    void classFilter;
    void timeFilter;
    void reload();
  });

  $effect(() => {
    const timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  });

  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((e) => e.uri.toLowerCase().includes(q) || (e.client_ip ?? "").includes(q) || e.host.includes(q));
  });
  const selected = $derived(shown.find((e) => keyOf(e) === selectedKey));
  const siteName = (id?: string) => app.config?.sites.find((s) => s.id === id)?.name ?? t("activity.unknownSite");

  function resultText(e: ipc.AccessEntry): string {
    if (e.firewall?.action === "blocked") return t("activity.blocked");
    if (e.firewall?.action === "detected") return t("activity.detected", { status: e.status });
    if (e.status === 502 || e.status === 504) return t("activity.noAnswer", { status: e.status });
    return String(e.status);
  }

  function onRowKey(ev: KeyboardEvent, i: number) {
    let next: number;
    if (ev.key === "ArrowDown") next = Math.min(i + 1, shown.length - 1);
    else if (ev.key === "ArrowUp") next = Math.max(i - 1, 0);
    else if (ev.key === "Escape") return void (selectedKey = "");
    else if (ev.key === "Enter") {
      const row = shown[i];
      if (row) selectedKey = keyOf(row);
      return;
    } else return;
    ev.preventDefault();
    const target = shown[next];
    if (!target) return;
    selectedKey = keyOf(target);
    ((ev.currentTarget as HTMLElement).parentElement?.children[next] as HTMLElement | undefined)?.focus();
  }

  const classes: { v: string; k: MessageKey }[] = [
    { v: "", k: "activity.result.all" },
    { v: "ok", k: "activity.result.ok" },
    { v: "client_error", k: "activity.result.client_error" },
    { v: "server_error", k: "activity.result.server_error" },
    { v: "blocked", k: "activity.result.blocked" },
  ];
  const times: { v: string; k: MessageKey }[] = [
    { v: "15m", k: "activity.time.15m" },
    { v: "1h", k: "activity.time.1h" },
    { v: "24h", k: "activity.time.24h" },
    { v: "all", k: "activity.time.all" },
  ];
</script>

<main class="screen">
  <div class="screen-head">
    <h1>{t("activity.title")}</h1>
    <p class="live small">{paused ? t("activity.paused") : t("activity.live")}</p>
    <button class="button" type="button" aria-pressed={paused} onclick={() => (paused = !paused)}>
      {paused ? t("activity.resume") : t("activity.pause")}
    </button>
  </div>

  <form class="filters" aria-label={t("activity.filter")} onsubmit={(e) => e.preventDefault()}>
    <div class="field">
      <label for="f-site">{t("activity.site")}</label>
      <select id="f-site" class="select-native" bind:value={siteFilter}>
        <option value="">{t("activity.allSites")}</option>
        {#each app.config?.sites ?? [] as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
      </select>
    </div>
    <div class="field">
      <label for="f-result">{t("activity.result")}</label>
      <select id="f-result" class="select-native" bind:value={classFilter}>
        {#each classes as c (c.v)}<option value={c.v}>{t(c.k)}</option>{/each}
      </select>
    </div>
    <div class="field">
      <label for="f-time">{t("activity.time")}</label>
      <select id="f-time" class="select-native" bind:value={timeFilter}>
        {#each times as c (c.v)}<option value={c.v}>{t(c.k)}</option>{/each}
      </select>
    </div>
    <div class="field">
      <label for="f-search">{t("activity.search")}</label>
      <span class="input"><Icon name="search" /><input id="f-search" class="input-bare" type="search" placeholder={t("activity.searchPlaceholder")} bind:value={search} /></span>
    </div>
  </form>

  {#if loaded && shown.length === 0}
    <EmptyState text={entries.length === 0 && !search ? t("activity.empty") : t("activity.emptyFiltered")} />
  {:else}
    <div class="split" class:split-single={!selected}>
      <div class="list-region">
        <table class="table log table-fixed" role="grid" aria-label={t("activity.list")}>
          <colgroup><col class="col-time" /><col class="col-site" /><col class="col-result" /><col /><col class="col-visitor" /></colgroup>
          <thead>
            <tr>
              <th scope="col">{t("activity.col.time")}</th>
              <th scope="col">{t("activity.col.site")}</th>
              <th scope="col">{t("activity.col.result")}</th>
              <th scope="col">{t("activity.col.request")}</th>
              <th scope="col" class="cell-visitor">{t("activity.col.visitor")}</th>
            </tr>
          </thead>
          <tbody>
            {#each shown as e, i (keyOf(e))}
              {@const blocked = e.firewall?.action === "blocked"}
              {@const flagged = !!e.firewall}
              <tr
                class:is-blocked={blocked}
                aria-selected={keyOf(e) === selectedKey}
                tabindex={keyOf(e) === selectedKey || (!selectedKey && i === 0) ? 0 : -1}
                onclick={() => (selectedKey = keyOf(e))}
                onkeydown={(ev) => onRowKey(ev, i)}
              >
                <td class="mono">{clockSeconds(e.time)}</td>
                <td class="cell-truncate"><VisibleText text={siteName(e.site_id)} max={40} /></td>
                <td class="result" class:result-warning={!blocked && (flagged || e.status >= 500)}>
                  <span class="status">
                    {#if blocked}<Icon name="blocked" />{:else if flagged || e.status >= 500}<Icon name="status-warning" />{:else}<span class="mark-space"></span>{/if}
                    {resultText(e)}
                  </span>
                </td>
                <td class="cell-truncate mono"><VisibleText text={e.method + " " + e.uri} max={160} /></td>
                <td class="mono cell-visitor"><VisibleText text={e.client_ip ?? ""} /></td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if more}
          <div class="list-foot"><button class="button" type="button" onclick={older}>{t("activity.older")}</button></div>
        {/if}
        {#if skipped > 0}
          <p class="list-foot small secondary">{t("activity.skipped", { n: skipped })}</p>
        {/if}
      </div>

      {#if selected}
        <aside class="pane" aria-labelledby="req-title">
          <div class="pane-head">
            <h2 id="req-title">
              {selected.firewall?.action === "blocked"
                ? t("activity.detail.blocked")
                : selected.firewall
                  ? t("activity.detail.detected")
                  : t("activity.detail.request")}
            </h2>
            <button class="button button-subtle button-icon" type="button" aria-label={t("common.closeDetails")} onclick={() => (selectedKey = "")}>
              <Icon name="dismiss" />
            </button>
          </div>
          {#if selected.firewall?.action === "blocked"}
            <p class="health status-danger"><Icon name="blocked" /><span>{t("activity.detail.blockedLine")}</span></p>
          {:else if selected.firewall}
            <p class="health status-warning"><Icon name="status-warning" /><span>{t("activity.detail.detectedLine")}</span></p>
          {:else}
            <p class="health status-off"><span class="mark-space"></span><span>{t("activity.detail.okLine", { status: selected.status })}</span></p>
          {/if}

          {#if selected.firewall}
            <section class="pane-section" aria-labelledby="h-rules">
              <h3 id="h-rules">{t("activity.detail.rules")}</h3>
              <dl class="facts">
                {#each selected.firewall.rules as r (r.id)}
                  <dt class="mono">{r.id}</dt>
                  <dd>
                    <VisibleText text={r.msg} />
                    {#if r.where?.length}<br /><span class="secondary small">{t("activity.detail.where", { where: r.where.join(", ") })}</span>{/if}
                  </dd>
                {/each}
              </dl>
            </section>
          {/if}

          <section class="pane-section" aria-labelledby="h-request">
            <h3 id="h-request">{t("activity.detail.request")}</h3>
            <dl class="facts">
              <dt>{t("activity.detail.time")}</dt>
              <dd>{dateTime(selected.time)}</dd>
              <dt>{t("activity.detail.site")}</dt>
              <dd><VisibleText text={siteName(selected.site_id)} /></dd>
              <dt>{t("activity.detail.host")}</dt>
              <dd class="mono small"><VisibleText text={selected.host} /></dd>
              <dt>{t("activity.detail.method")}</dt>
              <dd class="mono small"><VisibleText text={selected.method} /></dd>
              <dt>{t("activity.detail.status")}</dt>
              <dd class="mono small">{selected.status}</dd>
              <dt>{t("activity.detail.visitor")}</dt>
              <dd class="mono small"><VisibleText text={selected.client_ip ?? ""} /></dd>
            </dl>
            <h3 class="subhead">{t("activity.detail.path")}</h3>
            <p class="code-block" data-testid="detail-path"><VisibleText text={selected.uri} /></p>
            {#if selected.user_agent}
              <h3 class="subhead">{t("activity.detail.agent")}</h3>
              <p class="code-block" data-testid="detail-agent"><VisibleText text={selected.user_agent} /></p>
            {/if}
            {#if selected.referer}
              <h3 class="subhead">{t("activity.detail.referer")}</h3>
              <p class="code-block"><VisibleText text={selected.referer} /></p>
            {/if}
            <p class="note"><Icon name="info" />{t("activity.detail.textNote")}</p>
          </section>
        </aside>
      {/if}
    </div>
  {/if}
</main>
