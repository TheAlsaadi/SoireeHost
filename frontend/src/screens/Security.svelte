<script lang="ts">
  import Icon from "../components/Icon.svelte";
  import StatusMark from "../components/StatusMark.svelte";
  import VisibleText from "../components/VisibleText.svelte";
  import { api, type ipc } from "../lib/api";
  import { t } from "../lib/i18n";
  import { app } from "../lib/state.svelte";
  import { dateTime, type Tone } from "../lib/status";
  import type { Screen } from "../lib/nav";

  // A checklist of real protections with their actual state (plan section
  // 7): no score, no gauge. States come from the supervisor's answers.
  let { go }: { go: (s: Screen, siteId?: string) => void } = $props();

  let secret = $state<ipc.SecretStatus | undefined>();
  let audit = $state<{ ok: boolean; n: number } | undefined>();

  $effect(() => {
    api()
      .secretStatus()
      .then((r) => (secret = r.secrets.find((s) => s.name === "tunnel_token")))
      .catch(() => {});
    api()
      .auditList({ after: 0, limit: 1 })
      .then((r) => (audit = { ok: (r.report.breaks ?? []).length === 0, n: r.report.entries }))
      .catch(() => {});
  });

  const sites = $derived(app.config?.sites ?? []);
  const fwExceptions = $derived(sites.filter((s) => s.firewall.mode === "detect" || s.firewall.mode === "off"));
  const lanSites = $derived(sites.filter((s) => s.proxy?.allow_lan));
  const headerSites = $derived(sites.filter((s) => (s.remove_headers ?? []).length > 0));
  const repair = $derived(app.status?.tunnel.repair_needed ?? false);

  function stateOf(on: boolean, exceptions = 0): { tone: Tone; text: string } {
    if (!on) return { tone: "off", text: t("security.state.off") };
    if (exceptions > 0) return { tone: "warning", text: t("security.state.exceptions", { n: exceptions }) };
    return { tone: "ok", text: t("security.state.on") };
  }
  const on = { tone: "ok" as Tone, text: t("security.state.on") };
</script>

<main class="screen">
  <div class="screen-head">
    <h1>{t("security.title")}</h1>
  </div>
  <p class="screen-intro">{t("security.intro")}</p>

  <div class="checklist-scroll">
    <section class="group" aria-labelledby="g-reach">
      <h2 id="g-reach">{t("security.group.reach")}</h2>
      <ul class="checklist">
        {@render check(on, "security.ports.name", t("security.ports.what"))}
        {@render check(on, "security.fw.name", t("security.fw.what"))}
        {@render check(
          repair ? { tone: "danger", text: t("security.state.repair") } : on,
          "security.cloudflared.name",
          repair ? t("security.cloudflared.bad") : t("security.cloudflared.what"),
        )}
        {@render check(on, "security.hosts.name", t("security.hosts.what"))}
      </ul>
    </section>

    <section class="group" aria-labelledby="g-requests">
      <h2 id="g-requests">{t("security.group.requests")}</h2>
      <ul class="checklist">
        <li class="check">
          <StatusMark {...stateOf(true, fwExceptions.length)} />
          <div>
            <p class="check-name">{t("security.waf.name")}</p>
            <p class="check-what">{t("security.waf.what")}</p>
            {#if fwExceptions.length}
              <ul class="exceptions">
                {#each fwExceptions as s (s.id)}
                  <li>
                    <Icon name="status-warning" />
                    <span><VisibleText text={s.firewall.mode === "off" ? t("security.waf.off", { name: s.name }) : t("security.waf.detect", { name: s.name })} /></span>
                    <button class="button button-subtle" type="button" onclick={() => go("sites", s.id)}>{t("security.openSite", { name: s.name })}</button>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </li>
        {@render check(on, "security.rate.name", t("security.rate.what"))}
        {@render check(on, "security.files.name", t("security.files.what"))}
        {@render check(stateOf(true, headerSites.length), "security.headers.name", t("security.headers.what"))}
        {@render check(stateOf(true, lanSites.length), "security.lan.name", t("security.lan.what"))}
      </ul>
      {#if app.warnings.length}
        <h3 class="subhead group-sub">{t("security.weakened")}</h3>
        <ul class="exceptions warnings-list">
          {#each app.warnings as w, i (i)}
            <li><Icon name="status-warning" /><span><VisibleText text={w} /></span></li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="group" aria-labelledby="g-settings">
      <h2 id="g-settings">{t("security.group.settings")}</h2>
      <ul class="checklist">
        <li class="check">
          <StatusMark {...secret?.set ? on : { tone: "off" as Tone, text: t("security.state.notSet") }} />
          <div>
            <p class="check-name">{t("security.token.name")}</p>
            <p class="check-what">
              {t("security.token.what")}
              {#if secret?.set && secret.set_at}{t("security.token.setOn", { date: dateTime(secret.set_at) })}{/if}
            </p>
          </div>
          {#if !secret?.set}
            <button class="button" type="button" onclick={() => go("settings")}>{t("security.token.setUp")}</button>
          {/if}
        </li>
        {@render check(on, "security.config.name", t("security.config.what"))}
        {@render check(on, "security.isolation.name", t("security.isolation.what"))}
        <li class="check">
          <StatusMark
            {...audit && !audit.ok
              ? { tone: "danger" as Tone, text: t("security.state.broken") }
              : { tone: "ok" as Tone, text: t("security.state.intact") }}
          />
          <div>
            <p class="check-name">{t("security.audit.name")}</p>
            <p class="check-what">
              {t("security.audit.what")}
              {#if audit}{audit.ok ? t("security.audit.ok", { n: audit.n }) : t("security.audit.bad")}{/if}
            </p>
          </div>
          <button class="button" type="button" onclick={() => go("backups")}>{t("security.audit.view")}</button>
        </li>
      </ul>
    </section>

    <section class="group" aria-labelledby="g-outbound">
      <h2 id="g-outbound">{t("security.group.outbound")}</h2>
      <ul class="checklist">
        <li class="check">
          <span class="status"><Icon name="cloud" />{t("security.state.count", { n: 2 })}</span>
          <div>
            <p class="check-name">{t("security.outbound.name")}</p>
            <ul class="outbound check-what">
              <li>{t("security.outbound.tunnel")}</li>
              <li>{t("security.outbound.updates")}</li>
            </ul>
            <p class="check-what">{t("security.outbound.none")}</p>
          </div>
        </li>
      </ul>
    </section>
  </div>
</main>

{#snippet check(s: { tone: Tone; text: string }, name: "security.ports.name" | "security.fw.name" | "security.cloudflared.name" | "security.hosts.name" | "security.rate.name" | "security.files.name" | "security.headers.name" | "security.lan.name" | "security.config.name" | "security.isolation.name", what: string)}
  <li class="check">
    <StatusMark tone={s.tone} text={s.text} />
    <div>
      <p class="check-name">{t(name)}</p>
      <p class="check-what">{what}</p>
    </div>
  </li>
{/snippet}
