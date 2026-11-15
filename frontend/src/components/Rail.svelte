<script lang="ts">
  import Icon from "./Icon.svelte";
  import { t } from "../lib/i18n";
  import type { IconName } from "../lib/icons/icons";
  import type { MessageKey } from "../lib/i18n";
  import type { Screen } from "../lib/nav";

  let { current, onselect }: { current: Screen; onselect: (s: Screen) => void } = $props();

  const items: { id: Screen; icon: IconName; label: MessageKey }[] = [
    { id: "sites", icon: "sites", label: "nav.sites" },
    { id: "activity", icon: "activity", label: "nav.activity" },
    { id: "security", icon: "security", label: "nav.security" },
    { id: "backups", icon: "backups", label: "nav.backups" },
    { id: "settings", icon: "settings", label: "nav.settings" },
  ];
</script>

<nav class="rail" aria-label={t("nav.label")}>
  <p class="rail-name">{t("app.name")}</p>
  <ul>
    {#each items as item (item.id)}
      <li>
        <button
          class="rail-item"
          type="button"
          aria-current={current === item.id ? "page" : undefined}
          onclick={() => onselect(item.id)}
        >
          <Icon name={item.icon} large /><span class="rail-label">{t(item.label)}</span>
        </button>
      </li>
    {/each}
  </ul>
</nav>
