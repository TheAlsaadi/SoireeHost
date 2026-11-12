<script lang="ts">
  import { onMount } from "svelte";
  import { AppService } from "../bindings/github.com/TheAlsaadi/SoireeHost/internal/gui";
  import { versionLabel } from "./lib/version";

  let label = $state("Version loading");

  onMount(() => {
    AppService.Version()
      .then((v) => {
        label = versionLabel(v);
      })
      .catch(() => {
        label = versionLabel(undefined);
      });
  });
</script>

<main>
  <h1>SoiréeHost</h1>
  <p>{label}</p>
</main>
