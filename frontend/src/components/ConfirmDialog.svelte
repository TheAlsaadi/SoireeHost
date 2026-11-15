<script lang="ts">
  import Dialog from "./Dialog.svelte";
  import VisibleText from "./VisibleText.svelte";
  import { t } from "../lib/i18n";
  import { answerConfirmation, confirmation } from "../lib/state.svelte";

  // S-32: shows the supervisor's own sentences for a weakening change, as
  // text. The safe choice is the default button.
</script>

<Dialog open={confirmation.open} title={t("confirm.title")} onclose={() => answerConfirmation(false)}>
  <p class="dialog-lead">{t("confirm.lead")}</p>
  <ul class="confirm-list">
    {#each confirmation.sentences as s, i (i)}
      <li><VisibleText text={s} /></li>
    {/each}
  </ul>
  {#snippet actions()}
    <button class="button" type="button" onclick={() => answerConfirmation(true)}>{t("confirm.go")}</button>
    <!-- svelte-ignore a11y_autofocus -->
    <button class="button button-primary" type="button" autofocus onclick={() => answerConfirmation(false)}>{t("confirm.keep")}</button>
  {/snippet}
</Dialog>
