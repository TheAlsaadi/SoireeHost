import { mount } from "svelte";
import App from "./App.svelte";
import { bindingsApi, setApi, type Api } from "./lib/api";
import "./styles/tokens.css";
import "./styles/app.css";
import "./styles/components.css";

async function start(): Promise<void> {
  const target = document.getElementById("app");
  if (!target) {
    throw new Error("missing #app element");
  }
  let api: Api;
  // The fake supervisor exists only in the Vite development server, and only
  // when asked for (VITE_FAKE=1): in a release build import.meta.env.DEV is
  // false, so this branch and the fake module are left out of the bundle
  // (checked by build/check-bundle.mjs).
  if (import.meta.env.DEV && import.meta.env.VITE_FAKE === "1") {
    api = (await import("./lib/fake")).fakeApi();
  } else {
    api = await bindingsApi();
  }
  setApi(api);
  mount(App, { target });
}

void start();
