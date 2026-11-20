// One interface over the Go bindings, so screens and tests can use a stand-in.
// In a release build only the real bindings exist: the fake transport is
// loaded only by the Vite development server with VITE_FAKE=1, and the build
// check refuses a bundle that contains it (ADR-0009).

import type * as ipc from "../../bindings/github.com/TheAlsaadi/SoireeHost/internal/ipc/models";
import type * as config from "../../bindings/github.com/TheAlsaadi/SoireeHost/internal/config/models";
import type * as gui from "../../bindings/github.com/TheAlsaadi/SoireeHost/internal/gui/models";

export type { ipc, config, gui };

export interface Api {
  version(): Promise<string>;
  status(): Promise<ipc.StatusResult>;
  config(): Promise<ipc.ConfigResult>;
  putSite(site: config.Site, confirmation: string): Promise<ipc.ConfigResult>;
  setSiteEnabled(id: string, enabled: boolean, confirmation: string): Promise<ipc.ConfigResult>;
  removeSite(id: string): Promise<ipc.ConfigResult>;
  startQuickShare(id: string): Promise<ipc.ConfigResult>;
  stopQuickShare(id: string): Promise<ipc.ConfigResult>;
  setOffline(offline: boolean): Promise<ipc.ConfigResult>;
  activity(p: ipc.AccessListParams): Promise<ipc.AccessListResult>;
  auditList(p: ipc.AuditListParams): Promise<ipc.AuditListResult>;
  history(): Promise<ipc.HistoryResult>;
  rollback(revision: number, confirmation: string): Promise<ipc.ConfigResult>;
  secretStatus(): Promise<ipc.SecretStatusResult>;
  setTunnelToken(value: string, confirmation: string): Promise<ipc.SecretStatusResult>;
  exportConfig(): Promise<string>;
  importConfig(text: string): Promise<ipc.ConfigResult>;
  confirmImport(confirmation: string): Promise<ipc.ConfigResult>;
  chooseFolder(): Promise<string>;
  prepareFolder(path: string): Promise<string>;
  listeningPorts(): Promise<gui.Port[]>;
  qrCode(text: string): Promise<gui.QRCode>;
  openKnownLink(name: KnownLink): Promise<void>;
  openSiteAddress(address: string): Promise<void>;
  copyText(text: string): Promise<boolean>;
  saveExport(text: string): Promise<boolean>;
  openImport(): Promise<string>;
  startAtSignIn(): Promise<boolean>;
  setStartAtSignIn(on: boolean): Promise<void>;
  onFolderDropped(handler: (path: string) => void): () => void;
  checkForUpdates(): Promise<ipc.UpdateStatus>;
  setUpdateCheck(check: boolean, confirmation: string): Promise<ipc.ConfigResult>;
  setupState(): Promise<gui.SetupState>;
  runSetup(action: SetupAction): Promise<gui.SetupResult>;
  openInstalled(): Promise<void>;
  closeSetup(): Promise<void>;
}

/** The setup actions the control panel may start; the closed set of internal/gui. */
export type SetupAction = "install" | "repair" | "apply-update" | "uninstall" | "uninstall-purge";

export type KnownLink = "cloudflare-dashboard" | "tunnel-token-help" | "project" | "security-policy";

let current: Api | undefined;

/** The API in use. setApi replaces it (tests, the development fake). */
export function api(): Api {
  if (!current) throw new Error("API not set");
  return current;
}

export function setApi(a: Api): void {
  current = a;
}

/** The real bindings. Imported lazily so tests never load the runtime. */
export async function bindingsApi(): Promise<Api> {
  const [{ AppService, Control, Local, Setup }, { Events }] = await Promise.all([
    import("../../bindings/github.com/TheAlsaadi/SoireeHost/internal/gui"),
    import("@wailsio/runtime"),
  ]);
  return {
    version: () => AppService.Version(),
    status: () => Control.Status(),
    config: () => Control.Config(),
    putSite: (s, c) => Control.PutSite(s, c),
    setSiteEnabled: (id, on, c) => Control.SetSiteEnabled(id, on, c),
    removeSite: (id) => Control.RemoveSite(id),
    startQuickShare: (id) => Control.StartQuickShare(id),
    stopQuickShare: (id) => Control.StopQuickShare(id),
    setOffline: (o) => Control.SetOffline(o),
    activity: (p) => Control.Activity(p),
    auditList: (p) => Control.AuditList(p),
    history: () => Control.History(),
    rollback: (r, c) => Control.Rollback(r, c),
    secretStatus: () => Control.SecretStatus(),
    setTunnelToken: (v, c) => Control.SetTunnelToken(v, c),
    exportConfig: () => Control.ExportConfig(),
    importConfig: (t) => Control.ImportConfig(t),
    confirmImport: (c) => Control.ConfirmImport(c),
    chooseFolder: () => Local.ChooseFolder(),
    prepareFolder: (p) => Local.PrepareFolder(p),
    listeningPorts: () => Local.ListeningPorts(),
    qrCode: (t) => Local.QRCode(t),
    openKnownLink: (n) => Local.OpenKnownLink(n),
    openSiteAddress: (a) => Local.OpenSiteAddress(a),
    copyText: (t) => Local.CopyText(t),
    saveExport: (t) => Local.SaveExport(t),
    openImport: () => Local.OpenImport(),
    startAtSignIn: () => Local.StartAtSignIn(),
    setStartAtSignIn: (on) => Local.SetStartAtSignIn(on),
    onFolderDropped: (h) =>
      Events.On("folder-dropped", (ev: { data: unknown }) => {
        if (typeof ev.data === "string") h(ev.data);
      }),
    checkForUpdates: () => Control.CheckForUpdates(),
    setUpdateCheck: (on, c) => Control.SetUpdateCheck(on, c),
    setupState: () => Setup.State(),
    runSetup: (a) => Setup.Run(a),
    openInstalled: () => Setup.OpenInstalled(),
    closeSetup: () => Setup.Close(),
  };
}
