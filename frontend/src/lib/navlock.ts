// Navigation lock for drops (S-33). Dropping a link or text on the window
// would make WebView2 navigate to it; only file drops, which Wails handles
// for the folder pickers, are let through.
export function blockNonFileDrop(e: DragEvent): void {
  if (e.dataTransfer?.types.includes("Files")) return;
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = "none";
}
