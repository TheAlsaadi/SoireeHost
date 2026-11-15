// Design preview only: ?theme=light|dark|contrast forces a theme so the
// screens can be compared side by side. The app follows the system setting.
const theme = new URLSearchParams(location.search).get("theme");
if (theme === "light" || theme === "dark" || theme === "contrast") {
  document.documentElement.dataset.theme = theme;
}
