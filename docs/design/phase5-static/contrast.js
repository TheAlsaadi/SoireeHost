// Design preview only: draws the role swatches and measures WCAG contrast of
// the pairs the screens use, in whatever theme the page is showing.
// Builds every element with createElement/textContent (no HTML strings).
(() => {
  const roles = [
    "surface-window", "surface-main", "surface-raised", "surface-hover", "surface-selected",
    "surface-blocked", "text-primary", "text-secondary", "border-subtle", "border-control",
    "accent", "text-on-accent", "text-selected", "focus-ring", "switch-on", "status-ok", "status-warning",
    "status-danger", "status-off",
  ];
  // [foreground, background, minimum, what it is]
  const pairs = [
    ["text-primary", "surface-main", 4.5, "Body text"],
    ["text-primary", "surface-raised", 4.5, "Body text in lists"],
    ["text-secondary", "surface-main", 4.5, "Secondary text"],
    ["text-secondary", "surface-raised", 4.5, "Secondary text in lists"],
    ["text-secondary", "surface-window", 4.5, "Secondary text on the rail"],
    ["text-selected", "surface-selected", 4.5, "Selected row"],
    ["text-primary", "surface-blocked", 4.5, "Blocked log row"],
    ["text-on-accent", "accent", 4.5, "Primary button"],
    ["text-on-accent", "accent-hover", 4.5, "Primary button, hover"],
    ["focus-ring", "surface-main", 3, "Focus ring"],
    ["focus-ring", "surface-raised", 3, "Focus ring in lists"],
    ["border-control", "surface-raised", 3, "Control edges"],
    ["switch-on", "surface-raised", 3, "Switch, on"],
    ["status-ok", "surface-raised", 3, "OK icon"],
    ["status-warning", "surface-raised", 3, "Warning icon"],
    ["status-warning", "surface-main", 4.5, "Warning text"],
    ["status-danger", "surface-raised", 3, "Danger icon"],
    ["status-danger", "surface-blocked", 3, "Blocked icon on its row"],
    ["status-off", "surface-raised", 3, "Off icon"],
  ];

  const probe = document.createElement("div");
  document.body.append(probe);
  const resolve = (role) => {
    probe.style.color = `var(--${role})`;
    return getComputedStyle(probe).color;
  };
  const rgb = (s) => s.match(/[\d.]+/g).slice(0, 3).map(Number);
  const lum = ([r, g, b]) => {
    const f = (c) => {
      c /= 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const ratio = (a, b) => {
    const [x, y] = [lum(rgb(a)), lum(rgb(b))].sort((m, n) => n - m);
    return (x + 0.05) / (y + 0.05);
  };

  const sw = document.getElementById("swatches");
  for (const role of roles) {
    const box = document.createElement("div");
    box.className = "swatch";
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.style.background = `var(--${role})`;
    const name = document.createElement("span");
    name.className = "mono small";
    name.textContent = `--${role}`;
    const value = document.createElement("span");
    value.className = "mono small secondary";
    value.textContent = resolve(role);
    box.append(chip, name, value);
    sw.append(box);
  }

  const body = document.querySelector("#pairs tbody");
  for (const [fg, bg, min, what] of pairs) {
    const r = ratio(resolve(fg), resolve(bg));
    const tr = document.createElement("tr");
    const cells = [`${what}: --${fg}`, `--${bg}`, r.toFixed(2) + ":1", min + ":1", r >= min ? "Pass" : "Fail"];
    for (const text of cells) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.append(td);
    }
    if (r < min) tr.className = "fail";
    body.append(tr);
  }
  probe.remove();
})();
