// Test cases for the ts-no-inner-html rule (S-34).

export function render(el: HTMLElement, host: string, list: HTMLElement[]): void {
  // ruleid: ts-no-inner-html
  el.innerHTML = host;
  // ruleid: ts-no-inner-html
  el.outerHTML = `<b>${host}</b>`;
  // ruleid: ts-no-inner-html
  el.innerHTML += "<br>";
  // ruleid: ts-no-inner-html
  el["innerHTML"] = host;
  // ruleid: ts-no-inner-html
  el["outerHTML"] = host;
  // ruleid: ts-no-inner-html
  el.insertAdjacentHTML("beforeend", host);
  // ruleid: ts-no-inner-html
  document.write(host);
  // ruleid: ts-no-inner-html
  document.writeln(host);
  // ruleid: ts-no-inner-html
  window.document.write(host);

  for (const item of list) {
    if (item) {
      // ruleid: ts-no-inner-html
      item.innerHTML = host;
    }
  }
  list.forEach((item) => {
    // ruleid: ts-no-inner-html
    item.insertAdjacentHTML("afterbegin", host);
  });
}

export function safe(el: HTMLElement, host: string, out: WritableStreamDefaultWriter<string>): string {
  // ok: ts-no-inner-html
  el.textContent = host;
  // ok: ts-no-inner-html
  el.innerText = host;
  // ok: ts-no-inner-html
  el.insertAdjacentText("beforeend", host);
  // ok: ts-no-inner-html
  el.setAttribute("title", host);
  // ok: ts-no-inner-html
  void out.write(host);
  // ok: ts-no-inner-html
  const before = el.innerHTML;
  // ok: ts-no-inner-html
  el.append(document.createTextNode(host));
  return before;
}
