// Adds a copy button to each install command. Without JavaScript the commands
// are plain, selectable text.
(function () {
  "use strict";
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.className = "offscreen";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(area);
      if (ok) { resolve(); } else { reject(new Error("copy failed")); }
    });
  }
  document.querySelectorAll(".cmd").forEach(function (cmd) {
    var code = cmd.querySelector("code");
    if (!code) { return; }
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy: " + code.textContent);
    var timer;
    button.addEventListener("click", function () {
      copyText(code.textContent).then(function () {
        button.textContent = "Copied";
        button.setAttribute("data-done", "");
      }, function () {
        button.textContent = "Selected";
        var range = document.createRange();
        range.selectNodeContents(code);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      });
      clearTimeout(timer);
      timer = setTimeout(function () {
        button.textContent = "Copy";
        button.removeAttribute("data-done");
      }, 2000);
    });
    cmd.appendChild(button);
  });
})();
