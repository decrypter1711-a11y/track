/* security.js  -  client-side deterrents.
 * NOTE: these only RAISE THE BAR for casual users. Anyone determined can
 * still read client code (it is delivered to the browser). Real security
 * lives on the server (see app.py firewall + auth). Do not rely on this
 * file alone.
 */
(function () {
  "use strict";

  // Block right-click context menu.
  document.addEventListener("contextmenu", function (e) {
    e.preventDefault();
    return false;
  });

  // Block common "view source / devtools" keyboard shortcuts.
  document.addEventListener("keydown", function (e) {
    var k = (e.key || "").toUpperCase();
    if (
      k === "F12" ||
      (e.ctrlKey && e.shiftKey && (k === "I" || k === "J" || k === "C")) ||
      (e.ctrlKey && (k === "U" || k === "S")) ||
      (e.metaKey && e.altKey && (k === "I" || k === "J" || k === "C"))
    ) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  });

  // Discourage text selection + drag of images.
  document.addEventListener("dragstart", function (e) {
    e.preventDefault();
  });
})();
