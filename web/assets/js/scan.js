/* agentwatchdog — the two pieces of behaviour on this page.
 *
 * No framework, no bundler, no dependency. The tool this site describes runs
 * on a bare server with nothing but python3; the page holds itself to the
 * same standard.
 */
(function () {
  "use strict";

  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ----------------------------------------------------------------------
   * The scan.
   *
   * Lines arrive, then the spans that must never reach disk are covered in
   * front of you, each labelled with the rule that decided it. It runs once,
   * on first sight, and offers a replay rather than looping — a loop turns an
   * argument into wallpaper.
   * -------------------------------------------------------------------- */
  var scan = document.querySelector("[data-scan]");

  if (scan) {
    var lines = Array.prototype.slice.call(scan.querySelectorAll(".line"));
    var timers = [];
    var ARRIVE = 620; // gap between lines
    var COVER = 400; // how long a line sits legible before the bars land

    function clear() {
      timers.forEach(clearTimeout);
      timers = [];
    }

    function settle() {
      clear();
      lines.forEach(function (line) {
        line.setAttribute("data-state", "done");
      });
    }

    function play() {
      if (reduced) {
        settle();
        return;
      }
      clear();
      lines.forEach(function (line) {
        line.setAttribute("data-state", "");
      });
      lines.forEach(function (line, i) {
        timers.push(
          setTimeout(function () {
            line.setAttribute("data-state", "in");
          }, i * ARRIVE)
        );
        timers.push(
          setTimeout(function () {
            line.setAttribute("data-state", "done");
          }, i * ARRIVE + COVER)
        );
      });
    }

    var replay = scan.querySelector("[data-replay]");
    if (replay) {
      replay.addEventListener("click", play);
    }

    if (reduced || !("IntersectionObserver" in window)) {
      settle();
    } else {
      var seen = false;
      var watcher = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting && !seen) {
              seen = true;
              play();
              watcher.disconnect();
            }
          });
        },
        { threshold: 0.25 }
      );
      watcher.observe(scan);
    }
  }

  /* ----------------------------------------------------------------------
   * Copy the one command the page is asking anyone to run.
   * -------------------------------------------------------------------- */
  Array.prototype.forEach.call(
    document.querySelectorAll("[data-copy]"),
    function (button) {
      var label = button.querySelector(".copy__label");
      var idle = label ? label.textContent : "";
      var done = button.getAttribute("data-copied-label") || "Copied";

      button.addEventListener("click", function () {
        var text = button.getAttribute("data-copy");
        var reset = function () {
          button.setAttribute("data-copied", "true");
          if (label) {
            label.textContent = done;
          }
          setTimeout(function () {
            button.removeAttribute("data-copied");
            if (label) {
              label.textContent = idle;
            }
          }, 1800);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(reset, function () {});
          return;
        }
        // Older browsers, and any page not served over a secure origin.
        var field = document.createElement("textarea");
        field.value = text;
        field.setAttribute("readonly", "");
        field.style.position = "absolute";
        field.style.left = "-9999px";
        document.body.appendChild(field);
        field.select();
        try {
          document.execCommand("copy");
          reset();
        } catch (err) {
          /* Leave the command visible; it is short enough to type. */
        }
        document.body.removeChild(field);
      });
    }
  );
})();
