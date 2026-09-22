/* activity.js - active / idle / away tracking */
(function () {
  "use strict";

  var cfg = window.ET_CONFIG;
  if (!cfg || !cfg.loggedIn) return;

  var IDLE_THRESHOLD = cfg.idleThreshold || 60;
  var HEARTBEAT_MS = 30000;
  var TICK_MS = 1000;

  var lastActivity = Date.now();
  var lastTick = Date.now();

  var activeSeconds = 0;
  var idleSeconds = 0;
  var awaySeconds = 0;

  var newIdleEvents = 0;
  var newAwayEvents = 0;

  var wasIdle = false;
  var wasAway = document.hidden;

  if (wasAway) newAwayEvents = 1;

  var secondsLeft =
    cfg.secondsLeft === null || cfg.secondsLeft === undefined
      ? null
      : cfg.secondsLeft;

  ["mousemove", "mousedown", "keydown", "scroll", "touchstart", "click", "wheel"]
    .forEach(function (ev) {
      document.addEventListener(
        ev,
        function () {
          lastActivity = Date.now();
        },
        { passive: true, capture: true }
      );
    });

  function isAway() {
    return document.hidden;
  }

  window.addEventListener("visibilitychange", function () {
    var nowAway = isAway();

    if (nowAway && !wasAway) {
      newAwayEvents += 1;
    }

    wasAway = nowAway;
  });

  var audioCtx = null;

  function beep(times) {
    times = times || 1;

    try {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }

      var t0 = audioCtx.currentTime;

      for (var i = 0; i < times; i++) {
        var osc = audioCtx.createOscillator();
        var gain = audioCtx.createGain();

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        osc.type = "sine";
        osc.frequency.value = 880;

        var start = t0 + i * 0.35;

        gain.gain.setValueAtTime(0.0001, start);
        gain.gain.exponentialRampToValueAtTime(0.25, start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.25);

        osc.start(start);
        osc.stop(start + 0.28);
      }
    } catch (e) {}
  }

  if ("Notification" in window && Notification.permission === "default") {
    var ask = function () {
      Notification.requestPermission();
      window.removeEventListener("click", ask);
    };

    window.addEventListener("click", ask);
  }

  function notify(title, body) {
    try {
      if ("Notification" in window && Notification.permission === "granted") {
        new Notification(title, {
          body: body,
          icon: "/static/images/sugarrelax-logo.png",
        });
      }
    } catch (e) {}
  }

  function toast(msg) {
    var t = document.getElementById("et-toast");

    if (!t) {
      t = document.createElement("div");
      t.id = "et-toast";
      t.style.cssText =
        "position:fixed;bottom:24px;right:24px;z-index:9999;" +
        "background:#dc2626;color:#fff;padding:14px 18px;border-radius:12px;" +
        "font-family:Nunito,sans-serif;font-weight:700;font-size:14px;" +
        "box-shadow:0 8px 24px rgba(0,0,0,.2);max-width:320px;";

      document.body.appendChild(t);
    }

    t.textContent = msg;
    t.style.display = "block";

    clearTimeout(t._h);

    t._h = setTimeout(function () {
      t.style.display = "none";
    }, 8000);
  }

  var beepedAt = {};
  var lastOverdueMin = -1;

  setInterval(function () {
    var now = Date.now();
    var elapsed = Math.round((now - lastTick) / 1000);

    elapsed = Math.max(1, Math.min(elapsed, 120));
    lastTick = now;

    var idleFor = (now - lastActivity) / 1000;
    var away = isAway();

    /*
      FIXED LOGIC:

      Priority: ACTIVE > AWAY > IDLE

      1. App is focused + mouse/keyboard input   → ACTIVE only
      2. App is focused + no input               → IDLE only
      3. App is hidden/minimized (away)          → AWAY only
         (away seconds also count as active,
          because employee is likely working
          in another app like VS Code)

      Away is NEVER counted as Idle.
      Active and Idle never overlap.
      Active and Away never overlap in the counters
      (away is stored separately for admin reference
       but also added to active in the heartbeat payload).
    */

    if (away) {
      // Tab hidden / minimized → AWAY only (not idle)
      awaySeconds += elapsed;

      if (!wasAway) {
        newAwayEvents += 1;
        wasAway = true;
      }
    } else {
      // Tab is visible
      wasAway = false;

      if (idleFor < IDLE_THRESHOLD) {
        // Focused + recent input → ACTIVE
        activeSeconds += elapsed;
        wasIdle = false;
      } else {
        // Focused + no input → IDLE
        idleSeconds += elapsed;

        if (!wasIdle) {
          newIdleEvents += 1;
          wasIdle = true;
        }
      }
    }

    if (secondsLeft !== null) {
      secondsLeft = secondsLeft - elapsed;
    }

    [600, 300, 60].forEach(function (m) {
      if (
        secondsLeft !== null &&
        secondsLeft <= m &&
        secondsLeft > m - elapsed &&
        !beepedAt[m]
      ) {
        beepedAt[m] = true;
        beep(2);

        var mins = Math.round(m / 60);

        toast("Progress update due in " + mins + " minute" + (mins === 1 ? "" : "s"));
        notify("sugar.relax", "Progress update due in " + mins + " min");
      }
    });

    if (secondsLeft !== null && secondsLeft > 600) {
      beepedAt = {};
    }

    if (secondsLeft !== null && secondsLeft <= 0) {
      var overdueMin = Math.floor(Math.abs(secondsLeft) / 60);

      if (overdueMin !== lastOverdueMin) {
        lastOverdueMin = overdueMin;
        beep(3);
        toast("Progress update is overdue. Please post one.");
        notify("sugar.relax", "Progress update overdue");
      }
    } else {
      lastOverdueMin = -1;
    }

    updateProgressUI();
  }, TICK_MS);

  var lastHeartbeatAt = 0;

  function sendHeartbeat(immediate) {
    lastHeartbeatAt = Date.now();

    /*
      Away seconds are sent separately for admin reference,
      but also added into active so the employee's
      active time reflects real working time
      (they were likely working in VS Code / another app).
    */
    var payload = {
      active: immediate ? 1 : (activeSeconds + awaySeconds), // away counts as active
      idle: immediate ? 0 : idleSeconds,
      away: immediate ? 0 : awaySeconds,                     // still stored separately
      idle_events: immediate ? 0 : newIdleEvents,
      away_events: immediate ? 0 : newAwayEvents,
      currently_away: isAway() && !immediate ? 1 : 0,
    };

    if (!immediate) {
      activeSeconds = 0;
      idleSeconds = 0;
      awaySeconds = 0;
      newIdleEvents = 0;
      newAwayEvents = 0;
    }

    fetch("/heartbeat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": cfg.csrf,
      },
      body: JSON.stringify(payload),
      keepalive: true,
    })
      .then(function (r) {
        return r.json();
      })
      .then(function (d) {
        if (d && d.seconds_left !== undefined && d.seconds_left !== null) {
          secondsLeft = d.seconds_left;
        }

        updateProgressUI();
      })
      .catch(function () {});
  }

  sendHeartbeat(true);

  setInterval(sendHeartbeat, HEARTBEAT_MS);

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      sendHeartbeat(true);
    } else {
      sendHeartbeat(false);
    }
  });

  window.addEventListener("focus", function () {
    if (Date.now() - lastHeartbeatAt > 15000) {
      sendHeartbeat(true);
    }
  });

  var _navigatingInternally = false;

  document.addEventListener("click", function (e) {
    var a = e.target.closest("a[href]");

    if (!a) return;

    var href = a.getAttribute("href") || "";

    if (href.startsWith("/") || href.startsWith(window.location.origin)) {
      _navigatingInternally = true;
    }
  });

  document.addEventListener("submit", function () {
    _navigatingInternally = true;
  });

  window.addEventListener("beforeunload", function () {
    sendHeartbeat(false);
  });

  window.addEventListener("pagehide", function (e) {
    if (!e.persisted && !_navigatingInternally) {
      if (navigator.sendBeacon) {
        navigator.sendBeacon("/logout-beacon");
      }
    }
  });

  function updateProgressUI() {
    var badge = document.getElementById("progress-timer");

    if (!badge) return;

    if (secondsLeft === null) {
      badge.textContent = "Update due now";
      badge.className = "due";
      return;
    }

    if (secondsLeft <= 0) {
      var over = Math.abs(secondsLeft);
      var om = Math.floor(over / 60);
      var os = over % 60;

      badge.textContent =
        "Overdue by " + om + "m " + (os < 10 ? "0" : "") + os + "s";

      badge.className = "due";
    } else {
      var m = Math.floor(secondsLeft / 60);
      var s = secondsLeft % 60;

      badge.textContent =
        "Next update in " + m + "m " + (s < 10 ? "0" : "") + s + "s";

      badge.className = secondsLeft < 600 ? "soon" : "ok";
    }
  }

  updateProgressUI();
})();