// Subscriber login page controller.
// Reads the one-time token from the URL fragment (never sent to a server),
// opens an authenticated WebSocket to this service, and renders the remote
// browser with noVNC. Polls read-only status to show success / timeout.
import RFB from "/static/novnc/core/rfb.js";

const sessionId = location.pathname.split("/").filter(Boolean).pop();
const token = new URLSearchParams(location.hash.slice(1)).get("token");

const $ = (id) => document.getElementById(id);
const overlay = $("overlay");
const overlayText = $("overlay-text");

function showResult(ok, title, text) {
  $("result-title").textContent = title;
  $("result-text").textContent = text;
  const icon = $("result-icon");
  icon.textContent = ok ? "✓" : "!";
  icon.classList.toggle("bad", !ok);
  $("result").hidden = false;
}

if (!token) {
  showResult(false, "Invalid link", "This login link is missing its access token. Please start again from the app.");
  throw new Error("no token");
}

// Build wss:// (or ws:// on plain http dev) URL to our authenticated bridge.
const scheme = location.protocol === "https:" ? "wss" : "ws";
const wsUrl = `${scheme}://${location.host}/sessions/${encodeURIComponent(sessionId)}`
            + `/vnc?token=${encodeURIComponent(token)}`;

let rfb = null;
let done = false;

function connect() {
  rfb = new RFB($("screen"), wsUrl, { wsProtocols: ["binary"] });
  rfb.viewOnly = false;
  rfb.scaleViewport = true;
  rfb.resizeSession = false;
  rfb.background = "#000";

  rfb.addEventListener("connect", () => { overlay.hidden = true; });
  // The VNC server requires a password; fetch it (we're authorised by the
  // token) and hand it to noVNC when it reaches the auth step.
  rfb.addEventListener("credentialsrequired", async () => {
    try {
      const r = await fetch(`/login/${encodeURIComponent(sessionId)}/status?token=${encodeURIComponent(token)}`,
                            { cache: "no-store" });
      const d = await r.json();
      if (d.vnc_password) rfb.sendCredentials({ password: d.vnc_password });
    } catch { /* disconnect handler will surface the failure */ }
  });
  rfb.addEventListener("disconnect", (e) => {
    if (done) return;
    // A clean close usually means the login completed and the container exited.
    overlay.hidden = false;
    overlayText.textContent = "Checking login status…";
    setTimeout(poll, 800);
  });
  rfb.addEventListener("securityfailure", () => {
    if (!done) { done = true; showResult(false, "Connection refused", "The secure browser rejected the connection. Please start again."); }
  });
}

async function poll() {
  if (done) return;
  try {
    const r = await fetch(`/login/${encodeURIComponent(sessionId)}/status?token=${encodeURIComponent(token)}`,
                          { cache: "no-store" });
    const data = await r.json();
    if (data.status === "success") {
      done = true;
      try { rfb && rfb.disconnect(); } catch {}
      if (data.redirect_to) return returnToApp(data.redirect_to, true);
      showResult(true, "Account connected", "You're all set. You can close this window and return to the app.");
      return;
    }
    if (["timeout", "failed", "cancelled"].includes(data.status)) {
      done = true;
      if (data.redirect_to) return returnToApp(data.redirect_to, false);
      showResult(false, "Login not completed",
        "The session ended before login finished. Please start again from the app.");
      return;
    }
    updateTimer(data.expires_in);
  } catch {}
  if (!done) setTimeout(poll, 2500);
}

// Show the outcome briefly, then send the subscriber back to the app that
// started the login (the redirect_to URL already carries account_id + status).
function returnToApp(url, ok) {
  showResult(ok, ok ? "Account connected" : "Login not completed",
    "Returning you to the app…");
  setTimeout(() => { location.href = url; }, 1200);
}

function updateTimer(seconds) {
  const t = $("timer");
  if (seconds == null) { t.hidden = true; return; }
  const m = Math.floor(seconds / 60), s = seconds % 60;
  t.hidden = false;
  t.textContent = `Session expires in ${m}:${String(s).padStart(2, "0")}`;
}

connect();
poll();
