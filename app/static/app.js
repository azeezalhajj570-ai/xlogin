// Subscriber login page controller.
// Reads the one-time token from the URL fragment (never sent to a server),
// opens an authenticated WebSocket to this service, and renders the remote
// browser with noVNC. Polls read-only status to show success / timeout.
import RFB from "/static/novnc/core/rfb.js";
import KeyTable from "/static/novnc/core/input/keysym.js";
import keysyms from "/static/novnc/core/input/keysymdef.js";

const sessionId = location.pathname.split("/").filter(Boolean).pop();
const token = new URLSearchParams(location.hash.slice(1)).get("token");
// Two modes share this page: an interactive login (/login/<session>) and a
// short-lived view of an account's live browser (/view/<run>).
const IS_VIEW = location.pathname.startsWith("/view/");
const BASE = IS_VIEW ? `/view/${encodeURIComponent(sessionId)}` : `/login/${encodeURIComponent(sessionId)}`;
const STATUS_URL = `${BASE}/status?token=${encodeURIComponent(token || "")}`;

if (IS_VIEW) {
  // Same page, different job: explain the live-browser view instead of login.
  document.title = "Your X browser";
  const brand = document.querySelector(".brand");
  if (brand) brand.textContent = "Your X browser";
  const help = document.querySelector(".help");
  if (help) {
    help.querySelector("h2").textContent = "What this is";
    help.querySelector("ol").innerHTML =
      "<li>This is the browser that keeps your X account connected.</li>"
      + "<li>Finish whatever X is asking for, such as a captcha or an email code.</li>"
      + "<li>Then close this window. The browser keeps running.</li>";
    const note = document.getElementById("help-note");
    if (note) note.textContent = "This link works for a few minutes only. Don't share it.";
  }
}

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
const wsUrl = IS_VIEW
  ? `${scheme}://${location.host}${BASE}/vnc?token=${encodeURIComponent(token)}`
  : `${scheme}://${location.host}/sessions/${encodeURIComponent(sessionId)}`
    + `/vnc?token=${encodeURIComponent(token)}`;

let rfb = null;
let done = false;
let connected = false;

function connect() {
  rfb = new RFB($("screen"), wsUrl, { wsProtocols: ["binary"] });
  rfb.viewOnly = false;
  rfb.scaleViewport = true;
  rfb.resizeSession = false;
  rfb.background = "#000";
  // On touch, don't let a tap grab the (invisible) canvas keyboard; we route
  // typing through a real text field instead so the phone's keyboard appears.
  if (IS_TOUCH) rfb.focusOnClick = false;

  rfb.addEventListener("connect", () => { connected = true; overlay.hidden = true; });
  // The VNC server requires a password; fetch it (we're authorised by the
  // token) and hand it to noVNC when it reaches the auth step.
  rfb.addEventListener("credentialsrequired", async () => {
    try {
      const r = await fetch(STATUS_URL, { cache: "no-store" });
      const d = await r.json();
      if (d.vnc_password) rfb.sendCredentials({ password: d.vnc_password });
    } catch { /* disconnect handler will surface the failure */ }
  });
  rfb.addEventListener("disconnect", (e) => {
    connected = false;
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
    const r = await fetch(STATUS_URL, { cache: "no-store" });
    if (IS_VIEW && r.status === 403) {
      done = true;
      try { rfb && rfb.disconnect(); } catch {}
      showResult(false, "Link expired", "This view link has expired. Open a new one from the app.");
      return;
    }
    const data = await r.json();
    if (IS_VIEW) {
      if (data.status !== "live") {
        done = true;
        try { rfb && rfb.disconnect(); } catch {}
        showResult(false, "Browser closed",
          data.status === "logged_out" ? "X signed this account out. Reconnect it from the app."
                                       : "The browser is not running right now. Try again from the app.");
        return;
      }
      updateTimer(data.expires_in);
      if (!connected) connect();  // the bridge dropped but the browser is still live
      if (!done) setTimeout(poll, 5000);
      return;
    }
    if (data.status === "success") {
      done = true;
      try { rfb && rfb.disconnect(); } catch {}
      if (data.redirect_to) return returnToApp(data.redirect_to, true);
      if (data.credentials) return showCredentials(data.credentials);
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

// Success with no return URL: show the captured session tokens with copy
// buttons so the operator can paste them into their importer.
function showCredentials(creds) {
  showResult(true, "Account connected", "Copy your session tokens below.");
  const card = document.querySelector(".result-card");
  card.classList.add("wide");
  const box = document.createElement("div");
  box.className = "creds";
  const fields = [
    ["Cookie (for import)", creds.cookie],
    ["auth_token", creds.auth_token],
    ["ct0", creds.ct0],
  ];
  for (const [label, value] of fields) {
    if (!value) continue;
    const row = document.createElement("div");
    row.className = "cred";
    const lab = document.createElement("label");
    lab.textContent = label;
    const line = document.createElement("div");
    line.className = "cred-line";
    const input = document.createElement("input");
    input.type = "text"; input.readOnly = true; input.value = value;
    input.addEventListener("focus", () => input.select());
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "copy"; btn.textContent = "Copy";
    btn.addEventListener("click", () => copyValue(value, btn));
    line.append(input, btn);
    row.append(lab, line);
    box.append(row);
  }
  const note = document.createElement("p");
  note.className = "muted creds-note";
  note.textContent = "These are secrets — they grant access to the account. "
    + "Close this window when you're done.";
  box.append(note);
  card.append(box);
}

async function copyValue(value, btn) {
  const original = btn.textContent;
  try {
    await navigator.clipboard.writeText(value);
    btn.textContent = "Copied";
  } catch {
    btn.textContent = "Press ⌘/Ctrl+C";
  }
  setTimeout(() => { btn.textContent = original; }, 1500);
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
  t.textContent = `${IS_VIEW ? "View" : "Session"} expires in ${m}:${String(s).padStart(2, "0")}`;
}

// ---- mobile keyboard --------------------------------------------------------
// A canvas can't open a phone's on-screen keyboard, so we focus a hidden text
// field and forward what gets typed to the remote browser as key events. This
// mirrors how noVNC's own client supports touch devices.
const IS_TOUCH = window.matchMedia("(pointer: coarse)").matches
  || ("ontouchstart" in window);
const FILLER_LEN = 100;

function setupKeyboard() {
  const kbd = $("kbdinput");
  const toggle = $("kbd-toggle");
  if (!kbd || !toggle) return;
  if (!IS_TOUCH) { toggle.hidden = true; return; }
  toggle.hidden = false;

  let last = "";
  const reset = () => { last = "_".repeat(FILLER_LEN); kbd.value = last; };
  reset();

  function sendChar(cp) {
    if (cp === 0x0a || cp === 0x0d) { rfb && rfb.sendKey(KeyTable.XK_Return, "Enter"); return; }
    const ks = keysyms.lookup(cp);
    if (ks && rfb) rfb.sendKey(ks);
  }

  kbd.addEventListener("input", () => {
    const value = kbd.value;
    // Count how many trailing chars differ from the filler baseline.
    let shared = 0;
    const max = Math.min(value.length, last.length);
    while (shared < max && value[shared] === last[shared]) shared++;
    const backspaces = last.length - shared;
    for (let i = 0; i < backspaces; i++) rfb && rfb.sendKey(KeyTable.XK_BackSpace, "Backspace");
    for (const ch of value.slice(shared)) sendChar(ch.codePointAt(0));
    if (value.length > 2 * FILLER_LEN || value.length < 2) reset();
    else last = value;
  });

  // A few control keys that hardware/soft keyboards deliver as keydown.
  const SPECIAL = {
    Enter: KeyTable.XK_Return, Backspace: KeyTable.XK_BackSpace, Tab: KeyTable.XK_Tab,
    Escape: KeyTable.XK_Escape, ArrowUp: KeyTable.XK_Up, ArrowDown: KeyTable.XK_Down,
    ArrowLeft: KeyTable.XK_Left, ArrowRight: KeyTable.XK_Right,
  };
  kbd.addEventListener("keydown", (e) => {
    const ks = SPECIAL[e.key];
    if (ks) { e.preventDefault(); rfb && rfb.sendKey(ks, e.code); if (e.key !== "Backspace") reset(); }
  });

  const focusKbd = () => { kbd.focus(); };
  toggle.addEventListener("click", (e) => {
    e.preventDefault();
    if (document.activeElement === kbd) kbd.blur(); else focusKbd();
  });
  // Tapping the remote screen also brings up the keyboard.
  $("stage").addEventListener("touchend", () => { if (!done) setTimeout(focusKbd, 50); });
}

setupKeyboard();
connect();
poll();
