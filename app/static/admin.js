// Admin tool: create a one-time login link via POST /sessions.
// The API key is entered by the admin and kept only in sessionStorage (this tab).
const $ = (id) => document.getElementById(id);
const KEY_STORE = "xlogin_admin_key";

// Register the service worker so the admin tool is installable / works offline.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}

try {
  const saved = sessionStorage.getItem(KEY_STORE);
  if (saved) $("key").value = saved;
} catch {}

function showError(msg) {
  const e = $("error");
  e.textContent = msg;
  e.hidden = false;
}

function fmtTtl(seconds) {
  if (seconds == null) return "a short while";
  const m = Math.floor(seconds / 60);
  return m >= 1 ? `${m} min` : `${seconds}s`;
}

$("form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("error").hidden = true;
  $("result").hidden = true;

  const key = $("key").value.trim();
  const account_id = $("account_id").value.trim();
  if (!key || !account_id) return showError("API key and account id are required.");
  try { sessionStorage.setItem(KEY_STORE, key); } catch {}

  const body = { account_id };
  for (const f of ["username", "proxy_url", "redirect_url", "device"]) {
    const v = $(f).value.trim();
    if (v) body[f] = v;
  }

  const btn = $("go");
  btn.disabled = true;
  btn.textContent = "Generating…";
  try {
    const r = await fetch("/sessions", {
      method: "POST",
      headers: { "Authorization": "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const map = { 401: "Invalid API key.", 429: "Too many active sessions — try again shortly.",
                    503: data.message || "No browser capacity right now." };
      return showError(map[r.status] || data.message || data.error || `Request failed (${r.status}).`);
    }
    $("link").value = data.login_url;
    $("open").href = data.login_url;
    $("ttl").textContent = fmtTtl(data.expires_in);
    $("meta").textContent = `account: ${data.account_id} · session: ${data.session_id} · status: ${data.status}`;
    $("result").hidden = false;
  } catch (e) {
    showError("Network error: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate link";
  }
});

$("copy").addEventListener("click", async () => {
  const btn = $("copy");
  const val = $("link").value;
  try {
    await navigator.clipboard.writeText(val);
    btn.textContent = "Copied";
  } catch {
    $("link").focus(); $("link").select();
    btn.textContent = "Press ⌘/Ctrl+C";
  }
  setTimeout(() => { btn.textContent = "Copy"; }, 1500);
});
