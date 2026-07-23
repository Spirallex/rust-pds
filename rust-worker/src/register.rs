//! Account registration: the page, the handle rules, and the wire types.
//!
//! The page is hand-rolled and entirely self-contained — no external CSS, JS, or
//! images — for the same reason the OAuth consent screen is: a page that loads
//! third-party resources is a page a third party can influence, and this one
//! takes a password.
//!
//! The stylesheet is deliberately the same one `oauth/html.rs` serves, so signup
//! and login are visibly one system. System colours (`Canvas`, `AccentColor`)
//! rather than fixed hexes means both follow the viewer's light/dark preference
//! without a second palette to maintain.

use serde::{Deserialize, Serialize};

/// Escape text for HTML element content or a quoted attribute.
///
/// Every value interpolated into the page below is server-controlled today, but
/// the handle is echoed back on the error path and comes from the request, so
/// this is load-bearing rather than defensive habit.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------------

/// `com.atproto.server.createAccount` input.
///
/// Field-for-field the lexicon shape, and identical to the server crate's
/// `CreateAccountInput`, so a client cannot tell which implementation answered.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountInput {
    pub handle: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
}

#[derive(Deserialize)]
pub struct CheckInput {
    pub label: String,
}

// ---------------------------------------------------------------------------
// handle rules
// ---------------------------------------------------------------------------

/// Validate a single handle label — the part the person actually chooses.
///
/// The full-handle rules in the server crate's `validate_handle` cover the whole
/// dotted string; here the suffix is fixed by the deployment, so only one
/// segment is in play and it must not contain a dot at all. Rejecting the dot is
/// what stops someone typing `a.b` and claiming a nested name the wildcard
/// certificate does not cover.
pub fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("Pick a handle.");
    }
    if label.len() > 63 {
        return Err("That's too long — 63 characters at most.");
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err("Can't start or end with a hyphen.");
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Letters, numbers and hyphens only.");
    }
    // Reserved because these are real hostnames on the zone: handing them out
    // would let an account answer for infrastructure.
    const RESERVED: &[&str] = &[
        "www", "api", "admin", "pds", "registry", "plc", "oauth", "xrpc", "mail", "ns1", "ns2",
    ];
    if RESERVED.contains(&label) {
        return Err("That name is reserved.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the page
// ---------------------------------------------------------------------------

const STYLE: &str = r#"
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  margin: 0; padding: 2rem 1rem;
  display: flex; justify-content: center;
  background: Canvas; color: CanvasText;
}
main { width: 100%; max-width: 26rem; }
h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
.sub { color: GrayText; margin: 0 0 1.5rem; font-size: .9rem; }
.card {
  border: 1px solid color-mix(in srgb, CanvasText 15%, transparent);
  border-radius: 10px; padding: 1.25rem; margin-bottom: 1.25rem;
}
label { display: block; margin: .85rem 0 .3rem; font-weight: 500; }
label:first-of-type { margin-top: 0; }
.handle-row {
  display: flex; align-items: stretch;
  border: 1px solid color-mix(in srgb, CanvasText 25%, transparent);
  border-radius: 6px; background: Field; overflow: hidden;
}
.handle-row:focus-within { outline: 2px solid AccentColor; outline-offset: 1px; }
.handle-row.ok  { border-color: color-mix(in srgb, green 55%, transparent); }
.handle-row.bad { border-color: color-mix(in srgb, #d33 60%, transparent); }
.handle-row input { border: 0; flex: 1; min-width: 0; background: transparent; }
.handle-row .suffix {
  display: flex; align-items: center; padding: 0 .65rem;
  color: GrayText; font-size: .9rem; white-space: nowrap;
  background: color-mix(in srgb, CanvasText 5%, transparent);
}
input[type=text], input[type=password], input[type=email] {
  width: 100%; padding: .55rem .65rem; font-size: 1rem;
  border: 1px solid color-mix(in srgb, CanvasText 25%, transparent);
  border-radius: 6px; background: Field; color: FieldText;
}
input:focus-visible { outline: 2px solid AccentColor; outline-offset: 1px; }
.hint { font-size: .78rem; color: GrayText; margin: .3rem 0 0; min-height: 1.1em; }
.hint.ok  { color: color-mix(in srgb, green 75%, CanvasText); }
.hint.bad { color: color-mix(in srgb, #d33 75%, CanvasText); }
.actions { display: flex; gap: .6rem; margin-top: 1.25rem; }
button { flex: 1; padding: .6rem; font-size: 1rem; font-weight: 500;
         border-radius: 6px; cursor: pointer; border: 1px solid transparent; }
button.primary { background: AccentColor; color: AccentColorText; }
button:disabled { background: color-mix(in srgb, CanvasText 12%, transparent);
                  color: GrayText; cursor: not-allowed; }
button:focus-visible { outline: 2px solid AccentColor; outline-offset: 2px; }
.error { padding: .6rem .75rem; border-radius: 6px; margin-bottom: 1rem;
         background: color-mix(in srgb, #d33 15%, Canvas); color: CanvasText; }
.steplist { display: flex; flex-direction: column; gap: .55rem; margin: 0; padding: 0; list-style: none; }
.steplist li { display: flex; align-items: center; gap: .6rem; color: GrayText; }
.steplist li .dot { width: .5rem; height: .5rem; border-radius: 50%; flex: none;
                    background: color-mix(in srgb, CanvasText 25%, transparent); }
.steplist li.done, .steplist li.now { color: CanvasText; }
.steplist li.done .dot, .steplist li.now .dot { background: AccentColor; }
.kv { display: flex; flex-direction: column; gap: .1rem; margin: 0 0 .9rem;
      font-family: ui-monospace, monospace; font-size: .78rem; word-break: break-all; }
.kv .k { color: GrayText; }
.warnbox { border: 1px solid color-mix(in srgb, #b8860b 45%, transparent);
           background: color-mix(in srgb, #b8860b 10%, Canvas);
           border-radius: 6px; padding: .7rem .8rem; font-size: .85rem; }
.hidden { display: none; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
"#;

/// Render the registration page for a deployment whose handles end in
/// `zone_suffix`.
pub fn registration_page(zone_suffix: &str) -> String {
    let suffix = escape(&format!(".{zone_suffix}"));
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Claim your handle</title>
<style>{STYLE}</style>
</head>
<body>
<main>

  <section id="form-view">
    <h1>Claim your handle</h1>
    <p class="sub">This becomes your identity across the network.</p>
    <div id="err" class="error hidden" role="alert"></div>
    <form id="form" class="card" autocomplete="on">
      <label for="label">Handle</label>
      <div class="handle-row" id="handle-row">
        <input id="label" name="label" type="text" inputmode="url"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               autocomplete="username" required>
        <span class="suffix">{suffix}</span>
      </div>
      <p class="hint" id="handle-hint" aria-live="polite"></p>

      <label for="invite">Invite code</label>
      <input id="invite" name="invite" type="text" autocomplete="off"
             autocapitalize="none" spellcheck="false" required>

      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" required>

      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="new-password" minlength="8" required>
      <p class="hint">At least 8 characters.</p>

      <div class="actions">
        <button type="submit" class="primary" id="submit">Create account</button>
      </div>
    </form>
  </section>

  <section id="working-view" class="hidden">
    <h1>Creating your account</h1>
    <p class="sub">This takes a few seconds. Don't close the page.</p>
    <div class="card">
      <ul class="steplist">
        <li class="now" id="s1"><span class="dot"></span>Reserving your handle</li>
        <li id="s2"><span class="dot"></span>Generating your keys</li>
        <li id="s3"><span class="dot"></span>Registering your identity</li>
        <li id="s4"><span class="dot"></span>Finishing up</li>
      </ul>
    </div>
  </section>

  <section id="done-view" class="hidden">
    <h1>You're on the network</h1>
    <p class="sub" id="done-handle"></p>
    <div class="card">
      <div class="kv"><span class="k">DID</span><span id="done-did"></span></div>
      <div class="warnbox">
        <strong>Your account is portable.</strong> The recovery key that can move
        it to another server is held here for now. Export it from your account
        settings once you have somewhere safe to keep it.
      </div>
    </div>
  </section>

</main>
<script>
(function () {{
  var SUFFIX = {suffix_json};
  var labelEl = document.getElementById('label');
  var row = document.getElementById('handle-row');
  var hint = document.getElementById('handle-hint');
  var submit = document.getElementById('submit');
  var err = document.getElementById('err');
  var timer = null;
  var lastOk = false;

  function setHint(text, kind) {{
    hint.textContent = text || '';
    hint.className = 'hint' + (kind ? ' ' + kind : '');
    row.className = 'handle-row' + (kind ? ' ' + kind : '');
    lastOk = kind === 'ok';
    submit.disabled = !lastOk;
  }}

  labelEl.addEventListener('input', function () {{
    var v = labelEl.value.trim().toLowerCase();
    setHint('', null);
    submit.disabled = true;
    if (timer) clearTimeout(timer);
    if (!v) return;
    timer = setTimeout(function () {{ check(v); }}, 250);
  }});

  function check(v) {{
    fetch('/register/check', {{
      method: 'POST',
      headers: {{ 'content-type': 'application/json' }},
      body: JSON.stringify({{ label: v }})
    }})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        if (labelEl.value.trim().toLowerCase() !== v) return;
        if (d.available) setHint('Available', 'ok');
        else setHint(d.message || "That one's taken. Try another.", 'bad');
      }})
      .catch(function () {{ setHint('Could not check that right now.', 'bad'); }});
  }}

  document.getElementById('form').addEventListener('submit', function (e) {{
    e.preventDefault();
    if (!lastOk) return;
    err.classList.add('hidden');

    var handle = labelEl.value.trim().toLowerCase() + SUFFIX;
    document.getElementById('form-view').classList.add('hidden');
    document.getElementById('working-view').classList.remove('hidden');
    ['s1', 's2', 's3'].forEach(function (id, i) {{
      setTimeout(function () {{
        var el = document.getElementById(id);
        if (el) {{ el.className = 'done'; }}
        var nx = document.getElementById('s' + (i + 2));
        if (nx) {{ nx.className = 'now'; }}
      }}, (i + 1) * 600);
    }});

    fetch('/xrpc/com.atproto.server.createAccount', {{
      method: 'POST',
      headers: {{ 'content-type': 'application/json' }},
      body: JSON.stringify({{
        handle: handle,
        inviteCode: document.getElementById('invite').value.trim(),
        email: document.getElementById('email').value.trim(),
        password: document.getElementById('password').value
      }})
    }})
      .then(function (r) {{ return r.json().then(function (b) {{ return {{ ok: r.ok, body: b }}; }}); }})
      .then(function (res) {{
        if (!res.ok) throw new Error(res.body && res.body.message ? res.body.message : 'Something went wrong.');
        document.getElementById('working-view').classList.add('hidden');
        document.getElementById('done-view').classList.remove('hidden');
        document.getElementById('done-handle').textContent = res.body.handle;
        document.getElementById('done-did').textContent = res.body.did;
      }})
      .catch(function (e) {{
        document.getElementById('working-view').classList.add('hidden');
        document.getElementById('form-view').classList.remove('hidden');
        err.textContent = e.message;
        err.classList.remove('hidden');
      }});
  }});
}})();
</script>
</body>
</html>
"#,
        STYLE = STYLE,
        suffix = suffix,
        suffix_json = serde_json::to_string(&format!(".{zone_suffix}")).unwrap_or_default(),
    )
}
