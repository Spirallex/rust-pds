//! The login and consent page.
//!
//! Hand-rolled rather than templated: it is two pages, it must not pull in a
//! template engine for a single-binary PDS, and every interpolation point is
//! visible in one place where it can be checked for escaping.
//!
//! Everything is inline — no external CSS, JS, or images. A consent screen that
//! loads third-party resources is a consent screen a third party can influence.

/// Escape text for interpolation into HTML element content or a quoted
/// attribute.
///
/// All five of these matter. `<` and `>` prevent tag injection, `&` prevents
/// entity confusion, and both quote characters prevent breaking out of an
/// attribute value — the client name and `client_id` come from a document the
/// client controls, so every one of them is attacker-supplied.
fn escape(s: &str) -> String {
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
.client { font-weight: 600; }
.client-id { font-family: ui-monospace, monospace; font-size: .8rem;
             color: GrayText; word-break: break-all; }
ul.scopes { margin: .75rem 0 0; padding-left: 1.1rem; }
ul.scopes li { margin: .2rem 0; }
label { display: block; margin: .85rem 0 .3rem; font-weight: 500; }
input[type=text], input[type=password] {
  width: 100%; padding: .55rem .65rem; font-size: 1rem;
  border: 1px solid color-mix(in srgb, CanvasText 25%, transparent);
  border-radius: 6px; background: Field; color: FieldText;
}
.actions { display: flex; gap: .6rem; margin-top: 1.25rem; }
button { flex: 1; padding: .6rem; font-size: 1rem; font-weight: 500;
         border-radius: 6px; cursor: pointer; border: 1px solid transparent; }
button.primary { background: AccentColor; color: AccentColorText; }
button.secondary { background: transparent; color: CanvasText;
                   border-color: color-mix(in srgb, CanvasText 25%, transparent); }
.error { padding: .6rem .75rem; border-radius: 6px; margin-bottom: 1rem;
         background: color-mix(in srgb, #d33 15%, Canvas); color: CanvasText; }
"#;

/// A human-readable description for each scope, for the consent list.
///
/// Falls back to the raw scope string: an unknown scope must still be shown, not
/// silently omitted, or the user would be consenting to something invisible.
fn describe_scope(scope: &str) -> &str {
    match scope {
        "atproto" => "Know which account you are",
        "transition:generic" => "Read and write your posts, follows, likes, and profile",
        "transition:chat.bsky" => "Read and send your direct messages",
        "transition:email" => "See your email address",
        other => other,
    }
}

/// Render the combined login + consent page.
///
/// One page and one POST rather than a login step followed by a consent step:
/// that avoids holding server-side login state between two requests, which for a
/// single-binary PDS would mean either a session table or a cookie to get wrong.
pub fn authorize_page(
    request_uri: &str,
    client_name: &str,
    client_id: &str,
    scopes: &[&str],
    login_hint: Option<&str>,
    error: Option<&str>,
) -> String {
    let scope_items: String = scopes
        .iter()
        .map(|s| format!("<li>{}</li>", escape(describe_scope(s))))
        .collect();

    let error_block = error
        .map(|e| format!(r#"<div class="error">{}</div>"#, escape(e)))
        .unwrap_or_default();

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {client_name_esc}</title>
<style>{STYLE}</style>
</head>
<body>
<main>
  <h1>Authorize application</h1>
  <p class="sub">Sign in to grant access to your account.</p>
  {error_block}
  <form method="post" action="/oauth/authorize" autocomplete="on">
    <input type="hidden" name="request_uri" value="{request_uri_esc}">
    <div class="card">
      <div class="client">{client_name_esc}</div>
      <div class="client-id">{client_id_esc}</div>
      <ul class="scopes">{scope_items}</ul>
    </div>
    <div class="card">
      <label for="username">Handle or email</label>
      <input id="username" name="username" type="text" autocomplete="username"
             autocapitalize="none" autocorrect="off" spellcheck="false"
             required value="{hint_esc}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required>
      <div class="actions">
        <button class="secondary" type="submit" name="action" value="deny">Deny</button>
        <button class="primary" type="submit" name="action" value="accept">Authorize</button>
      </div>
    </div>
  </form>
</main>
</body>
</html>"#,
        client_name_esc = escape(client_name),
        client_id_esc = escape(client_id),
        request_uri_esc = escape(request_uri),
        hint_esc = escape(login_hint.unwrap_or("")),
    )
}

/// Render a terminal error page.
///
/// Used only when there is no validated `redirect_uri` to send the error to —
/// an unknown or expired `request_uri`, for instance. When a redirect URI *is*
/// known, the error goes there instead, as the RFC requires.
pub fn error_page(title: &str, message: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_esc}</title>
<style>{STYLE}</style>
</head>
<body>
<main>
  <h1>{title_esc}</h1>
  <div class="card">{message_esc}</div>
</main>
</body>
</html>"#,
        title_esc = escape(title),
        message_esc = escape(message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_every_dangerous_character() {
        assert_eq!(
            escape(r#"<script>alert("x" + 'y' & z)</script>"#),
            "&lt;script&gt;alert(&quot;x&quot; + &#x27;y&#x27; &amp; z)&lt;/script&gt;"
        );
    }

    #[test]
    fn client_supplied_name_cannot_inject_markup() {
        let page = authorize_page(
            "urn:ietf:params:oauth:request_uri:abc",
            r#"<img src=x onerror=alert(1)>"#,
            "https://evil.test/client-metadata.json",
            &["atproto"],
            None,
            None,
        );
        assert!(
            !page.contains("<img src=x"),
            "a client-supplied name must not reach the document as markup"
        );
        assert!(page.contains("&lt;img src=x"));
    }

    #[test]
    fn client_supplied_values_cannot_break_out_of_attributes() {
        // A request_uri that tries to close the value attribute and add another.
        let page = authorize_page(
            r#"abc" autofocus onfocus="alert(1)"#,
            "App",
            "https://app.test/client-metadata.json",
            &["atproto"],
            None,
            None,
        );
        assert!(
            !page.contains(r#"onfocus="alert(1)"#),
            "an attacker must not escape a quoted attribute value"
        );
    }

    #[test]
    fn login_hint_is_prefilled_and_escaped() {
        let page = authorize_page(
            "urn:x",
            "App",
            "https://app.test/m.json",
            &["atproto"],
            Some(r#"alice">"#),
            None,
        );
        assert!(page.contains("alice&quot;&gt;"));
        assert!(!page.contains(r#"value="alice">"#));
    }

    #[test]
    fn every_requested_scope_is_shown() {
        let page = authorize_page(
            "urn:x",
            "App",
            "https://app.test/m.json",
            &["atproto", "transition:generic", "some:unknown"],
            None,
            None,
        );
        assert!(page.contains("Know which account you are"));
        assert!(page.contains("Read and write your posts"));
        assert!(
            page.contains("some:unknown"),
            "an unrecognised scope must still be displayed, not hidden"
        );
    }

    #[test]
    fn both_decision_buttons_are_present() {
        let page = authorize_page(
            "urn:x",
            "App",
            "https://a.test/m.json",
            &["atproto"],
            None,
            None,
        );
        assert!(page.contains(r#"name="action" value="accept""#));
        assert!(page.contains(r#"name="action" value="deny""#));
        assert!(page.contains(r#"name="request_uri""#));
    }

    #[test]
    fn error_block_renders_only_when_present() {
        let clean = authorize_page(
            "urn:x",
            "A",
            "https://a.test/m.json",
            &["atproto"],
            None,
            None,
        );
        assert!(!clean.contains(r#"class="error""#));

        let with_error = authorize_page(
            "urn:x",
            "A",
            "https://a.test/m.json",
            &["atproto"],
            None,
            Some("Incorrect password"),
        );
        assert!(with_error.contains("Incorrect password"));
    }

    #[test]
    fn pages_are_self_contained() {
        let page = authorize_page(
            "urn:x",
            "A",
            "https://a.test/m.json",
            &["atproto"],
            None,
            None,
        );
        for external in ["http://", "//cdn", "<script"] {
            assert!(
                !page.contains(external),
                "the consent page must not reference {external:?} — no third party may influence it"
            );
        }
    }

    #[test]
    fn error_page_escapes_its_inputs() {
        let page = error_page("<b>bad</b>", "<i>worse</i>");
        assert!(!page.contains("<b>bad</b>"));
        assert!(page.contains("&lt;b&gt;bad&lt;/b&gt;"));
    }
}
