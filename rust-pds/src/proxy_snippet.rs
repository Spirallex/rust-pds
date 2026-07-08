//! Proxy-config snippet emitter for the adaptive front-door wizard.
//!
//! Emits a proxy-agnostic requirements block + Caddy (primary) + nginx (secondary) snippets
//! + a tunnel pointer. The generated text is intended for the operator to paste into their
//!   reverse-proxy config.
//!
//! Security: the nginx block sets ONLY the three required headers explicitly
//! (Upgrade, Connection "upgrade", Host $host). No raw client-header pass-through is emitted
//! that could enable Host/Upgrade smuggling. The Caddy `reverse_proxy` directive passes Host
//! and WS upgrade headers by default — no additional header directives are needed.

/// Returns a proxy-agnostic requirements block describing the three invariants any reverse
/// proxy must satisfy to work with this PDS.
pub fn requirements_block(upstream_port: u16) -> String {
    format!(
        "# stelyph reverse-proxy requirements (any proxy must satisfy all three):\n\
         # 1. Forward upstream → this PDS on localhost:{upstream_port}\n\
         # 2. Pass WebSocket Upgrade + Connection headers through (firehose subscribeRepos)\n\
         # 3. Pass the Host header through unchanged\n"
    )
}

/// Returns a Caddy snippet (primary — automatic TLS, single static binary) for the given
/// hostname and upstream port.
///
/// Caddy's `reverse_proxy` directive passes Host and WS Upgrade/Connection headers
/// automatically — no extra header directives required.
pub fn caddy_snippet(hostname: &str, upstream_port: u16) -> String {
    format!(
        "# Caddy (primary — automatic TLS, single static binary):\n\
         {hostname} {{\n\
             reverse_proxy localhost:{upstream_port}\n\
         }}\n\
         # Caddy passes Host + Upgrade/Connection automatically for reverse_proxy.\n"
    )
}

/// Returns an nginx snippet (secondary) for the given hostname and upstream port.
///
/// Sets only the three required headers (Upgrade, Connection "upgrade", Host $host).
/// No raw client-header pass-through is emitted (smuggling-safe defaults).
pub fn nginx_snippet(hostname: &str, upstream_port: u16) -> String {
    format!(
        "# nginx (secondary):\n\
         server {{\n\
             listen 443 ssl;\n\
             server_name {hostname};\n\
         \n\
             location / {{\n\
                 proxy_pass http://localhost:{upstream_port};\n\
         \n\
                 proxy_http_version 1.1;\n\
                 proxy_set_header Upgrade $http_upgrade;\n\
         \n\
                 proxy_set_header Connection \"upgrade\";\n\
                 proxy_set_header Host $host;\n\
             }}\n\
         }}\n"
    )
}

/// Returns a tunnel pointer with quickstart commands for operators with no public IP, CGNAT,
/// or mobile connectivity. Mentions both Cloudflare Tunnel and Tailscale Funnel, and points at
/// the README "Behind a tunnel" section for the full walkthrough. The commands reference
/// `upstream_port` — the same local port Stelyph listens on (`serve --port`) — so the tunnel
/// forwards to the right place regardless of which port the operator chose.
pub fn tunnel_note(upstream_port: u16) -> String {
    format!(
        "# No public IP / CGNAT / mobile: run `stelyph serve --mode proxy --port {port}` behind a tunnel\n\
         # instead of a local reverse proxy. The tunnel must forward to that same --port.\n\
         # Cloudflare Tunnel:  cloudflared tunnel create stelyph && cloudflared tunnel route dns stelyph\n\
         #   <host> && cloudflared tunnel run stelyph   (ingress service: http://localhost:{port})\n\
         # Tailscale Funnel:  tailscale funnel {port}\n\
         # Full walkthrough: README \"Behind a tunnel (no public IP)\".\n",
        port = upstream_port
    )
}

/// Returns the full combined snippet in the required order:
/// requirements block → Caddy example → nginx example → tunnel pointer.
pub fn full_snippet(hostname: &str, upstream_port: u16) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        requirements_block(upstream_port),
        caddy_snippet(hostname, upstream_port),
        nginx_snippet(hostname, upstream_port),
        tunnel_note(upstream_port)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// caddy_snippet contains the hostname and upstream port.
    #[test]
    fn caddy_snippet_contains_host_and_port() {
        let s = caddy_snippet("pds.example.com", 3000);
        assert!(s.contains("pds.example.com"), "must contain hostname");
        assert!(s.contains("3000"), "must contain upstream port");
    }

    /// nginx_snippet contains all three required headers (smuggling-safe coverage test).
    #[test]
    fn nginx_snippet_contains_required_headers() {
        let s = nginx_snippet("pds.example.com", 3000);
        assert!(s.contains("Upgrade"), "must mention Upgrade header");
        assert!(s.contains("Connection"), "must mention Connection header");
        assert!(
            s.contains("proxy_set_header Host"),
            "must mention Host header passthrough"
        );
    }

    /// nginx_snippet contains the hostname and upstream port.
    #[test]
    fn nginx_snippet_contains_host_and_port() {
        let s = nginx_snippet("pds.example.com", 8080);
        assert!(s.contains("pds.example.com"), "must contain hostname");
        assert!(s.contains("8080"), "must contain upstream port");
    }

    /// requirements_block mentions all three invariants.
    #[test]
    fn requirements_block_mentions_all_three_invariants() {
        let s = requirements_block(3000);
        assert!(
            s.contains("localhost:3000"),
            "must mention upstream localhost port"
        );
        assert!(
            s.contains("WebSocket") || s.contains("Upgrade"),
            "must mention WebSocket / Upgrade requirement"
        );
        assert!(s.contains("Host"), "must mention Host header requirement");
    }

    /// tunnel_note mentions both Cloudflare Tunnel and Tailscale Funnel and uses the upstream port.
    #[test]
    fn tunnel_note_mentions_both_tunnels() {
        let note = tunnel_note(8080);
        assert!(
            note.contains("Cloudflare Tunnel"),
            "must mention Cloudflare Tunnel"
        );
        assert!(
            note.contains("Tailscale Funnel"),
            "must mention Tailscale Funnel"
        );
        assert!(
            note.contains("8080"),
            "must reference the configured upstream port"
        );
        assert!(
            note.contains("localhost:8080"),
            "Cloudflare ingress must point at the upstream port"
        );
    }

    /// full_snippet ordering: requirements → Caddy → nginx → tunnel.
    #[test]
    fn full_snippet_ordering_is_correct() {
        let s = full_snippet("pds.example.com", 3000);
        let req_pos = s
            .find("reverse-proxy requirements")
            .expect("requirements block missing");
        let caddy_pos = s.find("Caddy (primary").expect("Caddy snippet missing");
        let nginx_pos = s.find("nginx (secondary)").expect("nginx snippet missing");
        let tunnel_pos = s.find("Cloudflare Tunnel").expect("tunnel note missing");
        assert!(
            req_pos < caddy_pos,
            "requirements must come before Caddy: req={req_pos} caddy={caddy_pos}"
        );
        assert!(
            caddy_pos < nginx_pos,
            "Caddy must come before nginx: caddy={caddy_pos} nginx={nginx_pos}"
        );
        assert!(
            nginx_pos < tunnel_pos,
            "nginx must come before tunnel: nginx={nginx_pos} tunnel={tunnel_pos}"
        );
    }

    /// full_snippet contains the hostname and port in both proxy sections.
    #[test]
    fn full_snippet_contains_host_and_port() {
        let s = full_snippet("my.pds.dev", 9090);
        assert!(
            s.contains("my.pds.dev"),
            "hostname must appear in full snippet"
        );
        assert!(s.contains("9090"), "port must appear in full snippet");
    }
}
