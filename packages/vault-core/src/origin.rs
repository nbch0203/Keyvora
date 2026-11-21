//! Origin normalization and credential matching (security contract: docs/CONTRACTS.md §4).
//!
//! Rules: WHATWG parsing (IDNA → punycode), exact origin match, or same registrable domain per the Public Suffix List
//! (private section included). Never substrings, prefixes or titles. Plain `http` only for loopback hosts.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// How well an entry URL matches the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchLevel {
    /// Different site — never offered.
    None,
    /// Same registrable domain, different host/port — requires explicit confirmation.
    SameSite,
    /// Same scheme, host and port — may be filled after a user action.
    Exact,
}

impl MatchLevel {
    /// Stable string used by the bindings.
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchLevel::Exact => "exact",
            MatchLevel::SameSite => "sameSite",
            MatchLevel::None => "none",
        }
    }
}

/// Normalized web origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebOrigin {
    /// `https` or `http`.
    pub scheme: String,
    /// Lower-case ASCII host (punycode for IDN), without trailing dot; IPv6 without brackets.
    pub host: String,
    /// Effective port.
    pub port: u16,
    /// Whether the host is an IP literal.
    pub is_ip: bool,
    /// Registrable domain (eTLD+1) when the host is a domain that has one.
    pub registrable_domain: Option<String>,
}

impl WebOrigin {
    /// `scheme://host[:port]` serialization.
    pub fn serialize(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default {
            format!("{}://{}", self.scheme, host)
        } else {
            format!("{}://{}:{}", self.scheme, host, self.port)
        }
    }

    /// Host as shown to the user: `host` or `host:port` when the port is not the scheme's default (so a page on
    /// another port of the same host is never displayed as if it were the same site).
    pub fn display_host(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Whether the host contains IDN labels (shown in punycode to the user).
    pub fn is_idn(&self) -> bool {
        self.host.split('.').any(|l| l.starts_with("xn--"))
    }

    fn is_loopback(&self) -> bool {
        if self.host == "localhost" || self.host.ends_with(".localhost") {
            return true;
        }
        if let Ok(v4) = self.host.parse::<Ipv4Addr>() {
            return v4.is_loopback();
        }
        if let Ok(v6) = self.host.parse::<Ipv6Addr>() {
            return v6.is_loopback();
        }
        false
    }
}

fn origin_from_url(url: &Url) -> Option<WebOrigin> {
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let (host, is_ip) = match url.host()? {
        Host::Domain(d) => (d.trim_end_matches('.').to_ascii_lowercase(), false),
        Host::Ipv4(a) => (a.to_string(), true),
        Host::Ipv6(a) => (a.to_string(), true),
    };
    if host.is_empty() {
        return None;
    }
    let port = url.port_or_known_default()?;
    let registrable_domain = if is_ip { None } else { psl::domain_str(&host).map(str::to_owned) };
    Some(WebOrigin { scheme: scheme.to_owned(), host, port, is_ip, registrable_domain })
}

/// Parses the URL of the page/tab/webDomain to fill. Returns `None` for anything not fillable
/// (non-HTTP(S) schemes, plain HTTP on non-loopback hosts, unparsable input).
pub fn parse_page_url(page_url: &str) -> Option<WebOrigin> {
    let url = Url::parse(page_url.trim()).ok()?;
    let o = origin_from_url(&url)?;
    if o.scheme == "http" && !o.is_loopback() {
        return None;
    }
    Some(o)
}

/// Parses a URL stored in an entry. A missing scheme defaults to `https://`.
pub fn parse_entry_url(entry_url: &str) -> Option<WebOrigin> {
    let s = entry_url.trim();
    if s.is_empty() {
        return None;
    }
    let candidate = if s.contains("://") { s.to_owned() } else { format!("https://{s}") };
    let url = Url::parse(&candidate).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    origin_from_url(&url)
}

/// Android package referenced by an `androidapp://<package>` entry URL.
pub fn parse_android_app(entry_url: &str) -> Option<String> {
    let rest = entry_url.trim().strip_prefix("androidapp://")?;
    let pkg = rest.trim_end_matches('/');
    let valid = !pkg.is_empty()
        && pkg.len() <= 255
        && pkg.contains('.')
        && pkg.split('.').all(|seg| {
            !seg.is_empty()
                && seg.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    valid.then(|| pkg.to_owned())
}

/// Whether a string is acceptable as an entry URL.
pub fn is_valid_entry_url(entry_url: &str) -> bool {
    parse_android_app(entry_url).is_some() || parse_entry_url(entry_url).is_some()
}

/// Match level between a stored entry URL and the page URL.
pub fn match_level(entry_url: &str, page_url: &str) -> MatchLevel {
    match (parse_entry_url(entry_url), parse_page_url(page_url)) {
        (Some(e), Some(p)) => match_origins(&e, &p),
        _ => MatchLevel::None,
    }
}

/// Match level between two already-normalized origins.
pub fn match_origins(entry: &WebOrigin, page: &WebOrigin) -> MatchLevel {
    if entry.scheme != page.scheme {
        return MatchLevel::None;
    }
    if entry.host == page.host && entry.port == page.port {
        return MatchLevel::Exact;
    }
    // Same host on another port: a different service (shared hosting, router panel…). Never offered (audit).
    if entry.host == page.host {
        return MatchLevel::None;
    }
    if entry.is_ip || page.is_ip {
        return MatchLevel::None;
    }
    match (&entry.registrable_domain, &page.registrable_domain) {
        (Some(a), Some(b)) if a == b => MatchLevel::SameSite,
        _ => MatchLevel::None,
    }
}
